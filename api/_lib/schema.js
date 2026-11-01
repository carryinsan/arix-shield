import { validateJsonSchema } from './waf-engine.js';

function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function resolvePointer(document, pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('#/')) throw new Error('Only local OpenAPI JSON references are supported.');
  return pointer.slice(2).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~')).reduce((value, key) => {
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, key)) throw new Error(`Unresolved OpenAPI reference: ${pointer.slice(0, 120)}`);
    return value[key];
  }, document);
}

function dereference(schema, document, stack = new Set(), depth = 0) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || depth > 24) throw new Error('Invalid or excessively nested OpenAPI schema.');
  if (typeof schema.$ref === 'string') {
    if (stack.has(schema.$ref)) throw new Error('Circular OpenAPI schema references are not supported by the runtime validator.');
    const next = new Set(stack);
    next.add(schema.$ref);
    const resolved = dereference(resolvePointer(document, schema.$ref), document, next, depth + 1);
    const siblings = Object.fromEntries(Object.entries(schema).filter(([key]) => key !== '$ref'));
    return { ...resolved, ...siblings };
  }
  const out = { ...schema };
  if (schema.properties && typeof schema.properties === 'object') {
    out.properties = {};
    for (const [key, value] of Object.entries(schema.properties)) out.properties[key] = dereference(value, document, stack, depth + 1);
  }
  if (schema.items) out.items = dereference(schema.items, document, stack, depth + 1);
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object') out.additionalProperties = dereference(schema.additionalProperties, document, stack, depth + 1);
  if (schema.allOf || schema.oneOf || schema.anyOf || schema.not) throw new Error('OpenAPI composition keywords (allOf/oneOf/anyOf/not) are not supported by the built-in validator.');
  return out;
}

/** Compile a parsed OpenAPI 3.x document's JSON request-body schema for one route. */
export function compileOpenApiRequestSchema(document, method, pathname) {
  if (!document || typeof document !== 'object' || !document.paths || typeof document.paths !== 'object') throw new TypeError('A parsed OpenAPI document with paths is required.');
  const upperMethod = String(method || 'GET').toLowerCase();
  const path = String(pathname || '/').split('?')[0];
  let match = null;
  for (const [template, pathItem] of Object.entries(document.paths)) {
    const routeRegex = new RegExp(`^${template.split('/').map((part) => part.startsWith('{') && part.endsWith('}') ? '[^/]+' : escapeRegex(part)).join('/')}/?$`);
    if (routeRegex.test(path)) { match = { template, pathItem }; break; }
  }
  const operation = match?.pathItem?.[upperMethod];
  if (!operation) throw new Error(`OpenAPI operation not found for ${upperMethod.toUpperCase()} ${path}.`);
  const content = operation.requestBody?.content || {};
  const schema = content['application/json']?.schema || content['application/*+json']?.schema;
  if (!schema) throw new Error('The OpenAPI operation does not declare an application/json request body schema.');
  return { schema: dereference(schema, document), operationId: operation.operationId || null, pathTemplate: match.template };
}


/** Check whether a concrete method/path is described by a parsed OpenAPI paths object. */
export function isOpenApiOperation(document, method, pathname) {
  if (!document || typeof document !== 'object' || !document.paths || typeof document.paths !== 'object') return false;
  const verb = String(method || 'GET').toLowerCase();
  const path = String(pathname || '/').split('?')[0];
  for (const [template, pathItem] of Object.entries(document.paths)) {
    const routeRegex = new RegExp(`^${template.split('/').map((part) => part.startsWith('{') && part.endsWith('}') ? '[^/]+' : escapeRegex(part)).join('/')}/?$`);
    if (routeRegex.test(path) && pathItem && typeof pathItem === 'object' && pathItem[verb]) return true;
  }
  return false;
}

/** Accept built-in JSON Schema, a precompiled OpenAPI schema, or a Zod-like safeParse schema. */
export function validatePayloadSchema(value, schema) {
  if (schema && typeof schema.safeParse === 'function') {
    const result = schema.safeParse(value);
    if (result.success) return { valid: true, errors: [] };
    const issues = Array.isArray(result.error?.issues) ? result.error.issues : [];
    return { valid: false, errors: issues.slice(0, 100).map((issue) => `${Array.isArray(issue.path) ? issue.path.join('.') : 'body'}: ${String(issue.message || 'invalid').slice(0, 120)}`) };
  }
  return validateJsonSchema(value, schema?.schema || schema);
}
