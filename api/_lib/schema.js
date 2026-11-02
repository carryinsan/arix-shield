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
  for (const keyword of ['allOf', 'oneOf', 'anyOf']) {
    if (schema[keyword] !== undefined) {
      if (!Array.isArray(schema[keyword]) || schema[keyword].length < 1 || schema[keyword].length > 16) throw new Error(`Invalid ${keyword} composition.`);
      out[keyword] = schema[keyword].map((child) => dereference(child, document, stack, depth + 1));
    }
  }
  if (schema.not) out.not = dereference(schema.not, document, stack, depth + 1);
  if (schema.properties && typeof schema.properties === 'object') {
    out.properties = {};
    for (const [key, value] of Object.entries(schema.properties)) out.properties[key] = dereference(value, document, stack, depth + 1);
  }
  if (schema.items) out.items = dereference(schema.items, document, stack, depth + 1);
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object') out.additionalProperties = dereference(schema.additionalProperties, document, stack, depth + 1);
  return out;
}

function matchOpenApiPath(document, pathname) {
  const path = String(pathname || '/').split('?')[0];
  for (const [template, pathItem] of Object.entries(document.paths || {})) {
    const names = [];
    const pattern = template.split('/').map((part) => {
      if (part.startsWith('{') && part.endsWith('}')) { names.push(part.slice(1, -1)); return '([^/]+)'; }
      return escapeRegex(part);
    }).join('/');
    const match = new RegExp(`^${pattern}/?$`).exec(path);
    if (match) return { template, pathItem, pathParams: Object.fromEntries(names.map((name, index) => [name, decodeURIComponent(match[index + 1])])) };
  }
  return null;
}

function operationFor(document, method, pathname) {
  const match = matchOpenApiPath(document, pathname);
  const verb = String(method || 'GET').toLowerCase();
  const operation = match?.pathItem?.[verb];
  return operation ? { ...match, operation, verb } : null;
}

/** Compile an OpenAPI operation into body and parameter validators. */
export function compileOpenApiRequestSchema(document, method, pathname) {
  if (!document || typeof document !== 'object' || !document.paths || typeof document.paths !== 'object') throw new TypeError('A parsed OpenAPI document with paths is required.');
  const route = operationFor(document, method, pathname);
  if (!route) throw new Error(`OpenAPI operation not found for ${String(method).toUpperCase()} ${String(pathname).slice(0, 160)}.`);
  const content = route.operation.requestBody?.content || {};
  const bodySchema = content['application/json']?.schema || content['application/*+json']?.schema || Object.entries(content).find(([type]) => /(?:application\/[^;]+\+json|application\/json)/i.test(type))?.[1]?.schema;
  const merged = new Map();
  for (const parameter of [...(route.pathItem.parameters || []), ...(route.operation.parameters || [])]) {
    if (!parameter || typeof parameter !== 'object' || typeof parameter.name !== 'string' || !['path', 'query', 'header'].includes(parameter.in)) continue;
    const resolved = parameter.$ref ? dereference(parameter, document) : parameter;
    if (!resolved.schema) continue;
    merged.set(`${resolved.in}:${resolved.name.toLowerCase()}`, {
      name: resolved.name, in: resolved.in, required: resolved.in === 'path' || resolved.required === true,
      style: resolved.style || (resolved.in === 'query' ? 'form' : 'simple'),
      explode: resolved.explode !== undefined ? resolved.explode : resolved.in === 'query',
      schema: dereference(resolved.schema, document)
    });
  }
  return {
    schema: bodySchema ? dereference(bodySchema, document) : null,
    parameters: [...merged.values()],
    operationId: route.operation.operationId || null,
    pathTemplate: route.template,
    requestBodyRequired: route.operation.requestBody?.required === true,
    security: route.operation.security ?? document.security ?? []
  };
}

function convertParameterValue(raw, schema) {
  if (schema?.type === 'integer') return /^-?\d+$/.test(String(raw)) ? Number(raw) : raw;
  if (schema?.type === 'number') return String(raw).trim() !== '' && Number.isFinite(Number(raw)) ? Number(raw) : raw;
  if (schema?.type === 'boolean') return raw === 'true' ? true : raw === 'false' ? false : raw;
  return raw;
}

/** Validates path/query/header parameters as well as the JSON request body. */
export function validateOpenApiRequest(document, { method = 'GET', url = '/', headers = {}, body = null } = {}) {
  const parsed = new URL(String(url), 'https://arixshield.invalid');
  const route = operationFor(document, method, parsed.pathname);
  if (!route) return { valid: false, errors: ['route: operation is not declared in OpenAPI document'] };
  const compiled = compileOpenApiRequestSchema(document, method, parsed.pathname);
  const errors = [];
  const headerGet = (name) => headers instanceof Headers ? headers.get(name) : headers?.[name.toLowerCase()] ?? headers?.[name] ?? null;
  for (const parameter of compiled.parameters) {
    let raw;
    if (parameter.in === 'path') raw = route.pathParams[parameter.name];
    else if (parameter.in === 'query') {
      const values = parsed.searchParams.getAll(parameter.name);
      if (parameter.schema.type === 'array') raw = values.length ? values.flatMap((value) => parameter.explode ? [value] : value.split(',')) : undefined;
      else if (values.length > 1) { errors.push(`query.${parameter.name}: duplicate parameter is not declared as an array`); continue; }
      else raw = values[0];
    } else raw = headerGet(parameter.name);
    if (raw === null || raw === undefined) {
      if (parameter.required) errors.push(`${parameter.in}.${parameter.name}: required`);
      continue;
    }
    const converted = Array.isArray(raw) ? raw.map((value) => convertParameterValue(value, parameter.schema.items || {})) : convertParameterValue(raw, parameter.schema);
    const result = validateJsonSchema(converted, parameter.schema, `${parameter.in}.${parameter.name}`);
    errors.push(...result.errors);
  }
  if (compiled.requestBodyRequired && (body === null || body === undefined)) errors.push('body: required');
  if (compiled.schema && body !== null && body !== undefined) errors.push(...validateJsonSchema(body, compiled.schema, 'body').errors);
  return { valid: errors.length === 0, errors: errors.slice(0, 100), operationId: compiled.operationId, pathTemplate: compiled.pathTemplate };
}

/** Check whether a concrete method/path is described by a parsed OpenAPI paths object. */
export function isOpenApiOperation(document, method, pathname) {
  return Boolean(document && operationFor(document, method, pathname));
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
