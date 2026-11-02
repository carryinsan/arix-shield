import http from 'node:http';
import https from 'node:https';

const port = Number(process.env.PORT || 8080);
if (!Number.isInteger(port) || port < 1 || port > 65_535) process.exit(1);
const tlsEnabled = Boolean(process.env.EDGE_TLS_CERT_FILE);
const transport = tlsEnabled ? https : http;
const request = transport.get({
  host: '127.0.0.1',
  port,
  path: '/_arix_edge_health',
  timeout: 2500,
  ...(tlsEnabled ? { rejectUnauthorized: false } : {})
}, (response) => {
  response.resume();
  process.exitCode = response.statusCode === 200 ? 0 : 1;
  response.once('end', () => { if (process.exitCode !== 0) process.exit(1); });
});
request.once('timeout', () => { request.destroy(new Error('Health check timeout.')); });
request.once('error', () => { process.exit(1); });
