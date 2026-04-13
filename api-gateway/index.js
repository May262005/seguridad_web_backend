const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const helmet = require('@fastify/helmet');
const rateLimit = require('@fastify/rate-limit');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const dotenv = require('dotenv');
const path = require('path');

const envPath = path.resolve(__dirname, '..', '.env');
console.log('Buscando .env en:', envPath);
dotenv.config({ path: envPath });

console.log('=== VARIABLES DE ENTORNO ===');
console.log('USER_SERVICE_URL:', process.env.USER_SERVICE_URL);
console.log('TICKETS_SERVICE_URL:', process.env.TICKETS_SERVICE_URL);
console.log('GROUPS_SERVICE_URL:', process.env.GROUPS_SERVICE_URL);
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Configurado' : 'No configurado');
console.log('API_GATEWAY_PORT:', process.env.API_GATEWAY_PORT);
console.log('FRONTEND_URL:', process.env.FRONTEND_URL || 'http://localhost:4200');
console.log('===========================');

const PORT = process.env.API_GATEWAY_PORT || 3000;

fastify.register(cors, {
  origin: (origin, cb) => {
    const allowedOrigins = [
      'http://localhost:4200',
      'http://localhost:3000',
      'http://127.0.0.1:4200',
      'http://127.0.0.1:3000',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) {
      cb(null, true);
    } else {
      console.log('Origen bloqueado por CORS:', origin);
      cb(null, true);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept',
    'Origin',
    'X-Requested-With',
    'x-user-id'          // ← agregado para que el preflight lo permita
  ]
});

fastify.register(helmet, {
  crossOriginResourcePolicy: { policy: "cross-origin" }
});

fastify.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  errorResponseBuilder: (request, context) => ({
    statusCode: 429,
    intOpCode: 'SxGW429',
    data: { error: 'Too many requests, please try again later.' }
  })
});

const sendResponse = (reply, statusCode, intOpCode, data = null) => {
  let formattedData = null;
  if (data !== null && data !== undefined) {
    if (Array.isArray(data)) {
      formattedData = data;
    } else if (typeof data === 'object') {
      formattedData = [data];
    } else {
      formattedData = [data];
    }
  }
  reply.status(statusCode).send({ statusCode, intOpCode, data: formattedData });
};

const verifyToken = async (request, reply) => {
  const publicEndpoints = ['/auth/login', '/auth/register', '/health'];
  if (publicEndpoints.some(endpoint => request.url.includes(endpoint))) return true;

  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    sendResponse(reply, 401, 'SxGW401', { error: 'Token no proporcionado' });
    return false;
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    request.user = decoded;
    return true;
  } catch (error) {
    sendResponse(reply, 401, 'SxGW401', { error: 'Token invalido o expirado' });
    return false;
  }
};

const verifyPermission = async (request, reply, requiredPermission) => {
  if (!requiredPermission) return true;

  const user = request.user;
  if (!user) {
    sendResponse(reply, 401, 'SxGW401', { error: 'Usuario no autenticado' });
    return false;
  }

  const permisos = user.permisos || [];
  const porGrupo = user.permisosPorGrupo || {};

  if (permisos.includes('admin:full') || permisos.includes(requiredPermission)) return true;

  const grupoId =
    request.params?.groupId ||
    request.body?.grupo_id  ||
    request.query?.grupo_id;

  if (grupoId && porGrupo[grupoId]) {
    if (porGrupo[grupoId].includes(requiredPermission)) return true;
  }

  const tieneEnAlgunGrupo = Object.values(porGrupo).some(p =>
    p.includes(requiredPermission)
  );
  if (tieneEnAlgunGrupo) return true;

  sendResponse(reply, 403, 'SxGW403', {
    error: 'No tienes permiso para realizar esta accion',
    requiredPermission
  });
  return false;
};

const proxyRequest = async (request, reply, serviceUrl, requiredPermission = null) => {
  if (!await verifyToken(request, reply)) return;
  if (requiredPermission && !await verifyPermission(request, reply, requiredPermission)) return;

  try {
    const targetUrl = `${serviceUrl}${request.url}`;
    console.log('Proxying to:', targetUrl);

    const xUserPermisos = request.user
      ? JSON.stringify({
          permisos: request.user.permisos || [],
          permisosPorGrupo: request.user.permisosPorGrupo || {}
        })
      : JSON.stringify({ permisos: [], permisosPorGrupo: {} });

    const response = await axios({
      method: request.method,
      url: targetUrl,
      data: request.body,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': request.headers.authorization,
        'X-User-Permisos': xUserPermisos,
        'x-user-id': request.headers['x-user-id'] || ''  // ← reenviar al microservicio
      },
      timeout: 10000,
      validateStatus: (status) => status >= 200 && status < 600
    });

    console.log('Response status:', response.status);
    sendResponse(reply, response.status, response.data?.intOpCode || 'SxGW200', response.data?.data || response.data);
  } catch (error) {
    console.error('Proxy error:', error.message);
    if (error.response) {
      sendResponse(reply, error.response.status, error.response.data?.intOpCode || 'SxGW500',
        error.response.data?.data || { error: error.response.data?.error || 'Error en el servicio' });
    } else {
      sendResponse(reply, 500, 'SxGW500', { error: 'Error de conexion con el servicio: ' + error.message });
    }
  }
};

// ─── Health ──────────────────────────────────────────────────
fastify.get('/health', async (request, reply) => {
  sendResponse(reply, 200, 'SxGW200', {
    status: 'OK',
    service: 'api-gateway',
    timestamp: new Date().toISOString()
  });
});

// ─── Auth ────────────────────────────────────────────────────
fastify.post('/auth/register', async (request, reply) => {
  try {
    const response = await axios({
      method: 'POST',
      url: `${process.env.USER_SERVICE_URL}/auth/register`,
      data: request.body,
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    sendResponse(reply, response.status, response.data.intOpCode || 'SxGW200', response.data.data);
  } catch (error) {
    console.error('Proxy error:', error.message);
    if (error.response) {
      sendResponse(reply, error.response.status, error.response.data?.intOpCode || 'SxGW500',
        error.response.data?.data || { error: error.response.data?.error || 'Error en el servicio' });
    } else {
      sendResponse(reply, 500, 'SxGW500', { error: 'Error de conexion con el servicio: ' + error.message });
    }
  }
});

fastify.post('/auth/login', async (request, reply) => {
  try {
    const response = await axios({
      method: 'POST',
      url: `${process.env.USER_SERVICE_URL}/auth/login`,
      data: request.body,
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    sendResponse(reply, response.status, response.data.intOpCode || 'SxGW200', response.data.data);
  } catch (error) {
    console.error('Proxy error:', error.message);
    if (error.response) {
      sendResponse(reply, error.response.status, error.response.data?.intOpCode || 'SxGW500',
        error.response.data?.data || { error: error.response.data?.error || 'Error en el servicio' });
    } else {
      sendResponse(reply, 500, 'SxGW500', { error: 'Error de conexion con el servicio: ' + error.message });
    }
  }
});

// ─── Users ───────────────────────────────────────────────────
fastify.get('/users',                              async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:view'));
fastify.get('/users/:id',                          async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:view'));
fastify.put('/users/:id',                          async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:edit'));
fastify.patch('/users/:id/password',               async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:edit'));
fastify.get('/users/:id/permisos',                 async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL));
fastify.post('/users/:id/permisos',                async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:manage-permissions'));
fastify.delete('/users/:id/permisos/:permiso_id',  async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:manage-permissions'));

// ─── Tickets ─────────────────────────────────────────────────
fastify.get('/tickets',                            async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.get('/tickets/:id',                        async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.post('/tickets',                           async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:create'));
fastify.put('/tickets/:id',                        async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:edit'));
fastify.patch('/tickets/:id/status',               async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:status'));
fastify.patch('/tickets/:id/close',                async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:move'));
fastify.get('/tickets/:id/comentarios',            async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.post('/tickets/:id/comentarios',           async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:comment'));
fastify.get('/tickets/:id/historial',              async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.delete('/tickets/:id',                     async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:delete'));

// ─── Estados, prioridades, estadísticas ──────────────────────
fastify.get('/estados',                            async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.get('/prioridades',                        async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL, 'ticket:view'));
fastify.get('/estadisticas',                       async (req, rep) => proxyRequest(req, rep, process.env.TICKETS_SERVICE_URL));

// ─── Permisos ─────────────────────────────────────────────────
fastify.get('/permisos/all',                       async (req, rep) => proxyRequest(req, rep, process.env.USER_SERVICE_URL, 'user:manage-permissions'));
fastify.get('/permisos',                           async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:manage-permissions'));

// ─── Groups ──────────────────────────────────────────────────
// IMPORTANTE: ruta específica /groups/user/:userId ANTES de /groups/:id
fastify.get('/groups/user/:userId',                                   async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL));
fastify.get('/groups',                                                async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:view'));
fastify.post('/groups',                                               async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:add'));
fastify.get('/groups/:id',                                            async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:view'));
fastify.put('/groups/:id',                                            async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:edit'));
fastify.delete('/groups/:id',                                         async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:delete'));
fastify.get('/groups/:id/members',                                    async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:view'));
fastify.post('/groups/:id/members',                                   async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:users-add'));
fastify.delete('/groups/:id/members/:usuario_id',                     async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:users-remove'));
fastify.get('/groups/:groupId/users/:userId/permisos',                async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL));
fastify.post('/groups/:groupId/users/:userId/permisos',               async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:manage-permissions'));
fastify.delete('/groups/:groupId/users/:userId/permisos/:permiso_id', async (req, rep) => proxyRequest(req, rep, process.env.GROUPS_SERVICE_URL, 'group:manage-permissions'));

fastify.listen({ port: PORT, host: '0.0.0.0' }, (err) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});