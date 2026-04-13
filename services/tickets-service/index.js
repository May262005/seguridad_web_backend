const fastify = require('fastify')({ logger: true });
const cors    = require('@fastify/cors');
const helmet  = require('@fastify/helmet');
const dotenv  = require('dotenv');
const path    = require('path');
const pool    = require('./db');

dotenv.config({ path: path.join(__dirname, '../../.env') });

const PORT = process.env.TICKETS_SERVICE_PORT || 3002;

fastify.register(cors);
fastify.register(helmet);

const sendResponse = (reply, statusCode, intOpCode, data = null) => {
  let formattedData = null;
  if (data !== null && data !== undefined) {
    if (Array.isArray(data))        formattedData = data;
    else if (typeof data === 'object') formattedData = [data];
    else                               formattedData = [data];
  }
  reply.status(statusCode).send({ statusCode, intOpCode, data: formattedData });
};

const getUserPermisos = (request) => {
  try {
    const raw = request.headers['x-user-permisos'];
    return raw ? JSON.parse(raw) : { permisos: [], permisosPorGrupo: {} };
  } catch {
    return { permisos: [], permisosPorGrupo: {} };
  }
};

// ✅ Sin admin:full — admin = user:manage-permissions global
const tienePermiso = (userPermisos, permiso, grupoId = null) => {
  const globales = userPermisos.permisos || [];

  // Admin del sistema o permiso global directo
  if (globales.includes('user:manage-permissions') || globales.includes(permiso)) return true;

  const porGrupo = userPermisos.permisosPorGrupo || {};

  if (grupoId) return (porGrupo[grupoId] || []).includes(permiso);

  return Object.values(porGrupo).some(p => p.includes(permiso));
};

// ✅ Sin admin:full — admin = user:manage-permissions global
const esAdminSistema = (userPermisos) => {
  return (userPermisos.permisos || []).includes('user:manage-permissions');
};

const verificarPermisoEnTicket = async (request, reply, permiso) => {
  const ticketId    = request.params.id;
  const userPermisos = getUserPermisos(request);

  try {
    const result = await pool.query(
      'SELECT grupo_id, autor_id, asignado_id FROM tickets WHERE id = $1', [ticketId]
    );

    if (result.rows.length === 0) {
      sendResponse(reply, 404, 'SxTK404', { error: 'Ticket no encontrado' });
      return false;
    }

    const { grupo_id } = result.rows[0];
    if (tienePermiso(userPermisos, permiso, grupo_id)) return true;

    sendResponse(reply, 403, 'SxTK403', {
      error: 'No tienes permiso para realizar esta acción en este ticket',
      requiredPermission: permiso
    });
    return false;
  } catch (err) {
    fastify.log.error(err);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
    return false;
  }
};

// Health
fastify.get('/health', async (request, reply) => {
  sendResponse(reply, 200, 'SxTK200', { status: 'OK', service: 'tickets-service' });
});

// GET /tickets
fastify.get('/tickets', async (request, reply) => {
  try {
    const { grupo_id, estado_id, prioridad_id, asignado_id } = request.query;
    const userPermisos = getUserPermisos(request);
    const globales     = userPermisos.permisos || [];
    const porGrupo     = userPermisos.permisosPorGrupo || {};

    let query = `
      SELECT
        t.id, t.titulo, t.descripcion, t.creado_en, t.fecha_final,
        t.grupo_id, t.autor_id, t.asignado_id, t.estado_id, t.prioridad_id,
        u.nombre_completo  as autor_nombre,
        ua.nombre_completo as asignado_nombre,
        e.nombre           as estado_nombre,
        e.color            as estado_color,
        p.nombre           as prioridad_nombre,
        p.color            as prioridad_color,
        g.nombre           as grupo_nombre
      FROM tickets t
      LEFT JOIN usuarios   u  ON t.autor_id    = u.id
      LEFT JOIN usuarios   ua ON t.asignado_id = ua.id
      LEFT JOIN estados    e  ON t.estado_id   = e.id
      LEFT JOIN prioridades p ON t.prioridad_id = p.id
      LEFT JOIN grupos     g  ON t.grupo_id    = g.id
      WHERE 1=1
    `;

    const params = [];
    let paramIndex = 1;

    // Admin = user:manage-permissions global o ticket:view global
    const esAdmin = globales.includes('user:manage-permissions') || globales.includes('ticket:view');

    if (!esAdmin) {
      const gruposConAcceso = Object.keys(porGrupo).filter(gId =>
        (porGrupo[gId] || []).includes('ticket:view')
      );
      if (gruposConAcceso.length === 0) {
        return sendResponse(reply, 200, 'SxTK200', []);
      }
      query += ` AND t.grupo_id = ANY($${paramIndex++}::uuid[])`;
      params.push(gruposConAcceso);
    }

    if (grupo_id)    { query += ` AND t.grupo_id    = $${paramIndex++}`; params.push(grupo_id); }
    if (estado_id)   { query += ` AND t.estado_id   = $${paramIndex++}`; params.push(estado_id); }
    if (prioridad_id){ query += ` AND t.prioridad_id= $${paramIndex++}`; params.push(prioridad_id); }
    if (asignado_id) { query += ` AND t.asignado_id = $${paramIndex++}`; params.push(asignado_id); }

    query += ` ORDER BY t.creado_en DESC`;

    const result = await pool.query(query, params);
    sendResponse(reply, 200, 'SxTK200', result.rows);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /tickets/:id
fastify.get('/tickets/:id', async (request, reply) => {
  try {
    const { id } = request.params;
    const userPermisos = getUserPermisos(request);

    const result = await pool.query(
      `SELECT
        t.*,
        u.nombre_completo  as autor_nombre,
        ua.nombre_completo as asignado_nombre,
        e.nombre           as estado_nombre,
        e.color            as estado_color,
        p.nombre           as prioridad_nombre,
        p.color            as prioridad_color,
        g.nombre           as grupo_nombre
      FROM tickets t
      LEFT JOIN usuarios   u  ON t.autor_id    = u.id
      LEFT JOIN usuarios   ua ON t.asignado_id = ua.id
      LEFT JOIN estados    e  ON t.estado_id   = e.id
      LEFT JOIN prioridades p ON t.prioridad_id = p.id
      LEFT JOIN grupos     g  ON t.grupo_id    = g.id
      WHERE t.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return sendResponse(reply, 404, 'SxTK404', { error: 'Ticket no encontrado' });
    }

    const ticket = result.rows[0];
    if (!tienePermiso(userPermisos, 'ticket:view', ticket.grupo_id)) {
      return sendResponse(reply, 403, 'SxTK403', { error: 'No tienes acceso a este ticket' });
    }

    sendResponse(reply, 200, 'SxTK200', ticket);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// POST /tickets
fastify.post('/tickets', async (request, reply) => {
  try {
    const { grupo_id, titulo, descripcion, autor_id, asignado_id, prioridad_id } = request.body;
    const userPermisos = getUserPermisos(request);

    if (!grupo_id || !titulo || !autor_id) {
      return sendResponse(reply, 400, 'SxTK400', { error: 'Faltan campos requeridos' });
    }

    // ✅ Admin puede crear en cualquier grupo aunque no sea miembro
    if (!tienePermiso(userPermisos, 'ticket:create', grupo_id)) {
      return sendResponse(reply, 403, 'SxTK403', {
        error: 'No tienes permiso para crear tickets en este grupo'
      });
    }

    const estadoResult = await pool.query("SELECT id FROM estados WHERE nombre = 'To-Do' LIMIT 1");
    const estado_id    = estadoResult.rows[0]?.id;

    const result = await pool.query(
      `INSERT INTO tickets (grupo_id, titulo, descripcion, autor_id, asignado_id, estado_id, prioridad_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [grupo_id, titulo, descripcion, autor_id, asignado_id || autor_id, estado_id, prioridad_id || null]
    );

    await pool.query(
      `INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)`,
      [result.rows[0].id, autor_id, 'Ticket creado']
    );

    sendResponse(reply, 201, 'SxTK201', result.rows[0]);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// PUT /tickets/:id
fastify.put('/tickets/:id', async (request, reply) => {
  try {
    const { id } = request.params;
    const { titulo, descripcion, asignado_id, prioridad_id, usuario_id } = request.body;

    if (!await verificarPermisoEnTicket(request, reply, 'ticket:edit')) return;

    const oldTicket = await pool.query(
      'SELECT titulo, descripcion, asignado_id, prioridad_id FROM tickets WHERE id = $1', [id]
    );

    const result = await pool.query(
      `UPDATE tickets
       SET titulo       = COALESCE($1, titulo),
           descripcion  = COALESCE($2, descripcion),
           asignado_id  = COALESCE($3, asignado_id),
           prioridad_id = COALESCE($4, prioridad_id)
       WHERE id = $5 RETURNING *`,
      [titulo, descripcion, asignado_id, prioridad_id, id]
    );

    const cambios = [];
    if (titulo       && titulo       !== oldTicket.rows[0].titulo)       cambios.push(`Titulo actualizado`);
    if (descripcion  && descripcion  !== oldTicket.rows[0].descripcion)  cambios.push('Descripcion actualizada');
    if (asignado_id  && asignado_id  !== oldTicket.rows[0].asignado_id) cambios.push('Asignado cambiado');
    if (prioridad_id && prioridad_id !== oldTicket.rows[0].prioridad_id) cambios.push('Prioridad cambiada');

    if (cambios.length > 0 && usuario_id) {
      await pool.query(
        `INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)`,
        [id, usuario_id, cambios.join(', ')]
      );
    }

    sendResponse(reply, 200, 'SxTK200', result.rows[0]);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// DELETE /tickets/:id
fastify.delete('/tickets/:id', async (request, reply) => {
  try {
    const { id } = request.params;
    const userPermisos = getUserPermisos(request);
    const userId = request.user?.userId;

    const ticketResult = await pool.query(
      'SELECT grupo_id, autor_id FROM tickets WHERE id = $1',
      [id]
    );

    if (ticketResult.rows.length === 0) {
      return sendResponse(reply, 404, 'SxTK404', { error: 'Ticket no encontrado' });
    }

    const ticket = ticketResult.rows[0];
    const esAutor = ticket.autor_id === userId;
    const tienePermiso = tienePermiso(userPermisos, 'ticket:delete', ticket.grupo_id);

    if (!esAutor && !tienePermiso) {
      return sendResponse(reply, 403, 'SxTK403', { 
        error: 'No tienes permiso para eliminar este ticket' 
      });
    }

    await pool.query(
      `INSERT INTO historial_tickets (ticket_id, usuario_id, accion)
       VALUES ($1, $2, $3)`,
      [id, userId || ticket.autor_id, 'Ticket eliminado']
    );

    await pool.query('DELETE FROM comentarios WHERE ticket_id = $1', [id]);
    await pool.query('DELETE FROM historial_tickets WHERE ticket_id = $1', [id]);
    await pool.query('DELETE FROM tickets WHERE id = $1', [id]);

    sendResponse(reply, 200, 'SxTK200', { message: 'Ticket eliminado correctamente' });
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// PATCH /tickets/:id/status
fastify.patch('/tickets/:id/status', async (request, reply) => {
  try {
    const { id } = request.params;
    const { estado_id, usuario_id } = request.body;
    const userPermisos = getUserPermisos(request);

    if (!estado_id) return sendResponse(reply, 400, 'SxTK400', { error: 'Estado requerido' });

    const oldTicket = await pool.query(
      `SELECT t.estado_id, t.grupo_id, t.asignado_id, e.nombre as estado_nombre
       FROM tickets t LEFT JOIN estados e ON t.estado_id = e.id WHERE t.id = $1`, [id]
    );

    if (oldTicket.rows.length === 0) {
      return sendResponse(reply, 404, 'SxTK404', { error: 'Ticket no encontrado' });
    }

    const { grupo_id, asignado_id } = oldTicket.rows[0];
    const esAsignado = asignado_id === usuario_id;

    if (!esAsignado && !tienePermiso(userPermisos, 'ticket:move', grupo_id)) {
      return sendResponse(reply, 403, 'SxTK403', { error: 'No tienes permiso para mover este ticket' });
    }

    const newEstado = await pool.query('SELECT nombre FROM estados WHERE id = $1', [estado_id]);
    const result    = await pool.query(
      `UPDATE tickets SET estado_id = $1 WHERE id = $2 RETURNING *`, [estado_id, id]
    );

    if (newEstado.rows[0]?.nombre === 'Done') {
      await pool.query(`UPDATE tickets SET fecha_final = NOW() WHERE id = $1`, [id]);
    }

    const accion = `Estado cambiado de ${oldTicket.rows[0].estado_nombre || 'null'} a ${newEstado.rows[0]?.nombre}`;
    await pool.query(
      `INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)`,
      [id, usuario_id, accion]
    );

    sendResponse(reply, 200, 'SxTK200', result.rows[0]);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// PATCH /tickets/:id/close
fastify.patch('/tickets/:id/close', async (request, reply) => {
  try {
    const { id } = request.params;
    const { usuario_id } = request.body;

    if (!await verificarPermisoEnTicket(request, reply, 'ticket:move')) return;

    const estadoResult = await pool.query("SELECT id FROM estados WHERE nombre = 'Done' LIMIT 1");
    const estado_id    = estadoResult.rows[0]?.id;

    const result = await pool.query(
      `UPDATE tickets SET estado_id = $1, fecha_final = NOW() WHERE id = $2 RETURNING *`,
      [estado_id, id]
    );

    if (result.rows.length === 0) {
      return sendResponse(reply, 404, 'SxTK404', { error: 'Ticket no encontrado' });
    }

    await pool.query(
      `INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)`,
      [id, usuario_id, 'Ticket cerrado']
    );

    sendResponse(reply, 200, 'SxTK200', result.rows[0]);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// POST /tickets/:id/comentarios
fastify.post('/tickets/:id/comentarios', async (request, reply) => {
  try {
    const { id } = request.params;
    const { autor_id, contenido } = request.body;

    if (!autor_id || !contenido) {
      return sendResponse(reply, 400, 'SxTK400', { error: 'Autor y contenido requeridos' });
    }

    if (!await verificarPermisoEnTicket(request, reply, 'ticket:view')) return;

    const result = await pool.query(
      `INSERT INTO comentarios (ticket_id, autor_id, contenido) VALUES ($1, $2, $3) RETURNING *`,
      [id, autor_id, contenido]
    );

    await pool.query(
      `INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)`,
      [id, autor_id, 'Comentario agregado']
    );

    sendResponse(reply, 201, 'SxTK201', result.rows[0]);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /tickets/:id/comentarios
fastify.get('/tickets/:id/comentarios', async (request, reply) => {
  try {
    const { id } = request.params;
    if (!await verificarPermisoEnTicket(request, reply, 'ticket:view')) return;

    const result = await pool.query(
      `SELECT c.*, u.nombre_completo as autor_nombre
       FROM comentarios c LEFT JOIN usuarios u ON c.autor_id = u.id
       WHERE c.ticket_id = $1 ORDER BY c.creado_en ASC`, [id]
    );

    sendResponse(reply, 200, 'SxTK200', result.rows);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /tickets/:id/historial
fastify.get('/tickets/:id/historial', async (request, reply) => {
  try {
    const { id } = request.params;
    if (!await verificarPermisoEnTicket(request, reply, 'ticket:view')) return;

    const result = await pool.query(
      `SELECT h.*, u.nombre_completo as usuario_nombre
       FROM historial_tickets h LEFT JOIN usuarios u ON h.usuario_id = u.id
       WHERE h.ticket_id = $1 ORDER BY h.creado_en DESC`, [id]
    );

    sendResponse(reply, 200, 'SxTK200', result.rows);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /estados
fastify.get('/estados', async (request, reply) => {
  try {
    const result = await pool.query('SELECT * FROM estados ORDER BY orden');
    sendResponse(reply, 200, 'SxTK200', result.rows);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /prioridades
fastify.get('/prioridades', async (request, reply) => {
  try {
    const result = await pool.query('SELECT * FROM prioridades ORDER BY orden');
    sendResponse(reply, 200, 'SxTK200', result.rows);
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

// GET /estadisticas
fastify.get('/estadisticas', async (request, reply) => {
  try {
    const { grupo_id }  = request.query;
    const userPermisos  = getUserPermisos(request);
    const globales      = userPermisos.permisos || [];
    const porGrupo      = userPermisos.permisosPorGrupo || {};

    const estadosResult     = await pool.query('SELECT id, nombre, color, orden FROM estados ORDER BY orden');
    const prioridadesResult = await pool.query('SELECT id, nombre, color, orden FROM prioridades ORDER BY orden');

    // Admin = user:manage-permissions global o ticket:view global
    const esAdmin = globales.includes('user:manage-permissions') || globales.includes('ticket:view');

    let ticketsQuery;
    if (grupo_id) {
      if (!tienePermiso(userPermisos, 'ticket:view', grupo_id)) {
        return sendResponse(reply, 403, 'SxTK403', { error: 'No tienes acceso a este grupo' });
      }
      ticketsQuery = await pool.query(
        'SELECT estado_id, prioridad_id FROM tickets WHERE grupo_id = $1', [grupo_id]
      );
    } else if (!esAdmin) {
      const gruposConAcceso = Object.keys(porGrupo).filter(gId =>
        (porGrupo[gId] || []).includes('ticket:view')
      );
      ticketsQuery = gruposConAcceso.length === 0
        ? { rows: [] }
        : await pool.query(
            'SELECT estado_id, prioridad_id FROM tickets WHERE grupo_id = ANY($1::uuid[])',
            [gruposConAcceso]
          );
    } else {
      ticketsQuery = await pool.query('SELECT estado_id, prioridad_id FROM tickets');
    }

    const estadoCounts    = {};
    const prioridadCounts = {};
    let total = 0;

    ticketsQuery.rows.forEach(ticket => {
      total++;
      if (ticket.estado_id)    estadoCounts[ticket.estado_id]       = (estadoCounts[ticket.estado_id] || 0) + 1;
      if (ticket.prioridad_id) prioridadCounts[ticket.prioridad_id] = (prioridadCounts[ticket.prioridad_id] || 0) + 1;
    });

    const porEstado    = estadosResult.rows.map(e    => ({ nombre: e.nombre,    color: e.color,    count: estadoCounts[e.id]       || 0 }));
    const porPrioridad = prioridadesResult.rows.map(p => ({ nombre: p.nombre, color: p.color, count: prioridadCounts[p.id] || 0 }));

    sendResponse(reply, 200, 'SxTK200', { total, porEstado, porPrioridad });
  } catch (error) {
    request.log.error(error);
    sendResponse(reply, 500, 'SxTK500', { error: 'Error interno del servidor' });
  }
});

fastify.listen({ port: PORT, host: '0.0.0.0' }, (err) => {
  if (err) { fastify.log.error(err); process.exit(1); }
  console.log(`✅ Tickets service running on port ${PORT}`);
});