const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');
const pool = require('./db');

dotenv.config({ path: path.join(__dirname, '../../.env') });

console.log('JWT_SECRET cargado:', process.env.JWT_SECRET ? 'SI' : 'NO');

const app = express();
const PORT = process.env.GROUPS_SERVICE_PORT || 3003;

app.use(cors({
  origin: ['http://localhost:4200', 'http://localhost:3000', 'http://127.0.0.1:4200', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'x-user-id']
}));

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

const sendResponse = (res, statusCode, intOpCode, data = null) => {
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

  res.status(statusCode).json({
    statusCode,
    intOpCode,
    data: formattedData
  });
};

// Health check
app.get('/health', (req, res) => {
  sendResponse(res, 200, 'SxGR200', { status: 'OK', service: 'groups-service' });
});

// ============== GRUPOS ==============

// Obtener todos los grupos
app.get('/groups', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT g.*, u.nombre_completo as creador_nombre
       FROM grupos g
       LEFT JOIN usuarios u ON g.creador_id = u.id
       ORDER BY g.nombre`
    );
    sendResponse(res, 200, 'SxGR200', result.rows);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Obtener grupos de un usuario
app.get('/groups/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    console.log('Obteniendo grupos para usuario:', userId);

    const result = await pool.query(
      `SELECT DISTINCT g.*,
              u.nombre_completo as creador_nombre,
              (SELECT COUNT(DISTINCT gm2.usuario_id) FROM grupo_miembros gm2 WHERE gm2.grupo_id = g.id) as total_miembros,
              (SELECT COUNT(DISTINCT t.id) FROM tickets t WHERE t.grupo_id = g.id) as total_tickets
       FROM grupos g
       LEFT JOIN usuarios u ON g.creador_id = u.id
       INNER JOIN grupo_miembros gm ON g.id = gm.grupo_id AND gm.usuario_id = $1
       ORDER BY g.nombre`,
      [userId]
    );

    console.log('Grupos encontrados:', result.rows.length);
    sendResponse(res, 200, 'SxGR200', result.rows);
  } catch (error) {
    console.error('Error en /groups/user/:userId:', error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Obtener grupo por ID
app.get('/groups/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT g.*, u.nombre_completo as creador_nombre
       FROM grupos g
       LEFT JOIN usuarios u ON g.creador_id = u.id
       WHERE g.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return sendResponse(res, 404, 'SxGR404', { error: 'Grupo no encontrado' });
    }

    sendResponse(res, 200, 'SxGR200', result.rows[0]);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Crear grupo — SIN agregar al creador como miembro automáticamente
app.post('/groups', async (req, res) => {
  try {
    const { nombre, descripcion, creador_id } = req.body;

    if (!nombre || !creador_id) {
      return sendResponse(res, 400, 'SxGR400', { error: 'Nombre y creador requeridos' });
    }

    const result = await pool.query(
      `INSERT INTO grupos (nombre, descripcion, creador_id)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [nombre, descripcion || null, creador_id]
    );

    sendResponse(res, 201, 'SxGR201', result.rows[0]);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Actualizar grupo
app.put('/groups/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, descripcion } = req.body;

    const result = await pool.query(
      `UPDATE grupos
       SET nombre = COALESCE($1, nombre),
           descripcion = COALESCE($2, descripcion)
       WHERE id = $3
       RETURNING *`,
      [nombre, descripcion, id]
    );

    if (result.rows.length === 0) {
      return sendResponse(res, 404, 'SxGR404', { error: 'Grupo no encontrado' });
    }

    sendResponse(res, 200, 'SxGR200', result.rows[0]);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Eliminar grupo
app.delete('/groups/:id', async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM grupo_permisos WHERE grupo_id = $1', [id]);
    await pool.query('DELETE FROM grupo_miembros WHERE grupo_id = $1', [id]);
    await pool.query('DELETE FROM grupos WHERE id = $1', [id]);

    sendResponse(res, 200, 'SxGR200', { message: 'Grupo eliminado correctamente' });
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// ============== MIEMBROS ==============

// Obtener miembros de un grupo
app.get('/groups/:id/members', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT u.id, u.nombre_completo, u.email, u.username, gm.fecha_union
       FROM grupo_miembros gm
       JOIN usuarios u ON gm.usuario_id = u.id
       WHERE gm.grupo_id = $1
       ORDER BY u.nombre_completo`,
      [id]
    );

    sendResponse(res, 200, 'SxGR200', result.rows);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Agregar miembro al grupo
app.post('/groups/:id/members', async (req, res) => {
  try {
    const { id } = req.params;
    const { usuario_id } = req.body;

    if (!usuario_id) {
      return sendResponse(res, 400, 'SxGR400', { error: 'usuario_id es requerido' });
    }

    await pool.query(
      'INSERT INTO grupo_miembros (grupo_id, usuario_id) VALUES ($1, $2) ON CONFLICT (grupo_id, usuario_id) DO NOTHING',
      [id, usuario_id]
    );

    sendResponse(res, 201, 'SxGR201', { message: 'Miembro agregado correctamente' });
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Remover miembro del grupo
app.delete('/groups/:id/members/:usuario_id', async (req, res) => {
  try {
    const { id, usuario_id } = req.params;
    const eliminador_id = req.headers['x-user-id'] || req.body?.eliminador_id;

    // 1. Verificar si el usuario existe en el grupo
    const checkMember = await pool.query(
      'SELECT * FROM grupo_miembros WHERE grupo_id = $1 AND usuario_id = $2',
      [id, usuario_id]
    );

    if (checkMember.rowCount === 0) {
      return sendResponse(res, 404, 'SxGR404', { error: 'Miembro no encontrado en el grupo' });
    }

    // 2. Obtener los tickets asignados al usuario en este grupo
    const ticketsResult = await pool.query(
      'SELECT id, autor_id, titulo FROM tickets WHERE grupo_id = $1 AND asignado_id = $2',
      [id, usuario_id]
    );

    const tickets = ticketsResult.rows;
    const creadoresAgregados = new Set();

    // 3. Reasignar cada ticket a su creador original
    for (const ticket of tickets) {
      const autorId = ticket.autor_id;
      const actorId = eliminador_id || usuario_id;

      // Si el autor es el mismo usuario que se remueve, dejar el ticket sin asignar
      if (autorId === usuario_id) {
        await pool.query(
          'UPDATE tickets SET asignado_id = NULL WHERE id = $1',
          [ticket.id]
        );

        await pool.query(
          'INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)',
          [ticket.id, actorId, 'Usuario removido del grupo. Ticket sin asignado (el autor era el mismo usuario removido).']
        );
        continue;
      }

      // Verificar si el autor ya es miembro del grupo
      const checkAutorEnGrupo = await pool.query(
        'SELECT * FROM grupo_miembros WHERE grupo_id = $1 AND usuario_id = $2',
        [id, autorId]
      );

      // Si el autor NO es miembro del grupo, agregarlo automáticamente
      if (checkAutorEnGrupo.rowCount === 0) {
        await pool.query(
          'INSERT INTO grupo_miembros (grupo_id, usuario_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [id, autorId]
        );
        creadoresAgregados.add(autorId);
        console.log(`Creador ${autorId} agregado al grupo ${id} porque tiene tickets reasignados`);
      }

      // Reasignar el ticket al autor original
      await pool.query(
        'UPDATE tickets SET asignado_id = $1 WHERE id = $2',
        [autorId, ticket.id]
      );

      // Registrar en historial
      const mensaje = creadoresAgregados.has(autorId)
        ? 'Usuario removido del grupo. Ticket reasignado a su creador (quien fue agregado automáticamente al grupo).'
        : 'Usuario removido del grupo. Ticket reasignado a su creador.';

      await pool.query(
        'INSERT INTO historial_tickets (ticket_id, usuario_id, accion) VALUES ($1, $2, $3)',
        [ticket.id, actorId, mensaje]
      );
    }

    console.log(`Se reasignaron ${tickets.length} tickets del usuario ${usuario_id} en el grupo ${id}`);
    if (creadoresAgregados.size > 0) {
      console.log(`Creadores agregados al grupo: ${Array.from(creadoresAgregados).join(', ')}`);
    }

    // 4. Eliminar permisos del usuario en este grupo
    await pool.query(
      'DELETE FROM grupo_permisos WHERE grupo_id = $1 AND usuario_id = $2',
      [id, usuario_id]
    );

    // 5. Eliminar al miembro del grupo
    await pool.query(
      'DELETE FROM grupo_miembros WHERE grupo_id = $1 AND usuario_id = $2',
      [id, usuario_id]
    );

    sendResponse(res, 200, 'SxGR200', {
      message: 'Miembro removido correctamente',
      ticketsReasignados: tickets.length,
      creadoresAgregados: Array.from(creadoresAgregados)
    });
  } catch (error) {
    console.error('Error removiendo miembro:', error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// ============== PERMISOS POR GRUPO ==============

// Obtener permisos de un usuario en un grupo
app.get('/groups/:groupId/users/:userId/permisos', async (req, res) => {
  try {
    const { groupId, userId } = req.params;

    const result = await pool.query(
      `SELECT p.id, p.nombre, p.descripcion, p.modulo
       FROM grupo_permisos gp
       JOIN permisos p ON gp.permiso_id = p.id
       WHERE gp.grupo_id = $1 AND gp.usuario_id = $2`,
      [groupId, userId]
    );

    sendResponse(res, 200, 'SxGR200', result.rows);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Asignar permiso a usuario en grupo
app.post('/groups/:groupId/users/:userId/permisos', async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    const { permiso_id } = req.body;

    const permisoValido = await pool.query(
      `SELECT nombre, modulo FROM permisos
       WHERE id = $1 AND (modulo = 'grupos' OR modulo = 'tickets')`,
      [permiso_id]
    );

    if (permisoValido.rows.length === 0) {
      return sendResponse(res, 400, 'SxGR400', {
        error: 'Solo se pueden asignar permisos de grupos o tickets a nivel de grupo'
      });
    }

    await pool.query(
      'INSERT INTO grupo_permisos (grupo_id, usuario_id, permiso_id) VALUES ($1, $2, $3) ON CONFLICT (grupo_id, usuario_id, permiso_id) DO NOTHING',
      [groupId, userId, permiso_id]
    );

    sendResponse(res, 201, 'SxGR201', { message: 'Permiso asignado correctamente' });
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Remover permiso de usuario en grupo
app.delete('/groups/:groupId/users/:userId/permisos/:permiso_id', async (req, res) => {
  try {
    const { groupId, userId, permiso_id } = req.params;

    await pool.query(
      'DELETE FROM grupo_permisos WHERE grupo_id = $1 AND usuario_id = $2 AND permiso_id = $3',
      [groupId, userId, permiso_id]
    );

    sendResponse(res, 200, 'SxGR200', { message: 'Permiso removido correctamente' });
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

// Obtener todos los permisos disponibles (solo grupos y tickets)
app.get('/permisos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM permisos
       WHERE modulo = 'grupos' OR modulo = 'tickets'
       ORDER BY nombre`
    );
    sendResponse(res, 200, 'SxGR200', result.rows);
  } catch (error) {
    console.error(error);
    sendResponse(res, 500, 'SxGR500', { error: 'Error interno del servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Groups service running on port ${PORT}`);
});