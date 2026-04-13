const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

dotenv.config({ path: path.join(__dirname, '../../.env') });

console.log('JWT_SECRET cargado:', process.env.JWT_SECRET ? 'SI' : 'NO');
console.log('USER_SERVICE_PORT:', process.env.USER_SERVICE_PORT);

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 3001;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb', type: 'application/json' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

app.use((req, res, next) => {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    console.log('Body recibido:', req.body);
    console.log('Content-Type:', req.headers['content-type']);
  }
  next();
});

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
  res.status(statusCode).json({ statusCode, intOpCode, data: formattedData });
};

// Health check
app.get('/health', (req, res) => {
  sendResponse(res, 200, 'SxUS200', { status: 'OK', service: 'user-service' });
});

// Registro
app.post('/auth/register', async (req, res) => {
  try {
    console.log('Request body completo:', JSON.stringify(req.body, null, 2));
    const { nombre_completo, email, username, password, direccion, telefono } = req.body;

    if (!req.body || Object.keys(req.body).length === 0) {
      return sendResponse(res, 400, 'SxUS400', { error: 'El cuerpo de la solicitud esta vacio' });
    }
    if (!nombre_completo) return sendResponse(res, 400, 'SxUS400', { error: 'El campo nombre_completo es requerido' });
    if (!email)           return sendResponse(res, 400, 'SxUS400', { error: 'El campo email es requerido' });
    if (!username)        return sendResponse(res, 400, 'SxUS400', { error: 'El campo username es requerido' });
    if (!password)        return sendResponse(res, 400, 'SxUS400', { error: 'El campo password es requerido' });

    const existingUser = await pool.query(
      'SELECT id FROM usuarios WHERE email = $1 OR username = $2',
      [email, username]
    );
    if (existingUser.rows.length > 0) {
      return sendResponse(res, 400, 'SxUS400', { error: 'El usuario o email ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO usuarios (nombre_completo, direccion, telefono, fecha_inicio, username, email, password_hash)
       VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6)
       RETURNING id, nombre_completo, email, username`,
      [nombre_completo, direccion || null, telefono || null, username, email, hashedPassword]
    );

    const newUser = result.rows[0];
    await pool.query(
      `INSERT INTO usuario_permisos (usuario_id, permiso_id)
       SELECT $1, id FROM permisos WHERE nombre IN ('crear_ticket', 'editar_ticket')`,
      [newUser.id]
    );

    console.log('Usuario registrado exitosamente:', newUser.email);
    sendResponse(res, 201, 'SxUS201', newUser);
  } catch (error) {
    console.error('Error en registro:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor: ' + error.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return sendResponse(res, 400, 'SxUS400', { error: 'Email y contrasena requeridos' });
    }

    const result = await pool.query(
      `SELECT u.*, array_agg(DISTINCT p.nombre) as permisos
       FROM usuarios u
       LEFT JOIN usuario_permisos up ON u.id = up.usuario_id
       LEFT JOIN permisos p ON up.permiso_id = p.id
       WHERE u.email = $1 AND u.active = true
       GROUP BY u.id`,
      [email]
    );

    if (result.rows.length === 0) {
      return sendResponse(res, 401, 'SxUS401', { error: 'Credenciales invalidas' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return sendResponse(res, 401, 'SxUS401', { error: 'Credenciales invalidas' });
    }

    const gruposResult = await pool.query(
      `SELECT gm.grupo_id, array_agg(p.nombre) as permisos
       FROM grupo_miembros gm
       LEFT JOIN grupo_permisos gp ON gm.grupo_id = gp.grupo_id AND gm.usuario_id = gp.usuario_id
       LEFT JOIN permisos p ON gp.permiso_id = p.id
       WHERE gm.usuario_id = $1
       GROUP BY gm.grupo_id`,
      [user.id]
    );

    const permisosPorGrupo = {};
    gruposResult.rows.forEach(row => {
      permisosPorGrupo[row.grupo_id] = row.permisos.filter(p => p !== null);
    });

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        username: user.username,
        permisos: user.permisos.filter(p => p !== null),
        permisosPorGrupo
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    sendResponse(res, 200, 'SxUS200', {
      token,
      user: {
        id: user.id,
        nombre_completo: user.nombre_completo,
        email: user.email,
        username: user.username,
        permisos: user.permisos.filter(p => p !== null),
        permisosPorGrupo
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Obtener usuario por ID
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT id, nombre_completo, email, username, direccion, telefono, active, fecha_inicio
       FROM usuarios WHERE id = $1`,
      [id]
    );
    if (result.rows.length === 0) {
      return sendResponse(res, 404, 'SxUS404', { error: 'Usuario no encontrado' });
    }
    sendResponse(res, 200, 'SxUS200', result.rows[0]);
  } catch (error) {
    console.error('Error al obtener usuario:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Actualizar usuario
app.put('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre_completo, direccion, telefono, email, username } = req.body;
    const result = await pool.query(
      `UPDATE usuarios
       SET nombre_completo = COALESCE($1, nombre_completo),
           direccion       = COALESCE($2, direccion),
           telefono        = COALESCE($3, telefono),
           email           = COALESCE($4, email),
           username        = COALESCE($5, username)
       WHERE id = $6
       RETURNING id, nombre_completo, email, username, direccion, telefono`,
      [nombre_completo, direccion, telefono, email, username, id]
    );
    if (result.rows.length === 0) {
      return sendResponse(res, 404, 'SxUS404', { error: 'Usuario no encontrado' });
    }
    sendResponse(res, 200, 'SxUS200', result.rows[0]);
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Cambiar contraseña
app.patch('/users/:id/password', async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;
    const userResult = await pool.query(
      'SELECT password_hash FROM usuarios WHERE id = $1', [id]
    );
    if (userResult.rows.length === 0) {
      return sendResponse(res, 404, 'SxUS404', { error: 'Usuario no encontrado' });
    }
    const validPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
    if (!validPassword) {
      return sendResponse(res, 401, 'SxUS401', { error: 'Contrasena actual incorrecta' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [hashedPassword, id]);
    sendResponse(res, 200, 'SxUS200', { message: 'Contrasena actualizada correctamente' });
  } catch (error) {
    console.error('Error al cambiar contrasena:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Listar todos los usuarios
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nombre_completo, email, username, direccion, telefono, active, fecha_inicio
       FROM usuarios ORDER BY nombre_completo`
    );
    sendResponse(res, 200, 'SxUS200', result.rows);
  } catch (error) {
    console.error('Error al listar usuarios:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Obtener permisos de un usuario
app.get('/users/:id/permisos', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT p.id, p.nombre, p.descripcion
       FROM usuario_permisos up
       JOIN permisos p ON up.permiso_id = p.id
       WHERE up.usuario_id = $1`,
      [id]
    );
    sendResponse(res, 200, 'SxUS200', result.rows);
  } catch (error) {
    console.error('Error al obtener permisos:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Asignar permiso a usuario
app.post('/users/:id/permisos', async (req, res) => {
  try {
    const { id } = req.params;
    const { permiso_id } = req.body;
    await pool.query(
      'INSERT INTO usuario_permisos (usuario_id, permiso_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [id, permiso_id]
    );
    sendResponse(res, 201, 'SxUS201', { message: 'Permiso asignado correctamente' });
  } catch (error) {
    console.error('Error al asignar permiso:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// Remover permiso de usuario
app.delete('/users/:id/permisos/:permiso_id', async (req, res) => {
  try {
    const { id, permiso_id } = req.params;
    await pool.query(
      'DELETE FROM usuario_permisos WHERE usuario_id = $1 AND permiso_id = $2',
      [id, permiso_id]
    );
    sendResponse(res, 200, 'SxUS200', { message: 'Permiso removido correctamente' });
  } catch (error) {
    console.error('Error al remover permiso:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

// ✅ NUEVO: Obtener TODOS los permisos disponibles (para admin de usuarios)
app.get('/permisos/all', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM permisos ORDER BY modulo, nombre`
    );
    sendResponse(res, 200, 'SxUS200', result.rows);
  } catch (error) {
    console.error('Error al obtener todos los permisos:', error);
    sendResponse(res, 500, 'SxUS500', { error: 'Error interno del servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`User service running on port ${PORT}`);
});