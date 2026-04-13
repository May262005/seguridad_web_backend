const { Pool } = require('pg');

const pool = new Pool({
  host: 'db.kwijsaurfybgefwaicum.supabase.co',
  port: 5432,
  database: 'postgres',
  user: 'postgres',
  password: 'Maite03121126',
  ssl: { 
    rejectUnauthorized: false 
  },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('Error conectando a Supabase:', err.message);
  } else {
    console.log('Conexion a Supabase establecida');
    release();
  }
});

pool.on('error', (err) => {
  console.error('Error inesperado en pool de BD:', err.message);
});

module.exports = pool;