require('dotenv').config();
const mysql = require('mysql2/promise');

// Création d'un pool de connexions (plus performant qu'une connexion unique)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test de la connexion
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connexion à la base MySQL réussie !');
    connection.release();
  } catch (error) {
    console.error('❌ Erreur de connexion à MySQL :', error.message);
  }
}

testConnection();

module.exports = pool;