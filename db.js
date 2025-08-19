const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

// Crear instancia de base de datos
const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) {
    console.error("Error al conectar con SQLite:", err);
  } else {
    console.log("Conectado a SQLite");
    initializeDatabase();
  }
});

// Guardar métodos originales
const originalRun = db.run.bind(db);
const originalGet = db.get.bind(db);
const originalAll = db.all.bind(db);

// Crear versiones promisificadas
db.run = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    originalRun(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

db.get = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    originalGet(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

db.all = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    originalAll(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Función para inicializar la base de datos
async function initializeDatabase() {
  try {
    // Tabla SuperUser
    await db.run(`
      CREATE TABLE IF NOT EXISTS SuperUser (
        superUser TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        cant_usuarios_permitidos INTEGER NOT NULL
      )
    `);

    // Tabla User
    await db.run(`
      CREATE TABLE IF NOT EXISTS User (
        user TEXT NOT NULL,
        superUser TEXT NOT NULL,
        nombreReal TEXT NOT NULL,
        password TEXT NOT NULL,
        PRIMARY KEY (user, superUser),
        FOREIGN KEY (superUser) REFERENCES SuperUser(superUser)
      )
    `);

    // Tabla Hash
    await db.run(`
      CREATE TABLE IF NOT EXISTS Hash (
        superUser TEXT NOT NULL,
        hash TEXT NOT NULL,
        PRIMARY KEY (superUser, hash),
        FOREIGN KEY (superUser) REFERENCES SuperUser(superUser)
      )
    `);

    // Tabla Sesion
    await db.run(`
      CREATE TABLE IF NOT EXISTS Sesion (
        id_sesion INTEGER PRIMARY KEY AUTOINCREMENT,
        paciente TEXT NOT NULL,  
        user TEXT NOT NULL,      
        superUser TEXT NOT NULL, 
        inicio DATETIME NOT NULL,
        fin DATETIME,
        estadoInicial TEXT NOT NULL,
        estadoFinal TEXT,
        FOREIGN KEY (user, superUser) REFERENCES User(user, superUser),
        FOREIGN KEY (superUser) REFERENCES SuperUser(superUser)
      )
    `);

    // Tabla Ejercicio
    await db.run(`
      CREATE TABLE IF NOT EXISTS Ejercicio (
        id_ejercicio INTEGER PRIMARY KEY AUTOINCREMENT,
        escena TEXT NOT NULL,
        inicio DATETIME NOT NULL,
        fin DATETIME,
        id_sesion INTEGER NOT NULL,
        FOREIGN KEY (id_sesion) REFERENCES Sesion(id_sesion)
      )
    `);

    // Tabla Metrica
    await db.run(`
      CREATE TABLE IF NOT EXISTS Metrica (
        id_metrica INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        data TEXT NOT NULL,
        id_ejercicio INTEGER NOT NULL,
        FOREIGN KEY (id_ejercicio) REFERENCES Ejercicio(id_ejercicio)
      )
    `);

    // Tabla License
    await db.run(`
      CREATE TABLE IF NOT EXISTS License (
        id_license INTEGER PRIMARY KEY AUTOINCREMENT,
        superUser TEXT NOT NULL,
        fecha_alta DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        fecha_baja DATETIME,
        estado TEXT CHECK(estado IN ('activa', 'expirada', 'cancelada')) DEFAULT 'activa',
        tipo_licencia TEXT CHECK(tipo_licencia IN ('basica', 'premium')) DEFAULT 'basica',
        FOREIGN KEY (superUser) REFERENCES SuperUser(superUser)
      )
    `);

    console.log("Todas las tablas creadas/verificadas");
  } catch (err) {
    console.error("Error al inicializar la base de datos:", err);
  }
}

module.exports = db;
