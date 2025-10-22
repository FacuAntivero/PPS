// db.js
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
require("dotenv").config();

const dbPath = process.env.DB_PATH || "./database.sqlite";
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Error al conectar con SQLite:", err);
  } else {
    console.log("Conectado a SQLite");
    initializeDatabase();
  }
});

const originalRun = db.run.bind(db);
const originalGet = db.get.bind(db);
const originalAll = db.all.bind(db);

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

async function initializeDatabase() {
  try {
    // SuperUser: cant_usuarios_permitidos nullable (fallback) y license_id para trazabilidad
    await db.run(`
      CREATE TABLE IF NOT EXISTS SuperUser (
        superUser TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        cant_usuarios_permitidos INTEGER,
        license_id INTEGER
      )
    `);

    // User
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

    // Sesion
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

    // Ejercicio
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

    // Metrica
    await db.run(`
      CREATE TABLE IF NOT EXISTS Metrica (
        id_metrica INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        data TEXT NOT NULL,
        id_ejercicio INTEGER NOT NULL,
        FOREIGN KEY (id_ejercicio) REFERENCES Ejercicio(id_ejercicio)
      )
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS License (
        id_license INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT UNIQUE,
        tipo_licencia TEXT CHECK(tipo_licencia IN ('basica','mediana','pro','custom')) DEFAULT 'basica',
        max_usuarios INTEGER,
        estado TEXT CHECK(estado IN ('pendiente','activa','revocada','expirada')) DEFAULT 'pendiente',
        fecha_generacion DATETIME DEFAULT CURRENT_TIMESTAMP,
        fecha_activacion DATETIME,
        fecha_expiracion DATETIME,
        superUser TEXT,
        notas TEXT,
        FOREIGN KEY (superUser) REFERENCES SuperUser(superUser)
      )
    `);

    // Crear SuperUser admin inicial desde .env (solo si no existe)
    if (process.env.ADMIN_USER && process.env.ADMIN_PASS) {
      const admin = await db.get(
        "SELECT * FROM SuperUser WHERE superUser = ?",
        [process.env.ADMIN_USER]
      );

      if (!admin) {
        const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
        const hashedPassword = await bcrypt.hash(
          process.env.ADMIN_PASS,
          saltRounds
        );

        await db.run(
          `INSERT INTO SuperUser (superUser, password, cant_usuarios_permitidos)
           VALUES (?, ?, ?)`,
          [
            process.env.ADMIN_USER,
            hashedPassword,
            process.env.ADMIN_MAX_USERS
              ? parseInt(process.env.ADMIN_MAX_USERS)
              : null,
          ]
        );

        console.log(`SuperUser inicial creado: ${process.env.ADMIN_USER}`);
      }

      // Crear licencia inicial asociada si no existe (sin key_hash)
      const existingLicense = await db.get(
        "SELECT id_license FROM License WHERE superUser = ?",
        [process.env.ADMIN_USER]
      );

      if (!existingLicense) {
        await db.run(
          `INSERT INTO License (superUser, tipo_licencia, max_usuarios, estado, fecha_activacion)
           VALUES (?, ?, ?, 'activa', datetime('now'))`,
          [
            process.env.ADMIN_USER,
            process.env.ADMIN_LICENSE_TYPE || "basica",
            process.env.ADMIN_MAX_USERS
              ? parseInt(process.env.ADMIN_MAX_USERS)
              : null,
          ]
        );

        console.log(
          `Licencia inicial creada para SuperUser: ${process.env.ADMIN_USER}`
        );
      }
    }

    console.log("Todas las tablas creadas/verificadas");
  } catch (err) {
    console.error("Error al inicializar la base de datos:", err);
  }
}

module.exports = db;
