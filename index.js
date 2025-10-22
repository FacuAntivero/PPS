// index.js
require("dotenv").config();
const Joi = require("joi");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const db = require("./db"); // conexión SQLite
const {
  PRESETS,
  hashLicenseKey,
  generateKeyPlaintext,
} = require("./lib/license");

app.use(express.json());
const cors = require("cors");
app.use(cors({ origin: "http://localhost:57001" }));

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => console.log(`Listening on port ${port}...`));

app.get("/", (req, res) => res.send("OK"));

app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});
/* ---------------------------
   Helpers
   --------------------------- */

// Obtiene el límite efectivo de usuarios para una residencia (licencia > legacy)
async function getEffectiveUserLimit(superUser) {
  const su = await db.get(
    "SELECT license_id, cant_usuarios_permitidos FROM SuperUser WHERE superUser = ?",
    [superUser]
  );
  if (!su) return null;

  if (su.license_id) {
    const lic = await db.get(
      "SELECT max_usuarios FROM License WHERE id_license = ?",
      [su.license_id]
    );
    if (lic) {
      // if max_usuarios is null => unlimited
      return lic.max_usuarios === null ? null : lic.max_usuarios;
    }
  }

  // fallback legacy (could be null)
  return typeof su.cant_usuarios_permitidos !== "undefined"
    ? su.cant_usuarios_permitidos
    : null;
}

/* ---------------------------
   Schemas
   --------------------------- */

const superUserLoginSchema = Joi.object({
  usuario: Joi.string().min(3).required().messages({
    "string.empty": "El nombre de superusuario es requerido",
    "string.min": "El nombre debe tener al menos 3 caracteres",
    "any.required": "El nombre de superusuario es obligatorio",
  }),
  password: Joi.string().min(6).required().messages({
    "string.empty": "La contraseña es requerida",
    "string.min": "La contraseña debe tener al menos 6 caracteres",
    "any.required": "La contraseña es obligatoria",
  }),
});

const userLoginSchema = Joi.object({
  usuario: Joi.string().min(3).required().messages({
    "string.empty": "El nombre de usuario es requerido",
    "string.min": "El nombre debe tener al menos 3 caracteres",
    "any.required": "El nombre de usuario es obligatorio",
  }),
  password: Joi.string().min(6).required().messages({
    "string.empty": "La contraseña es requerida",
    "string.min": "La contraseña debe tener al menos 6 caracteres",
    "any.required": "La contraseña es obligatoria",
  }),
});

/* ---------------------------
   LICENSE endpoints
   --------------------------- */

// Generar licencia (backoffice) - protegido por x-admin-token (ADMIN_TOKEN)
app.post("/license/generate", async (req, res) => {
  try {
    const adminToken = req.header("x-admin-token");
    if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
      return res.status(401).json({ success: false, error: "No autorizado" });
    }

    const {
      tipo_licencia = "basica",
      notas = "",
      max_usuarios = undefined,
    } = req.body;
    const finalMax =
      typeof max_usuarios === "number"
        ? max_usuarios
        : PRESETS[tipo_licencia] ?? null;

    const keyPlain = generateKeyPlaintext();
    const keyHash = hashLicenseKey(keyPlain);

    // Insertamos sin fecha_expiracion: la expiración se calculará al ACTIVAR la licencia
    await db.run(
      `INSERT INTO License (key_hash, tipo_licencia, max_usuarios, estado, notas, fecha_generacion)
       VALUES (?, ?, ?, 'pendiente', ?, datetime('now'))`,
      [keyHash, tipo_licencia, finalMax, notas]
    );
    
    await db.run(
      `INSERT INTO License (superUser, tipo_licencia, estado) VALUES (?, 'basica', 'activa')`,
      [value.superUser]
    );


    // Mostrar la clave en claro solo una vez (guardar en backoffice)
    res.status(201).json({
      success: true,
      licenseKey: keyPlain,
      tipo_licencia,
      max_usuarios: finalMax,
    });
  } catch (err) {
    console.error("Error generating license:", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

app.post("/license/validate", async (req, res) => {
  try {
    console.log("POST /license/validate body:", req.body);
    const { licenseKey } = req.body;
    if (!licenseKey) {
      return res.status(400).json({
        success: false,
        valid: false,
        message: "licenseKey es requerido",
      });
    }

    const trimmed = licenseKey.toString().trim();
    const keyHash = hashLicenseKey(trimmed);
    console.log("Computed keyHash:", keyHash);

    const row = await db.get(
      `SELECT id_license, tipo_licencia, estado, superUser, max_usuarios, fecha_expiracion
       FROM License WHERE key_hash = ?`,
      [keyHash]
    );

    console.log("License row found:", row);

    // 1) No está generada
    if (!row) {
      return res.status(404).json({
        success: false,
        valid: false,
        message: "Licencia invalida",
      });
    }

    // 2) Comprobar expiración (si existe fecha_expiracion)
    if (row.fecha_expiracion) {
      const expDate = new Date(row.fecha_expiracion.replace(" ", "T"));
      if (expDate < new Date()) {
        // marcar como expirada si no lo está
        if (row.estado !== "expirada") {
          try {
            await db.run(
              "UPDATE License SET estado = 'expirada' WHERE id_license = ?",
              [row.id_license]
            );
          } catch (e) {
            console.error("Error marcando licencia expirada:", e);
          }
        }
        return res.status(410).json({
          success: false,
          valid: false,
          message: "Licencia invalida: expirada",
          tipo_licencia: row.tipo_licencia,
          max_usuarios: row.max_usuarios,
          fecha_expiracion: row.fecha_expiracion,
        });
      }
    }

    // 3) Si está pendiente => canjeable
    if (row.estado === "pendiente") {
      return res.status(200).json({
        success: true,
        valid: true,
        message: "Licencia valida",
        tipo_licencia: row.tipo_licencia,
        max_usuarios: row.max_usuarios,
      });
    }

    // 4) Si ya está activa => ya usada
    if (row.estado === "activa") {
      return res.status(409).json({
        success: false,
        valid: false,
        message: "Licencia invalida, ya fue validada.",
        tipo_licencia: row.tipo_licencia,
        max_usuarios: row.max_usuarios,
        fecha_expiracion: row.fecha_expiracion || null,
        assigned: !!row.superUser,
      });
    }

    // 5) revocada u otros estados
    if (row.estado === "revocada") {
      return res.status(403).json({
        success: false,
        valid: false,
        message: "Licencia invalida: revocada",
      });
    }

    // fallback
    return res.status(400).json({
      success: false,
      valid: false,
      message: "Licencia invalida",
    });
  } catch (err) {
    console.error("Error en /license/validate:", err);
    return res.status(500).json({
      success: false,
      valid: false,
      message: "Error interno del servidor",
    });
  }
});

// Registrar nueva residencia (SuperUser)
app.post("/superuser", async (req, res) => {
  const schema = Joi.object({
    superUser: Joi.string().min(3).required().messages({
      "string.empty": "El nombre de la residencia es requerido",
      "string.min": "El nombre debe tener al menos 3 caracteres",
    }),
    password: Joi.string().min(6).required().messages({
      "string.empty": "La contraseña es requerida",
      "string.min": "La contraseña debe tener al menos 6 caracteres",
    }),
    confirmPassword: Joi.any().valid(Joi.ref("password")).required().messages({
      "any.only": "Las contraseñas no coinciden",
      "any.required": "La confirmación de contraseña es requerida",
    }),
    licenseKey: Joi.string().min(8).required().messages({
      "string.empty": "La licencia es requerida",
      "string.min": "La licencia debe tener al menos 8 caracteres",
    }),
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ success: false, error: error.details[0].message });
  }

  try {
    const { superUser, password, licenseKey } = value;
    const keyHash = hashLicenseKey(licenseKey);

    // Buscar licencia canjeable (por hash)
    const license = await db.get(
      "SELECT id_license, estado, max_usuarios, tipo_licencia FROM License WHERE key_hash = ?",
      [keyHash]
    );

    if (!license) {
      return res
        .status(400)
        .json({ success: false, error: "Licencia inválida" });
    }

    if (license.estado !== "pendiente") {
      return res.status(409).json({
        success: false,
        error: "La licencia no está disponible para canjear",
      });
    }

    const finalCant = license.max_usuarios; // puede ser null = ilimitado
    const hashedPassword = await bcrypt.hash(password, 10);

    // Transacción: insertar SuperUser y activar la licencia
    await db.run("BEGIN TRANSACTION");
    try {
      await db.run(
        "INSERT INTO SuperUser (superUser, password, cant_usuarios_permitidos, license_id) VALUES (?, ?, ?, ?)",
        [superUser, hashedPassword, finalCant, license.id_license]
      );

      await db.run(
        `UPDATE License
         SET estado = 'activa',
             fecha_activacion = datetime('now'),
             fecha_expiracion = datetime('now', '+1 year'),
             superUser = ?
         WHERE id_license = ?`,
        [superUser, license.id_license]
      );

      await db.run("COMMIT");

      return res.status(201).json({
        success: true,
        tipo_licencia: license.tipo_licencia,
        max_usuarios: finalCant,
      });
    } catch (innerErr) {
      await db.run("ROLLBACK");
      if (innerErr.message && innerErr.message.includes("UNIQUE constraint")) {
        return res
          .status(409)
          .json({ success: false, error: "El nombre de residencia ya existe" });
      }
      console.error("Error en registro con licencia:", innerErr);
      return res
        .status(500)
        .json({ success: false, error: "Error interno del servidor" });
    }
  } catch (err) {
    console.error("Error en POST /superuser:", err);
    return res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Login SuperUser
   --------------------------- */
app.post("/login-superuser", async (req, res) => {
  try {
    const { error } = superUserLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { usuario, password } = req.body;

    // Buscar superusuario en DB
    const superUser = await db.get(
      "SELECT password FROM SuperUser WHERE superUser = ?",
      [usuario]
    );

    if (!superUser) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    // Comparar contraseña
    const match = await bcrypt.compare(password, superUser.password);
    if (!match) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    // Obtener tipo de licencia (si aplica)
    const license = await db.get(
      `SELECT tipo_licencia 
       FROM License 
       WHERE superUser = ? 
         AND estado = 'activa'
       ORDER BY fecha_activacion DESC 
       LIMIT 1`,
      [usuario]
    );

    // Detectar admin (según .env.ADMIN_USER)
    const isAdmin =
      !!process.env.ADMIN_USER && usuario === process.env.ADMIN_USER;

    res.status(200).json({
      success: true,
      tipo_licencia: license ? license.tipo_licencia : null,
      is_admin: isAdmin, // <-- indicador útil para el frontend
    });
  } catch (error) {
    console.error("Error en login-superuser:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

/* ---------------------------
   Login User (profesional)
   --------------------------- */
app.post("/login-user", async (req, res) => {
  try {
    const { error } = userLoginSchema.validate(req.body);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { usuario, password } = req.body;
    const user = await db.get(
      "SELECT password, superUser FROM User WHERE user = ?",
      [usuario]
    );
    if (!user)
      return res
        .status(401)
        .json({ success: false, error: "Credenciales inválidas" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res
        .status(401)
        .json({ success: false, error: "Credenciales inválidas" });

    res.status(200).json({ success: true, superUser: user.superUser });
  } catch (error) {
    console.error("Error en login-user:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Cambiar contraseña por SuperUser
   --------------------------- */
const changePasswordSchema = Joi.object({
  superUser: Joi.string().min(3).required().messages({
    "string.empty": "El superusuario es requerido",
    "any.required": "El superusuario es obligatorio",
  }),
  superUserPassword: Joi.string().min(6).required().messages({
    "string.empty": "La contraseña del superusuario es requerida",
    "any.required": "La contraseña del superusuario es obligatoria",
  }),
  targetUser: Joi.string().min(3).required().messages({
    "string.empty": "El usuario objetivo es requerido",
    "any.required": "El usuario objetivo es obligatorio",
  }),
  newPassword: Joi.string().min(6).required().messages({
    "string.empty": "La nueva contraseña es requerida",
    "string.min": "La nueva contraseña debe tener al menos 6 caracteres",
    "any.required": "La nueva contraseña es obligatoria",
  }),
});

app.put("/cambiar-password", async (req, res) => {
  try {
    const { error } = changePasswordSchema.validate(req.body);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { superUser, superUserPassword, targetUser, newPassword } = req.body;

    const superUserRecord = await db.get(
      "SELECT password FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUserRecord)
      return res
        .status(404)
        .json({ success: false, error: "Superusuario no encontrado" });

    const superUserMatch = await bcrypt.compare(
      superUserPassword,
      superUserRecord.password
    );
    if (!superUserMatch)
      return res.status(401).json({
        success: false,
        error: "Credenciales de superusuario inválidas",
      });

    const userRecord = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [targetUser, superUser]
    );
    if (!userRecord)
      return res.status(404).json({
        success: false,
        error: "Usuario no encontrado o no pertenece a este superusuario",
      });

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await db.run(
      "UPDATE User SET password = ? WHERE user = ? AND superUser = ?",
      [newPasswordHash, targetUser, superUser]
    );

    res
      .status(200)
      .json({ success: true, message: "Contraseña actualizada exitosamente" });
  } catch (error) {
    console.error("Error al cambiar contraseña:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Listar usuarios (query)
   --------------------------- */
const listUsersSchema = Joi.object({
  superUser: Joi.string().min(3).required().messages({
    "string.empty": "superUser no puede estar vacío",
    "string.min": "superUser debe tener al menos 3 caracteres",
    "any.required": "superUser es obligatorio",
  }),
});

app.get("/usuarios", async (req, res) => {
  try {
    const { error } = listUsersSchema.validate(req.query);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { superUser } = req.query;
    const superUserExists = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUserExists)
      return res
        .status(404)
        .json({ success: false, error: "El superusuario no existe" });

    const users = await db.all("SELECT user FROM User WHERE superUser = ?", [
      superUser,
    ]);
    const userList = users.map((u) => u.user);

    res.status(200).json({ success: true, usuarios: userList });
  } catch (error) {
    console.error("Error en GET /usuarios:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Agregar nuevo Usuario (profesional)
   --------------------------- */
const usuarioSchema = Joi.object({
  user: Joi.string().min(3).required().messages({
    "string.empty": "user no puede estar vacío",
    "string.min": "user debe tener al menos 3 caracteres",
    "any.required": "user es obligatorio",
  }),
  superUser: Joi.string().min(3).required().messages({
    "string.empty": "superUser no puede estar vacío",
    "string.min": "superUser debe tener al menos 3 caracteres",
    "any.required": "superUser es obligatorio",
  }),
  nombreReal: Joi.string().min(3).required().messages({
    "string.empty": "nombreReal no puede estar vacío",
    "string.min": "nombreReal debe tener al menos 3 caracteres",
    "any.required": "nombreReal es obligatorio",
  }),
  password: Joi.string().min(6).required().messages({
    "string.empty": "password no puede estar vacío",
    "string.min": "password debe tener al menos 6 caracteres",
    "any.required": "password es obligatorio",
  }),
});

app.post("/usuarios", async (req, res) => {
  try {
    const { error, value } = usuarioSchema.validate(req.body);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { user, superUser, nombreReal, password } = value;
    const superUsuario = await db.get(
      "SELECT superUser, cant_usuarios_permitidos, license_id FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUsuario)
      return res
        .status(404)
        .json({ success: false, error: "El superusuario no está registrado" });

    const usuarioExistente = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [user, superUser]
    );
    if (usuarioExistente)
      return res.status(409).json({
        success: false,
        error: "El usuario ya está registrado con este superusuario",
      });

    // Verificar límite de usuarios (usa licencia si existe, sino legacy)
    const effectiveLimit = await getEffectiveUserLimit(superUser);
    const [currentUsers] = await db.all(
      "SELECT COUNT(*) AS count FROM User WHERE superUser = ?",
      [superUser]
    );

    if (
      typeof effectiveLimit === "number" &&
      currentUsers.count >= effectiveLimit
    ) {
      return res.status(403).json({
        success: false,
        error: "Límite de usuarios alcanzado para este superusuario",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      "INSERT INTO User (user, superUser, nombreReal, password) VALUES (?, ?, ?, ?)",
      [user, superUser, nombreReal, hashedPassword]
    );

    res
      .status(201)
      .json({ success: true, message: "Usuario agregado exitosamente" });
  } catch (error) {
    console.error("Error en POST /usuarios:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Crear sesiones
   --------------------------- */
app.post("/sesiones", async (req, res) => {
  try {
    const { paciente, user, superUser, estadoInicial } = req.body;
    const usuario = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [user, superUser]
    );
    if (!usuario)
      return res
        .status(404)
        .json({ success: false, error: "Usuario profesional no encontrado" });

    const result = await db.run(
      `INSERT INTO Sesion (paciente, user, superUser, inicio, estadoInicial) VALUES (?, ?, ?, datetime('now'), ?)`,
      [paciente, user, superUser, estadoInicial]
    );

    res.status(201).json({
      success: true,
      id_sesion: result.lastID,
      message: "Sesión iniciada",
    });
  } catch (error) {
    console.error("Error en POST /sesiones:", error);
    res
      .status(500)
      .json({ success: false, error: "Error al iniciar sesión terapéutica" });
  }
});

/* ---------------------------
   Finalizar sesión
   --------------------------- */
app.put("/sesiones/:id/finalizar", async (req, res) => {
  try {
    const { id } = req.params;
    const { estadoFinal } = req.body;
    await db.run(
      `UPDATE Sesion SET fin = datetime('now'), estadoFinal = ? WHERE id_sesion = ?`,
      [estadoFinal, id]
    );
    res.json({ success: true, message: "Sesión finalizada" });
  } catch (error) {
    console.error("Error al finalizar sesión:", error);
    res
      .status(500)
      .json({ success: false, error: "Error al finalizar sesión" });
  }
});

/* ---------------------------
   Registrar ejercicio
   --------------------------- */
app.post("/ejercicios", async (req, res) => {
  try {
    const { id_sesion, escena } = req.body;
    const result = await db.run(
      `INSERT INTO Ejercicio (id_sesion, escena, inicio) VALUES (?, ?, datetime('now'))`,
      [id_sesion, escena]
    );
    res.status(201).json({
      success: true,
      id_ejercicio: result.lastID,
      message: "Ejercicio iniciado",
    });
  } catch (error) {
    console.error("Error en POST /ejercicios:", error);
    res
      .status(500)
      .json({ success: false, error: "Error al iniciar ejercicio" });
  }
});

/* ---------------------------
   Finalizar ejercicio
   --------------------------- */
app.put("/ejercicios/:id/finalizar", async (req, res) => {
  try {
    const { id } = req.params;
    await db.run(
      `UPDATE Ejercicio SET fin = datetime('now') WHERE id_ejercicio = ?`,
      [id]
    );
    res.json({ success: true, message: "Ejercicio finalizado" });
  } catch (error) {
    console.error("Error al finalizar ejercicio:", error);
    res
      .status(500)
      .json({ success: false, error: "Error al finalizar ejercicio" });
  }
});

/* ---------------------------
   Registrar métricas
   --------------------------- */
app.post("/metricas", async (req, res) => {
  try {
    const { id_ejercicio, nombre, data } = req.body;
    await db.run(
      `INSERT INTO Metrica (id_ejercicio, nombre, data) VALUES (?, ?, ?)`,
      [id_ejercicio, nombre, JSON.stringify(data)]
    );
    res.status(201).json({ success: true, message: "Métrica registrada" });
  } catch (error) {
    console.error("Error en POST /metricas:", error);
    res
      .status(500)
      .json({ success: false, error: "Error al registrar métrica" });
  }
});

/* ---------------------------
   Obtener métricas de un paciente
   --------------------------- */
const metricasPacienteSchema = Joi.object({
  paciente: Joi.string().min(1).required().messages({
    "string.empty": "El nombre del paciente es requerido",
    "any.required": "El paciente es obligatorio",
  }),
  user: Joi.string().min(1).required().messages({
    "string.empty": "El usuario profesional es requerido",
    "any.required": "El usuario profesional es obligatorio",
  }),
  superUser: Joi.string().min(1).required().messages({
    "string.empty": "El superusuario es requerido",
    "any.required": "El superusuario es obligatorio",
  }),
});

app.get("/metricas-paciente", async (req, res) => {
  try {
    const { error, value } = metricasPacienteSchema.validate(req.query);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { paciente, user, superUser } = value;
    const sesiones = await db.all(
      `SELECT id_sesion FROM Sesion WHERE paciente = ? AND user = ? AND superUser = ?`,
      [paciente, user, superUser]
    );
    if (sesiones.length === 0)
      return res.status(404).json({
        success: false,
        error: "No se encontraron sesiones para este paciente y profesional",
      });

    const metricas = await db.all(
      `SELECT M.id_metrica, M.nombre AS nombre_metrica, M.data, E.escena, E.inicio AS inicio_ejercicio, E.fin AS fin_ejercicio, S.inicio AS inicio_sesion, S.fin AS fin_sesion, S.estadoInicial, S.estadoFinal
       FROM Metrica M
       JOIN Ejercicio E ON M.id_ejercicio = E.id_ejercicio
       JOIN Sesion S ON E.id_sesion = S.id_sesion
       WHERE S.paciente = ? AND S.user = ? AND S.superUser = ?`,
      [paciente, user, superUser]
    );

    if (metricas.length === 0)
      return res.status(404).json({
        success: false,
        error: "No se encontraron métricas para este paciente",
      });

    const resultado = metricas.map((metrica) => ({
      id_metrica: metrica.id_metrica,
      nombre: metrica.nombre_metrica,
      data: JSON.parse(metrica.data),
      ejercicio: {
        escena: metrica.escena,
        inicio: metrica.inicio_ejercicio,
        fin: metrica.fin_ejercicio,
      },
      sesion: {
        inicio: metrica.inicio_sesion,
        fin: metrica.fin_sesion,
        estadoInicial: metrica.estadoInicial,
        estadoFinal: metrica.estadoFinal,
      },
    }));

    res.status(200).json({
      success: true,
      paciente,
      profesional: user,
      residencia: superUser,
      metricas: resultado,
    });
  } catch (error) {
    console.error("Error en GET /metricas-paciente:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Obtener usuarios de un SuperUser
   --------------------------- */
const superUserParamSchema = Joi.string().min(3).required().messages({
  "string.empty": "superUser no puede estar vacío",
  "string.min": "superUser debe tener al menos 3 caracteres",
  "any.required": "superUser es obligatorio",
});

app.get("/superuser/:superUser/usuarios", async (req, res) => {
  try {
    const { superUser } = req.params;
    const { error } = superUserParamSchema.validate(superUser);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const superUserExists = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUserExists)
      return res
        .status(404)
        .json({ success: false, error: "El superusuario no existe" });

    const usuarios = await db.all(
      "SELECT user, nombreReal FROM User WHERE superUser = ?",
      [superUser]
    );
    res.status(200).json({
      success: true,
      superUser,
      total_usuarios: usuarios.length,
      usuarios,
    });
  } catch (error) {
    console.error("Error en GET /superuser/:superUser/usuarios:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});
