// index.js
const crypto = require("crypto");
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
app.use(cors({ origin: ["http://localhost:53521"] }));

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => console.log(`Listening on port ${port}...`));

app.get("/", (req, res) => res.send("OK"));

app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});
// Middleware mínimo para endpoints admin — comprueba cabeceras
function requireAdmin(req, res, next) {
  const adminUser = process.env.ADMIN_USER;
  const adminPass = process.env.ADMIN_PASS;
  const headerUser = req.header("x-admin-user");
  const headerPass = req.header("x-admin-pass");

  if (!adminUser || !adminPass) {
    return res
      .status(500)
      .json({ success: false, error: "Admin no configurado en servidor" });
  }

  if (headerUser !== adminUser || headerPass !== adminPass) {
    return res
      .status(403)
      .json({ success: false, error: "Acceso de administrador denegado" });
  }
  next();
}

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
// Si la app externa (Oculus) necesita una API key para guardar:
function requireApiKey(req, res, next) {
  const apiKey = req.header("x-api-key");
  if (!apiKey || apiKey !== process.env.EXTERNAL_API_KEY) {
    return res
      .status(401)
      .json({ success: false, error: "API Key inválida o faltante" });
  }
  next();
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
  password: Joi.string().min(5).required().messages({
    "string.empty": "La contraseña es requerida",
    "string.min": "La contraseña debe tener al menos 5 caracteres",
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

function hashingLicenseKey(licenseKey) {
  return crypto
    .createHash("sha256")
    .update(licenseKey.toString().trim())
    .digest("hex");
}

// ==========================================================
// 1. ENDPOINT: GENERAR LICENCIA (ADMIN)
// ==========================================================
app.post("/license/generate", requireAdmin, async (req, res) => {
  try {
    const { tipo_licencia } = req.body; // opcional, default 'basica'
    const tipo = tipo_licencia || "basica";

    // Mapping por defecto de máximos si no se proporciona max_usuarios:
    const maxMap = { basica: 3, mediana: 7, pro: 10, custom: null };
    const maxUsuarios = req.body.max_usuarios ?? maxMap[tipo] ?? null;

    // Generar clave legible (ej: 24 chars)
    // Usamos generateKeyPlaintext importada
    const licenseKey = generateKeyPlaintext();

    // Generamos el hash usando la función consistente
    const keyHash = hashingLicenseKey(licenseKey);

    const result = await db.run(
      `INSERT INTO License (key_hash, tipo_licencia, max_usuarios, estado, fecha_generacion)
            VALUES (?, ?, ?, 'pendiente', datetime('now'))`,
      [keyHash, tipo, maxUsuarios]
    );

    res.status(201).json({
      success: true,
      id_license: result.lastID,
      licenseKey, // IMPORTANTE: clave en texto plano para el admin
      tipo_licencia: tipo,
      max_usuarios: maxUsuarios,
    });
  } catch (err) {
    console.error("Error POST /license/generate", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// ==========================================================
// 2. ENDPOINT: VALIDAR LICENCIA
// ==========================================================
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
    const keyHash = hashingLicenseKey(trimmed); // Uso consistente de la función
    console.log("Computed keyHash:", keyHash);

    const row = await db.get(
      `SELECT id_license, tipo_licencia, estado, superUser, max_usuarios, fecha_expiracion
             FROM License WHERE key_hash = ?`,
      [keyHash]
    );

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

// ==========================================================
// 3. ENDPOINT: REGISTRAR SUPERUSER (Ruta ajustada a /superusers/register)
// ==========================================================
app.post("/superusers/register", async (req, res) => {
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
    const keyHash = hashingLicenseKey(licenseKey); // Uso consistente de la función

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
      // Asegúrate de que los nombres de columna aquí (superUser, password, etc.) coincidan con tu BD
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
    console.error("Error en POST /superusers/register:", err);
    return res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// Devuelve la licencia más reciente asociada a superUser (puede venir con estado 'activa','expirada','revocada','pendiente')
app.get("/license/active", async (req, res) => {
  try {
    const { superUser } = req.query;
    if (!superUser) {
      return res
        .status(400)
        .json({ success: false, error: "superUser is required" });
    }

    const license = await db.get(
      `SELECT id_license, tipo_licencia, estado, max_usuarios, fecha_generacion, fecha_activacion, fecha_expiracion, notas
       FROM License
       WHERE superUser = ?
       ORDER BY 
         CASE WHEN fecha_activacion IS NOT NULL THEN datetime(fecha_activacion) ELSE datetime(fecha_generacion) END DESC
       LIMIT 1`,
      [superUser]
    );

    return res.status(200).json({ success: true, license: license || null });
  } catch (err) {
    console.error("Error GET /license/active:", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// Login SuperUser (residencia)
app.post("/login-superuser", async (req, res) => {
  try {
    // Validar estructura de los datos
    const { error } = superUserLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { usuario, password } = req.body;

    // Buscar superusuario
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

    const match = await bcrypt.compare(password, superUser.password);
    if (!match) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    const license = await db.get(
      `SELECT tipo_licencia 
       FROM License 
       WHERE superUser = ? 
         AND estado = 'activa'
       ORDER BY fecha_activacion DESC 
       LIMIT 1`,
      [usuario]
    );

    const isAdmin = !!(
      process.env.ADMIN_USER && usuario === process.env.ADMIN_USER
    );

    res.status(200).json({
      success: true,
      tipo_licencia: license ? license.tipo_licencia : null,
      is_admin: !!(
        process.env.ADMIN_USER && usuario === process.env.ADMIN_USER
      ),
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
app.get("/admin/superusers", requireAdmin, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT
        S.superUser,
        S.cant_usuarios_permitidos,
        -- licencia activa más reciente por superUser (puede ser NULL)
        (SELECT id_license
         FROM License L
         WHERE L.superUser = S.superUser
           AND L.estado = 'activa'
         ORDER BY L.fecha_activacion DESC
         LIMIT 1) AS id_license,
        (SELECT tipo_licencia
         FROM License L
         WHERE L.superUser = S.superUser
           AND L.estado = 'activa'
         ORDER BY L.fecha_activacion DESC
         LIMIT 1) AS tipo_licencia,
        (SELECT estado
         FROM License L
         WHERE L.superUser = S.superUser
           AND L.estado = 'activa'
         ORDER BY L.fecha_activacion DESC
         LIMIT 1) AS licencia_estado,
        (SELECT fecha_expiracion
         FROM License L
         WHERE L.superUser = S.superUser
           AND L.estado = 'activa'
         ORDER BY L.fecha_activacion DESC
         LIMIT 1) AS fecha_expiracion
      FROM SuperUser S
      ORDER BY S.superUser
    `);

    res.json({ success: true, total: rows.length, superusers: rows });
  } catch (err) {
    console.error("Error GET /admin/superusers", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// GET /license (admin)
app.get("/license", requireAdmin, async (req, res) => {
  try {
    const rows = await db.all(
      `SELECT id_license, tipo_licencia, max_usuarios, estado, fecha_generacion, fecha_activacion, fecha_expiracion, superUser, notas
       FROM License ORDER BY fecha_generacion DESC`
    );
    res.json({ success: true, total: rows.length, licenses: rows });
  } catch (err) {
    console.error("Error GET /license", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// DELETE /license/:id
app.delete("/license/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run("DELETE FROM License WHERE id_license = ?", [id]);
    res.json({ success: true, message: "Licencia borrada" });
  } catch (err) {
    console.error("Error DELETE /license/:id", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// --- FUNCIÓN CENTRAL DE CHEQUEO DE LICENCIA ---
// Esta función es crucial para la validación tanto del frontend como del backend.
async function getSuperUserLicenseStatus(superUser) {
  try {
    const licenseData = await db.get(
      `SELECT * FROM License WHERE superUser = ?`,
      [superUser]
    );

    if (!licenseData) {
      // Si no hay licencia asociada
      return {
        active: false,
        maxUsers: 0,
        currentUsers: 0,
        error: "Licencia no encontrada para el SuperUser.",
      };
    }

    const currentUsersResult = await db.get(
      `SELECT COUNT(id_usuario) as currentUsers FROM Usuarios WHERE superUser = ?`,
      [superUser]
    );
    const currentUsers = currentUsersResult.currentUsers;
    const now = new Date();
    const expirationDate = new Date(licenseData.fecha_expiracion);

    // Determinamos si la licencia está expirada por fecha o por estado manual del administrador
    const isExpiredByDate = expirationDate <= now;
    const isExpiredByAdmin = licenseData.estado === "expirada";

    const licenseStatus = {
      // Es activa solo si el estado es 'activa' Y la fecha no ha pasado
      active: licenseData.estado === "activa" && !isExpiredByDate,
      isExpired: isExpiredByDate || isExpiredByAdmin,
      maxUsers: licenseData.max_usuarios,
      currentUsers: currentUsers,
      estado: licenseData.estado,
      fechaExpiracion: licenseData.fecha_expiracion,
    };

    return licenseStatus;
  } catch (err) {
    console.error("Error al obtener el estado de la licencia:", err);
    return {
      active: false,
      maxUsers: 0,
      currentUsers: 0,
      error: "Error interno al verificar la licencia.",
    };
  }
}

// PUT /license/:id/expire
app.put("/license/:id/expire", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run(
      `UPDATE License SET estado = 'expirada', fecha_expiracion = datetime('now') WHERE id_license = ?`,
      [id]
    );
    res.json({ success: true, message: "Licencia marcada como expirada" });
  } catch (err) {
    console.error("Error PUT /license/:id/expire", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});
async function getSuperUserLicenseStatus(superUser) {
  try {
    // Obtenemos la licencia por el nombre del SuperUser (que es el campo 'superUser' en License)
    const licenseData = await db.get(
      `SELECT * FROM License WHERE superUser = ?`,
      [superUser]
    );

    if (!licenseData) {
      return {
        active: false,
        maxUsers: 0,
        currentUsers: 0,
        error: "Licencia no encontrada.",
      };
    }

    const currentUsersResult = await db.get(
      `SELECT COUNT(id_usuario) as currentUsers FROM Usuarios WHERE superUser = ?`,
      [superUser]
    );
    const currentUsers = currentUsersResult.currentUsers;

    const licenseStatus = {
      active:
        licenseData.estado === "activa" &&
        new Date(licenseData.fecha_expiracion) > new Date(),
      isExpired:
        licenseData.estado === "expirada" ||
        new Date(licenseData.fecha_expiracion) <= new Date(),
      maxUsers: licenseData.max_usuarios,
      currentUsers: currentUsers,
      estado: licenseData.estado,
      fechaExpiracion: licenseData.fecha_expiracion,
    };

    // Si el estado es 'expirada' por la acción del administrador o la fecha pasó
    if (licenseStatus.isExpired || licenseData.estado !== "activa") {
      licenseStatus.active = false;
    }

    return licenseStatus;
  } catch (err) {
    console.error("Error al obtener el estado de la licencia:", err);
    return {
      active: false,
      maxUsers: 0,
      currentUsers: 0,
      error: "Error interno al verificar la licencia.",
    };
  }
}

// --- RUTA DE API para que el frontend valide el estado (SuperUserDashboard) ---
// La ruta que usa tu Flutter: await _api!.checkLicenseStatus(superUser: currentSuperUser);
app.get("/license/status/:superUser", async (req, res) => {
  const { superUser } = req.params;
  const status = await getSuperUserLicenseStatus(superUser);

  if (status.error) {
    return res.status(500).json({ success: false, error: status.error });
  }

  // El frontend usa 'isExpired' para el chequeo de vigencia.
  res.json({
    success: true,
    isExpired: status.isExpired,
    isActive: status.active,
    maxUsers: status.maxUsers,
    currentUsers: status.currentUsers,
    message: status.active
      ? "Licencia activa."
      : "Licencia no activa o expirada.",
  });
});

// --- RUTA CLAVE: CREACIÓN DE USUARIO (CON VALIDACIÓN DE LICENCIA Y LÍMITE) ---
app.post("/createUsuario", async (req, res) => {
  // Asegúrate de que los campos vengan en el cuerpo de la solicitud
  const { user, superUser, nombreReal, password } = req.body;

  // 1. OBTENER Y VALIDAR ESTADO DE LA LICENCIA
  const status = await getSuperUserLicenseStatus(superUser);

  if (status.error) {
    return res.status(500).json({ success: false, error: status.error });
  }

  // Chequeo de vigencia/estado: Si no está activa (por admin o por fecha)
  if (!status.active) {
    return res.status(403).json({
      success: false,
      error:
        status.estado === "expirada"
          ? "La licencia ha sido marcada como expirada por el administrador."
          : "La licencia ha expirado por fecha o no está activa.",
    });
  }

  // 2. VALIDAR LÍMITE DE PROFESIONALES
  if (status.currentUsers >= status.maxUsers) {
    return res.status(403).json({
      success: false,
      error: `Límite de ${status.maxUsers} profesionales alcanzado. (${status.currentUsers} de ${status.maxUsers})`,
    });
  }

  // 3. CONTINUAR CON LA CREACIÓN DEL USUARIO
  try {
    // [AQUÍ DEBERÍAS HASHEAR LA CONTRASEÑA, EJEMPLO SIMPLE POR AHORA]
    const hashedPassword = password;

    await db.run(
      `INSERT INTO Usuarios (user, superUser, nombreReal, password) VALUES (?, ?, ?, ?)`,
      [user, superUser, nombreReal, hashedPassword]
    );

    res.json({ success: true, message: "Profesional creado exitosamente." });
  } catch (err) {
    if (err.message && err.message.includes("UNIQUE constraint failed")) {
      return res.status(400).json({
        success: false,
        error: "El nombre de usuario ya está en uso.",
      });
    }
    console.error("Error POST /createUsuario:", err);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor al crear usuario.",
    });
  }
});
// Cambiar password de una Residencia siendo Admin
app.put(
  "/admin/superuser/:superUser/password",
  requireAdmin,
  async (req, res) => {
    try {
      const { superUser } = req.params;
      const { newPassword } = req.body;
      if (!newPassword || newPassword.length < 6) {
        return res
          .status(400)
          .json({ success: false, error: "newPassword mínimo 6 caracteres" });
      }
      const hashed = await bcrypt.hash(newPassword, 10);
      const result = await db.run(
        "UPDATE SuperUser SET password = ? WHERE superUser = ?",
        [hashed, superUser]
      );
      if (!result.changes && result.changes !== 0) {
        /* sqlite driver specifics */
      }
      res.json({
        success: true,
        message: "Contraseña de residencia actualizada",
      });
    } catch (err) {
      console.error("Error PUT /admin/superuser/:superUser/password", err);
      res
        .status(500)
        .json({ success: false, error: "Error interno del servidor" });
    }
  }
);

//Borrar un SuperUser y todas sus licencias asociadas.
app.delete("/admin/superuser/:superUser", requireAdmin, async (req, res) => {
  try {
    const { superUser } = req.params;
    if (!superUser) {
      return res
        .status(400)
        .json({ success: false, error: "Falta el nombre de superUser" });
    }

    // 1. Borramos primero las licencias asociadas (hijo)
    await db.run(`DELETE FROM License WHERE superUser = ?`, [superUser]);

    // 2. Borramos el SuperUser (padre)
    const result = await db.run("DELETE FROM SuperUser WHERE superUser = ?", [
      superUser,
    ]);

    if (result.changes === 0) {
      // Si result.changes es 0, significa que no se encontró
      // un SuperUser con ese nombre.
      return res.status(404).json({
        success: false,
        error: "Residencia (SuperUser) no encontrada",
      });
    }

    res.json({
      success: true,
      message: "Residencia y sus licencias asociadas han sido eliminadas",
    });
  } catch (err) {
    console.error("Error DELETE /admin/superuser/:superUser", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});
// GET /license (admin)
app.get("/license", requireAdmin, async (req, res) => {
  try {
    const rows = await db.all(
      `SELECT id_license, tipo_licencia, max_usuarios, estado, fecha_generacion, fecha_activacion, fecha_expiracion, superUser, notas
       FROM License ORDER BY fecha_generacion DESC`
    );
    res.json({ success: true, total: rows.length, licenses: rows });
  } catch (err) {
    console.error("Error GET /license", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// DELETE /license/:id
app.delete("/license/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run("DELETE FROM License WHERE id_license = ?", [id]);
    res.json({ success: true, message: "Licencia borrada" });
  } catch (err) {
    console.error("Error DELETE /license/:id", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// PUT /license/:id/expire
app.put("/license/:id/expire", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run(
      `UPDATE License SET estado = 'expirada', fecha_expiracion = datetime('now') WHERE id_license = ?`,
      [id]
    );
    res.json({ success: true, message: "Licencia marcada como expirada" });
  } catch (err) {
    console.error("Error PUT /license/:id/expire", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/* ---------------------------
   Cambiar contraseña de un profesional desde el panel de Residencia
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
    // Validar parámetros de query
    const { error } = listUsersSchema.validate(req.query);
    if (error)
      return res
        .status(400)
        .json({ success: false, error: error.details[0].message });

    const { superUser } = req.query;

    // Verificar que el superUser exista
    const superUserExists = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUserExists)
      return res
        .status(404)
        .json({ success: false, error: "El superusuario no existe" });

    // Buscar la licencia ACTIVA más reciente del superUser
    const activeLicense = await db.get(
      `SELECT id_license, tipo_licencia, max_usuarios, estado, fecha_activacion, fecha_expiracion
       FROM License
       WHERE superUser = ?
         AND estado = 'activa'
       ORDER BY fecha_activacion DESC
       LIMIT 1`,
      [superUser]
    );

    if (!activeLicense) {
      // No hay licencia activa -> no permitimos listar/usar usuarios
      return res.status(403).json({
        success: false,
        error:
          "No hay licencia activa para este superusuario. Contacte al administrador.",
      });
    }

    // Obtener usuarios (incluye nombre real)
    const usuariosRows = await db.all(
      "SELECT user, nombreReal FROM User WHERE superUser = ?",
      [superUser]
    );

    // Contar usuarios actuales
    const countRow = await db.get(
      "SELECT COUNT(*) AS count FROM User WHERE superUser = ?",
      [superUser]
    );
    const totalUsuarios = countRow ? countRow.count : usuariosRows.length;

    // Formatear respuesta: usuarios como lista de objetos
    const usuarios = usuariosRows.map((r) => ({
      user: r.user,
      nombreReal: r.nombreReal,
    }));

    res.status(200).json({
      success: true,
      superUser,
      tipo_licencia: activeLicense.tipo_licencia,
      max_usuarios: activeLicense.max_usuarios, // null = ilimitado
      total_usuarios: totalUsuarios,
      usuarios,
    });
  } catch (error) {
    console.error("Error en GET /usuarios:", error);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

// Esquema de validación para agregar un nuevo Usuario (mantén tu usuarioSchema)
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
    // Validar entrada
    const { error, value } = usuarioSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { user, superUser, nombreReal, password } = value;

    // Verificar existencia de superUser
    const superUsuario = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );
    if (!superUsuario) {
      return res.status(404).json({
        success: false,
        error: "El superusuario no está registrado",
      });
    }

    // Verificar si el usuario ya existe
    const usuarioExistente = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [user, superUser]
    );
    if (usuarioExistente) {
      return res.status(409).json({
        success: false,
        error: "El usuario ya está registrado con este superusuario",
      });
    }

    // --- NUEVA LÓGICA: comprobar licencia ACTIVA y limites ---
    const license = await db.get(
      `SELECT id_license, tipo_licencia, max_usuarios, estado, fecha_expiracion
       FROM License
       WHERE superUser = ?
         AND estado = 'activa'
       ORDER BY fecha_activacion DESC, fecha_generacion DESC
       LIMIT 1`,
      [superUser]
    );

    if (!license) {
      // No hay licencia activa -> bloquear creación
      return res.status(403).json({
        success: false,
        error:
          "No hay licencia activa para esta residencia. Contacte al administrador.",
      });
    }

    // Si existe fecha_expiracion, verificar que no haya expirado
    if (license.fecha_expiracion) {
      const expCheck = await db.get(
        `SELECT CASE WHEN datetime(?) <= datetime('now') THEN 1 ELSE 0 END AS expired`,
        [license.fecha_expiracion]
      );
      if (expCheck && expCheck.expired === 1) {
        return res.status(403).json({
          success: false,
          error:
            "La licencia de la residencia ha expirado. No se pueden crear usuarios.",
        });
      }
    }

    // Contar usuarios actuales
    const countRow = await db.get(
      "SELECT COUNT(*) AS count FROM User WHERE superUser = ?",
      [superUser]
    );
    const currentCount = countRow ? countRow.count : 0;

    // Si max_usuarios es NULL -> ilimitado
    if (license.max_usuarios !== null && license.max_usuarios !== undefined) {
      if (currentCount >= license.max_usuarios) {
        return res.status(403).json({
          success: false,
          error: "Límite de usuarios alcanzado para esta residencia.",
        });
      }
    }
    // --- FIN LÓGICA DE LICENCIA ---

    // Hashear la contraseña e insertar usuario
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      "INSERT INTO User (user, superUser, nombreReal, password) VALUES (?, ?, ?, ?)",
      [user, superUser, nombreReal, hashedPassword]
    );

    res.status(201).json({
      success: true,
      message: "Usuario agregado exitosamente",
    });
  } catch (error) {
    console.error("Error en POST /usuarios:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

/**
 * Cambia estado a 'activa' y suma 1 año a la fecha de expiración.
 */
app.put("/license/:id/renew", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Calcular la nueva fecha de expiración en JavaScript
    const now = new Date();
    now.setFullYear(now.getFullYear() + 1);

    // 2. Formatear la fecha para SQLite (YYYY-MM-DD HH:MM:SS)
    // .toISOString() -> 2025-10-30T20:15:00.000Z
    const newExpirationDate = now.toISOString().slice(0, 19).replace("T", " ");

    // 3. Ejecutar la consulta SQL con la fecha como parámetro
    const result = await db.run(
      `UPDATE License 
       SET estado = 'activa', fecha_expiracion = ?
       WHERE id_license = ?`,
      [newExpirationDate, id] // Pasamos la fecha calculada
    );

    if (result.changes === 0) {
      return res
        .status(404)
        .json({ success: false, error: "Licencia no encontrada" });
    }

    res.json({ success: true, message: "Licencia renovada por 1 año" });
  } catch (err) {
    console.error("Error PUT /license/:id/renew", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/**
 * Cambia 'tipo_licencia' y 'max_usuarios' basado en el body.
 */
app.put("/license/:id/modify-type", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tipo_licencia, max_usuarios } = req.body;

  if (!tipo_licencia) {
    return res
      .status(400)
      .json({ success: false, error: "Falta tipo_licencia en el body" });
  }

  let newMaxUsuarios;
  switch (tipo_licencia) {
    case "basica":
      newMaxUsuarios = 3;
      break;
    case "mediana":
      newMaxUsuarios = 5;
      break;
    case "pro":
      newMaxUsuarios = 7;
      break;
    case "personalizada":
      if (!max_usuarios || parseInt(max_usuarios, 10) <= 0) {
        return res.status(400).json({
          success: false,
          error:
            'Para tipo "personalizada", se requiere un max_usuarios válido',
        });
      }
      newMaxUsuarios = parseInt(max_usuarios, 10);
      break;
    default:
      return res
        .status(400)
        .json({ success: false, error: "Tipo de licencia no reconocido" });
  }

  try {
    await db.run(
      `UPDATE License 
       SET tipo_licencia = ?, max_usuarios = ?
       WHERE id_license = ?`,
      [tipo_licencia, newMaxUsuarios, id]
    );

    await db.run(
      `UPDATE SuperUser 
       SET cant_usuarios_permitidos = ? 
       WHERE superUser = (SELECT superUser FROM License WHERE id_license = ?)`,
      [newMaxUsuarios, id]
    );

    res.json({
      success: true,
      message: "Tipo de licencia actualizado y sincronizado",
    });
  } catch (err) {
    console.error("Error PUT /license/:id/modify-type", err);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

/// -----------------------------------------------------------------
/// ENDPOINT 1: RECIBIR Y GUARDAR (Llamado por la App Externa/Oculus)
/// -----------------------------------------------------------------
// Este endpoint escucha en POST, recibe el JSON completo de la sesión.
// Se asume que la app externa te envía el JSON en 'req.body'.
// (Opcional: protegerlo con una API Key simple usando 'requireApiKey')

app.post(
  "/session/save",
  /* requireApiKey, */ async (req, res) => {
    const { sesion, ejercicios } = req.body;

    // Validación básica del JSON recibido
    if (!sesion || !sesion.paciente || !sesion.profesional) {
      return res
        .status(400)
        .json({ success: false, error: "Datos de sesión incompletos." });
    }

    const { paciente, profesional, inicio, fin } = sesion;
    let superUser;
    try {
      const userRow = await db.get(
        `SELECT superUser FROM User WHERE user = ?`,
        [profesional]
      );
      if (!userRow) {
        return res
          .status(404)
          .json({ success: false, error: "Profesional no encontrado" });
      }
      superUser = userRow.superUser;
    } catch (e) {
      return res
        .status(500)
        .json({ success: false, error: "Error al buscar SuperUser" });
    }

    try {
      await db.run("BEGIN TRANSACTION");

      // 1. Insertar la Sesion
      const resultSesion = await db.run(
        `INSERT INTO Sesion (paciente, user, superUser, inicio, fin)
       VALUES (?, ?, ?, ?, ?)`,
        [paciente, profesional, superUser, inicio, fin]
      );

      // Obtenemos el ID de la sesión que acabamos de insertar
      const id_sesion = resultSesion.lastID;

      // 2. Iterar e insertar los Ejercicios
      if (ejercicios && ejercicios.length > 0) {
        for (const ejercicio of ejercicios) {
          const { escena, inicio, fin, metricas } = ejercicio;

          const resultEjercicio = await db.run(
            `INSERT INTO Ejercicio (escena, inicio, fin, id_sesion)
           VALUES (?, ?, ?, ?)`,
            [escena, inicio, fin, id_sesion]
          );

          const id_ejercicio = resultEjercicio.lastID;

          // 3. Iterar e insertar las Metricas
          if (metricas && metricas.length > 0) {
            for (const metrica of metricas) {
              const { nombre, data } = metrica;

              // Guardamos el array 'data' como un string JSON
              const dataString = JSON.stringify(data);

              await db.run(
                `INSERT INTO Metrica (nombre, data, id_ejercicio)
               VALUES (?, ?, ?)`,
                [nombre, dataString, id_ejercicio]
              );
            }
          }
        }
      }

      await db.run("COMMIT");
      res.status(201).json({
        success: true,
        message: "Sesión guardada localmente",
        sesionId: id_sesion,
      });
    } catch (err) {
      // Si algo falla, revertimos todo
      await db.run("ROLLBACK");
      console.error("Error en POST /session/save:", err.message);
      res
        .status(500)
        .json({ success: false, error: "Error al guardar la sesión en la BD" });
    }
  }
);

/// -----------------------------------------------------------------
/// ENDPOINT 2: LEER Y ENVIAR (Llamado por tu App de Flutter)
/// -----------------------------------------------------------------
// Este endpoint consulta la BD y rearma el JSON anidado
// que tu app de Flutter espera.
// (Opcional: protégelo con tu sistema de login JWT/requireAuth)

app.get(
  "/sessions/:profesional",
  /* requireAuth, */ async (req, res) => {
    const { profesional } = req.params;

    try {
      // 1. Obtenemos todas las sesiones de ese profesional
      const sesiones = await db.all(
        `SELECT * FROM Sesion WHERE user = ? ORDER BY inicio DESC`,
        [profesional]
      );

      if (sesiones.length === 0) {
        return res.json([]); // Devuelve lista vacía si no hay sesiones
      }

      // 2. Preparamos el array de respuesta final
      const sesionesData = [];

      // 3. Iteramos por cada sesión para buscar sus hijos (ejercicios y métricas)
      for (const sesion of sesiones) {
        // 4. Buscamos los ejercicios de esta sesión
        const ejercicios = await db.all(
          `SELECT * FROM Ejercicio WHERE id_sesion = ?`,
          [sesion.id_sesion]
        );

        const ejerciciosData = [];

        // 5. Iteramos por cada ejercicio para buscar sus métricas
        for (const ejercicio of ejercicios) {
          // 6. Buscamos las métricas de este ejercicio
          const metricas = await db.all(
            `SELECT id_metrica, nombre, data, id_ejercicio FROM Metrica WHERE id_ejercicio = ?`,
            [ejercicio.id_ejercicio]
          );

          const metricasData = metricas.map((m) => ({
            id: m.id_metrica,
            ejercicio: m.id_ejercicio,
            nombre: m.nombre,

            data: m.data,
          }));

          ejerciciosData.push({
            id: ejercicio.id_ejercicio,
            escena: ejercicio.escena,
            inicio: ejercicio.inicio,
            fin: ejercicio.fin,
            sesion: ejercicio.id_sesion,
            metricas: metricasData,
          });
        }

        // 7. Construimos el objeto SesionData (el formato que espera el frontend)
        sesionesData.push({
          sesion: {
            id: sesion.id_sesion,
            paciente: sesion.paciente,
            profesional: sesion.user, // Aseguramos que los nombres coincidan
            inicio: sesion.inicio,
            fin: sesion.fin,
          },
          ejercicios: ejerciciosData,
        });
      }

      // 8. Enviamos la lista de sesiones rearmada
      res.json(sesionesData);
    } catch (err) {
      console.error("Error en GET /sessions/:profesional:", err.message);
      res
        .status(500)
        .json({ success: false, error: "Error al consultar la base de datos" });
    }
  }
);

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
