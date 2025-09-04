const Joi = require("joi");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const db = require("./db"); // Importar la conexión SQLite

app.use(express.json());

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

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

// Registrar nueva residencia (SuperUser)
app.post("/superuser", async (req, res) => {
  const schema = Joi.object({
    superUser: Joi.string().min(3).required(),
    password: Joi.string().min(6).required(),
    cant_usuarios_permitidos: Joi.number().integer().min(1).required(),
  });

  // Validación de datos
  const { error, value } = schema.validate(req.body);
  if (error)
    return res.status(400).json({
      success: false,
      error: error.details[0].message,
    });

  try {
    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(value.password, 10);

    // Insertar en base de datos
    await db.run(
      `INSERT INTO SuperUser (superUser, password, cant_usuarios_permitidos) 
             VALUES (?, ?, ?)`,
      [value.superUser, hashedPassword, value.cant_usuarios_permitidos]
    );

    res.status(201).json({ success: true });
  } catch (err) {
    if (err.message.includes("UNIQUE constraint")) {
      res.status(409).json({
        success: false,
        error: "El nombre de residencia ya existe",
      });
    } else {
      console.error("Error en registro de residencia:", err);
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }
});

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

    // Comparar contraseña
    const match = await bcrypt.compare(password, superUser.password);
    if (!match) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    // Obtener tipo de licencia
    const license = await db.get(
      `SELECT tipo_licencia 
       FROM License 
       WHERE superUser = ? 
         AND estado = 'activa'
       ORDER BY fecha_alta DESC 
       LIMIT 1`,
      [usuario]
    );

    res.status(200).json({
      success: true,
      tipo_licencia: license ? license.tipo_licencia : null,
    });
  } catch (error) {
    console.error("Error en login-superuser:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

// Esquema para login de User (profesional)
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

// Endpoint para login de User (profesional)
app.post("/login-user", async (req, res) => {
  try {
    // Validar estructura de los datos
    const { error } = userLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { usuario, password } = req.body;

    // Buscar usuario profesional
    const user = await db.get(
      "SELECT password, superUser FROM User WHERE user = ?",
      [usuario]
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    // Comparar contraseña
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({
        success: false,
        error: "Credenciales inválidas",
      });
    }

    res.status(200).json({
      success: true,
      superUser: user.superUser, // Residencia a la que pertenece
    });
  } catch (error) {
    console.error("Error en login-user:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

// Esquema de validación para Hash
const hashSchema = Joi.object({
  superUser: Joi.string().min(3).required().messages({
    "string.empty": "superUser no puede estar vacío",
    "string.min": "superUser debe tener al menos 3 caracteres",
    "any.required": "superUser es obligatorio",
  }),
  hash: Joi.string().min(8).required().messages({
    "string.empty": "Hash no puede estar vacío",
    "string.min": "Hash debe tener al menos 8 caracteres",
    "any.required": "Hash es obligatorio",
  }),
});

// Endpoint para agregar/verificar hashes
app.post("/hash", async (req, res) => {
  try {
    // Validar datos con Joi
    const { error, value } = hashSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { superUser, nombre, cant_usuarios_permitidos, hash } = value;

    // Verificar si el superusuario existe
    const superUsuario = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );

    if (!superUsuario) {
      return res.status(404).json({
        success: false,
        error: "El superusuario no existe",
      });
    }

    // Verificar si el hash ya existe para este superusuario
    const hashExistente = await db.get(
      "SELECT hash FROM Hash WHERE superUser = ? AND hash = ?",
      [superUser, hash]
    );

    if (hashExistente) {
      return res.json(false); // Hash ya existe
    }

    // Insertar nuevo hash
    await db.run("INSERT INTO Hash (superUser, hash) VALUES (?, ?)", [
      superUser,
      hash,
    ]);

    res.json(true); // Hash agregado exitosamente
  } catch (error) {
    console.error("Error en POST /hash:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});
//Esquema para cambiar la contraseña de un user siendo superUser
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
    // Validar datos de entrada
    const { error } = changePasswordSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { superUser, superUserPassword, targetUser, newPassword } = req.body;

    // 1. Verificar que el SuperUser es válido
    const superUserRecord = await db.get(
      "SELECT password FROM SuperUser WHERE superUser = ?",
      [superUser]
    );

    if (!superUserRecord) {
      return res.status(404).json({
        success: false,
        error: "Superusuario no encontrado",
      });
    }

    // 2. Validar contraseña del SuperUser
    const superUserMatch = await bcrypt.compare(
      superUserPassword,
      superUserRecord.password
    );

    if (!superUserMatch) {
      return res.status(401).json({
        success: false,
        error: "Credenciales de superusuario inválidas",
      });
    }

    // 3. Verificar que el usuario objetivo existe y pertenece al SuperUser
    const userRecord = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [targetUser, superUser]
    );

    if (!userRecord) {
      return res.status(404).json({
        success: false,
        error: "Usuario no encontrado o no pertenece a este superusuario",
      });
    }

    // 4. Generar nuevo hash y actualizar contraseña
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    await db.run(
      "UPDATE User SET password = ? WHERE user = ? AND superUser = ?",
      [newPasswordHash, targetUser, superUser]
    );

    res.status(200).json({
      success: true,
      message: "Contraseña actualizada exitosamente",
    });
  } catch (error) {
    console.error("Error al cambiar contraseña:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});
// Esquema de validación para listar usuarios
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
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { superUser } = req.query;

    // Verificar que el superUser exista
    const superUserExists = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );

    if (!superUserExists) {
      return res.status(404).json({
        success: false,
        error: "El superusuario no existe",
      });
    }

    // Obtener usuarios
    const users = await db.all("SELECT user FROM User WHERE superUser = ?", [
      superUser,
    ]);

    // Extraer solo los nombres de usuario
    const userList = users.map((u) => u.user);

    res.status(200).json({
      success: true,
      usuarios: userList,
    });
  } catch (error) {
    console.error("Error en GET /usuarios:", error);
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

// Esquema de validación para agregar un nuevo Usuario
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
    // Validar datos con Joi
    const { error, value } = usuarioSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { user, superUser, nombreReal, password } = value;

    // Verificar si el superusuario existe
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

    // Verificar límite de usuarios permitidos
    const superUserConfig = await db.get(
      // Usar .get ya que esperas una sola fila
      "SELECT cant_usuarios_permitidos FROM SuperUser WHERE superUser = ?",
      [superUser]
    );

    if (superUserConfig) {
      // Verifica si se encontró la configuración del superusuario
      const [currentUsers] = await db.all(
        "SELECT COUNT(*) AS count FROM User WHERE superUser = ?",
        [superUser]
      );

      if (currentUsers.count >= superUserConfig.cant_usuarios_permitidos) {
        return res.status(403).json({
          success: false,
          error: "Límite de usuarios alcanzado para este superusuario",
        });
      }
    } else {
      // Manejar caso donde no se encuentra el superusuario, aunque ya se verifica antes
      return res.status(404).json({
        success: false,
        error:
          "El superusuario no existe o no tiene configuración de usuarios permitidos.",
      });
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar nuevo usuario
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

// Endpoint para crear sesiones
app.post("/sesiones", async (req, res) => {
  try {
    // Cambiamos "nombre" por "paciente" en el request
    const { paciente, user, superUser, estadoInicial } = req.body;

    // Verificar existencia del usuario profesional
    const usuario = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [user, superUser]
    );

    if (!usuario) {
      return res.status(404).json({
        success: false,
        error: "Usuario profesional no encontrado",
      });
    }

    // Insertar nueva sesión con campo "paciente"
    const result = await db.run(
      `INSERT INTO Sesion 
       (paciente, user, superUser, inicio, estadoInicial) 
       VALUES (?, ?, ?, datetime('now'), ?)`,
      [paciente, user, superUser, estadoInicial]
    );

    res.status(201).json({
      success: true,
      id_sesion: result.lastID,
      message: "Sesión iniciada",
    });
  } catch (error) {
    console.error("Error en POST /sesiones:", error);
    res.status(500).json({
      success: false,
      error: "Error al iniciar sesión terapéutica",
    });
  }
});

// Endpoint para finalizar sesiones
app.put("/sesiones/:id/finalizar", async (req, res) => {
  try {
    const { id } = req.params;
    const { estadoFinal } = req.body;

    await db.run(
      `UPDATE Sesion 
       SET fin = datetime('now'), estadoFinal = ? 
       WHERE id_sesion = ?`,
      [estadoFinal, id]
    );

    res.json({
      success: true,
      message: "Sesión finalizada",
    });
  } catch (error) {
    console.error("Error al finalizar sesión:", error);
    res.status(500).json({
      success: false,
      error: "Error al finalizar sesión",
    });
  }
});

// Endpoint para registrar ejercicios
app.post("/ejercicios", async (req, res) => {
  try {
    const { id_sesion, escena } = req.body;

    // Insertar nuevo ejercicio
    const result = await db.run(
      `INSERT INTO Ejercicio 
      (id_sesion, escena, inicio) 
      VALUES (?, ?, datetime('now'))`,
      [id_sesion, escena]
    );

    res.status(201).json({
      success: true,
      id_ejercicio: result.lastID,
      message: "Ejercicio iniciado",
    });
  } catch (error) {
    console.error("Error en POST /ejercicios:", error);
    res.status(500).json({
      success: false,
      error: "Error al iniciar ejercicio",
    });
  }
});

// Endpoint para finalizar ejercicios
app.put("/ejercicios/:id/finalizar", async (req, res) => {
  try {
    const { id } = req.params;

    await db.run(
      `UPDATE Ejercicio 
       SET fin = datetime('now') 
       WHERE id_ejercicio = ?`,
      [id]
    );

    res.json({
      success: true,
      message: "Ejercicio finalizado",
    });
  } catch (error) {
    console.error("Error al finalizar ejercicio:", error);
    res.status(500).json({
      success: false,
      error: "Error al finalizar ejercicio",
    });
  }
});

// Endpoint para registrar métricas
app.post("/metricas", async (req, res) => {
  try {
    const { id_ejercicio, nombre, data } = req.body;

    // Insertar nueva métrica
    await db.run(
      `INSERT INTO Metrica 
      (id_ejercicio, nombre, data) 
      VALUES (?, ?, ?)`,
      [id_ejercicio, nombre, JSON.stringify(data)] // Convertir datos a JSON
    );

    res.status(201).json({
      success: true,
      message: "Métrica registrada",
    });
  } catch (error) {
    console.error("Error en POST /metricas:", error);
    res.status(500).json({
      success: false,
      error: "Error al registrar métrica",
    });
  }
});

// Esquema para devolver las metricas de un paciente
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
    // Validar parámetros de query
    const { error, value } = metricasPacienteSchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { paciente, user, superUser } = value;

    // 1. Verificar que exista la combinación paciente-user-superUser en Sesion
    const sesiones = await db.all(
      `SELECT id_sesion 
       FROM Sesion 
       WHERE paciente = ? 
         AND user = ? 
         AND superUser = ?`,
      [paciente, user, superUser]
    );

    if (sesiones.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No se encontraron sesiones para este paciente y profesional",
      });
    }

    // 2. Obtener todas las métricas relacionadas
    const metricas = await db.all(
      `SELECT 
        M.id_metrica,
        M.nombre AS nombre_metrica,
        M.data,
        E.escena,
        E.inicio AS inicio_ejercicio,
        E.fin AS fin_ejercicio,
        S.inicio AS inicio_sesion,
        S.fin AS fin_sesion,
        S.estadoInicial,
        S.estadoFinal
      FROM Metrica M
      JOIN Ejercicio E ON M.id_ejercicio = E.id_ejercicio
      JOIN Sesion S ON E.id_sesion = S.id_sesion
      WHERE S.paciente = ? 
        AND S.user = ? 
        AND S.superUser = ?`,
      [paciente, user, superUser]
    );

    if (metricas.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No se encontraron métricas para este paciente",
      });
    }

    // 3. Formatear respuesta
    const resultado = metricas.map((metrica) => ({
      id_metrica: metrica.id_metrica,
      nombre: metrica.nombre_metrica,
      data: JSON.parse(metrica.data), // Convertir de string JSON a objeto
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
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});

// Esquema de validación para devolver los user de un SuperUser
const superUserParamSchema = Joi.string().min(3).required().messages({
  "string.empty": "superUser no puede estar vacío",
  "string.min": "superUser debe tener al menos 3 caracteres",
  "any.required": "superUser es obligatorio",
});

// Endpoint para obtener todos los usuarios asociados a un SuperUser
app.get("/superuser/:superUser/usuarios", async (req, res) => {
  try {
    const { superUser } = req.params;

    // Validar parámetro de ruta
    const { error } = superUserParamSchema.validate(superUser);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    // Verificar si el superusuario existe
    const superUserExists = await db.get(
      "SELECT superUser FROM SuperUser WHERE superUser = ?",
      [superUser]
    );

    if (!superUserExists) {
      return res.status(404).json({
        success: false,
        error: "El superusuario no existe",
      });
    }

    // Obtener todos los usuarios asociados al superusuario
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
    res.status(500).json({
      success: false,
      error: "Error interno del servidor",
    });
  }
});
