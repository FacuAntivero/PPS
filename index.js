const Joi = require("joi");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const db = require("./db"); // Importar la conexión SQLite

app.use(express.json());

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

const loginSchema = Joi.object({
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

app.post("/login", async (req, res) => {
  try {
    // Validar estructura de los datos
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message,
      });
    }

    const { usuario, password } = req.body;

    // 1. Primero intentar autenticar como SuperUser
    const superUserResult = await db.get(
      "SELECT password FROM SuperUser WHERE superUser = ?",
      [usuario]
    );

    if (superUserResult) {
      const match = await bcrypt.compare(password, superUserResult.password);
      if (match) {
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

        return res.status(200).json({
          success: true,
          message: "Soy un SuperUser",
          tipo_licencia: license ? license.tipo_licencia : null,
        });
      }
    }

    // 2. Si no es SuperUser, intentar como User normal
    const userResult = await db.get(
      `SELECT password 
       FROM User 
       WHERE user = ?`,
      [usuario]
    );

    if (userResult) {
      const match = await bcrypt.compare(password, userResult.password);
      if (match) {
        return res.status(200).json({
          success: true,
          message: "Soy un User",
        });
      }
    }

    // 3. Si ninguna credencial es válida
    return res.status(401).json({
      success: false,
      error: "Credenciales inválidas",
    });
  } catch (error) {
    console.error("Error en login:", error);
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
    const { paciente, user, superUser, estadoInicial } = req.body;

    // Verificar existencia del usuario
    const usuario = await db.get(
      "SELECT user FROM User WHERE user = ? AND superUser = ?",
      [user, superUser]
    );

    if (!usuario) {
      return res.status(404).json({
        success: false,
        error: "Usuario no encontrado",
      });
    }

    // Insertar nueva sesión
    const result = await db.run(
      `INSERT INTO Sesion
   (nombre, superUser, inicio, estadoInicial)
   VALUES (?, ?, datetime('now'), ?)`,
      [paciente, superUser, estadoInicial]
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
      error: "Error al iniciar sesión",
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
