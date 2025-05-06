const Joi = require("joi");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
app.use(express.json());

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

// EndPoint Login
const loginSchema = Joi.object({
  nombre: Joi.string().required(),
  password: Joi.string().required(),
});

// Esquema de validación Joi para creación de usuarios
const usuarioSchema = Joi.object({
  nombre: Joi.string().min(3).required(),
  rol: Joi.string()
    .valid("terapeuta", "supervisor", "administrador")
    .required(),
  password: Joi.string().min(6).required(),
});

app.post("/login", async (req, res) => {
  // Validar entrada con Joi
  const { error } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { nombre, password } = req.body;

  try {
    // 1. Buscar usuario por nombre
    const [usuarios] = await db.query(
      "SELECT * FROM Usuario WHERE nombre = ?",
      [nombre]
    );
    if (!usuarios.length)
      return res.status(401).json({ error: "Credenciales inválidas" });

    const usuario = usuarios[0];

    // 2. Verificar contraseña
    const passwordValida = await bcrypt.compare(
      password,
      usuario.contrasena_hash
    );
    if (!passwordValida)
      return res.status(401).json({ error: "Credenciales inválidas" });

    // 3. Obtener SuperUsuario asociado al profesional
    const [superUsuario] = await db.query(
      `SELECT sp.ID_SuperUsuario 
       FROM SuperUsuario_Usuario sp
       WHERE sp.ID_Usuario = ?`,
      [usuario.ID_profesional]
    );
    if (!superUsuario.length)
      return res
        .status(403)
        .json({ error: "No estás asociado a ninguna institución" });

    const ID_SuperUsuario = superUsuario[0].ID_SuperUsuario;

    // 4. Obtener licencia activa de la institución
    const [licencias] = await db.query(
      `SELECT tipo_licencia 
       FROM Licencia 
       WHERE ID_SuperUsuario = ? 
         AND estado = 'active' 
         AND fecha_baja >= CURDATE()`,
      [ID_SuperUsuario]
    );
    if (!licencias.length)
      return res
        .status(403)
        .json({ error: "La institución no tiene licencia activa" });

    // 5. Devolver el tipo de licencia
    res.json({ tipoLicencia: licencias[0].tipo_licencia });
  } catch (err) {
    console.error("Error en /login:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Middleware de autenticación JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Acceso no autorizado" });
  }

  jwt.verify(token, "tu_clave_secreta", (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado" });
    }

    // Verificar que el usuario tenga licencia admin
    if (decoded.licenseType !== "admin") {
      return res
        .status(403)
        .json({ error: "No tienes permisos para esta acción" });
    }

    req.superUsuarioId = decoded.superUsuarioId;
    next();
  });
};

// Endpoint para crear usuarios
app.post(
  "/usuarios",
  authenticateJWT, // Verifica JWT
  validate(usuarioSchema), // Valida datos con Joi
  async (req, res) => {
    const { nombre, rol, password } = req.body;
    const { superUsuarioId } = req;

    try {
      // 1. Verificar existencia del SuperUsuario
      const [superUsuario] = await db.query(
        "SELECT * FROM SuperUsuario WHERE ID_SuperUsuario = ?",
        [superUsuarioId]
      );

      if (!superUsuario.length) {
        return res.status(404).json({ error: "Institución no encontrada" });
      }

      // 2. Hashear contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // 3. Crear usuario en transacción
      const connection = await db.getConnection();
      await connection.beginTransaction();

      try {
        // Insertar usuario
        const [usuarioResult] = await connection.query(
          `INSERT INTO Usuario 
           (nombre, rol, contrasena_hash) 
           VALUES (?, ?, ?)`,
          [nombre, rol, hashedPassword]
        );

        // Vincular con SuperUsuario
        await connection.query(
          `INSERT INTO SuperUsuario_Profesional 
           (ID_SuperUsuario, ID_Usuario) 
           VALUES (?, ?)`,
          [superUsuarioId, usuarioResult.insertId]
        );

        await connection.commit();

        res.status(201).json({
          id: usuarioResult.insertId,
          nombre,
          rol,
          institucion: superUsuario[0].nombre,
        });
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error("Error en creación de usuario:", error);

      // Manejar errores de duplicados
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ error: "El usuario ya existe" });
      }

      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);
