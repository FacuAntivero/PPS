const Joi = require("joi");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
app.use(express.json());

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

// Esquemas de validación Joi
const licenseSchema = Joi.object({
  name: Joi.string().min(3).required(),
  type: Joi.string().valid("basic", "premium", "enterprise").required(),
  expirationDate: Joi.date().iso().greater("now").required(),
  status: Joi.string().valid("active", "inactive").default("active"),
});

const updateLicenseSchema = Joi.object({
  name: Joi.string().min(3),
  type: Joi.string().valid("basic", "premium", "enterprise"),
  expirationDate: Joi.date().iso().greater("now"),
  status: Joi.string().valid("active", "inactive"),
}).min(1); // Al menos un campo debe ser enviado

// EndPoint Login
const loginSchema = Joi.object({
  nombre: Joi.string().required(),
  password: Joi.string().required(),
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
