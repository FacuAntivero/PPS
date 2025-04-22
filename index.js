const Joi = require("joi");
const express = require("express");
const app = express();
app.use(express.json());

// Datos en memoria
const licenses = [
  {
    id: 1,
    name: "Basic",
    type: "basic",
    expirationDate: "2024-12-31",
    status: "active",
  },
  {
    id: 2,
    name: "Premium",
    type: "premium",
    expirationDate: "2025-06-30",
    status: "active",
  },
  {
    id: 3,
    name: "Admin",
    type: "admin",
    expirationDate: "2024-01-01",
    status: "inactive",
  },
];
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

// Middleware de validación genérico
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  next();
};

// Middleware de permisos
const checkLicensePermission = (allowedTypes) => (req, res, next) => {
  const licenseType = req.headers["x-license-type"];
  if (!allowedTypes.includes(licenseType)) {
    return res.status(403).json({
      error: `Acceso denegado. Licencia requerida: ${allowedTypes.join(" o ")}`,
    });
  }
  next();
};

// Endpoints
app.get(
  "/licenses",
  checkLicensePermission(["basic", "premium", "admin"]),
  (req, res) => {
    res.json(licenses);
  }
);

// GET: Obtener licencia por ID
app.get(
  "/licenses/:id",
  checkLicensePermission(["basic", "premium", "admin"]),
  (req, res) => {
    const license = licenses.find((l) => l.id === parseInt(req.params.id));
    if (!license)
      return res.status(404).json({ error: "Licencia no encontrada" });
    res.json(license);
  }
);

app.post(
  "/licenses",
  checkLicensePermission(["admin", "premium"]),
  validate(licenseSchema),
  (req, res) => {
    const newLicense = { id: licenses.length + 1, ...req.body };
    licenses.push(newLicense);
    res.status(201).json(newLicense);
  }
);

app.put(
  "/licenses/:id",
  checkLicensePermission(["admin"]),
  validate(updateLicenseSchema),
  (req, res) => {
    const license = licenses.find((l) => l.id === parseInt(req.params.id));
    if (!license)
      return res.status(404).json({ error: "Licencia no encontrada" });

    Object.assign(license, req.body);
    res.json(license);
  }
);

app.delete("/licenses/:id", checkLicensePermission(["admin"]), (req, res) => {
  const index = licenses.findIndex((l) => l.id === parseInt(req.params.id));
  if (index === -1)
    return res.status(404).json({ error: "Licencia no encontrada" });

  const deletedLicense = licenses.splice(index, 1);
  res.json(deletedLicense[0]);
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Error interno del servidor" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

/*
const courses = [
  { id: 1, name: "course1" },
  { id: 2, name: "course2" },
  { id: 3, name: "course3" },
];

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.get("/api/courses", (req, res) => {
  res.send(courses);
});

app.get("/api/courses/:id", (req, res) => {
  const course = courses.find((c) => c.id === parseInt(req.params.id));
  if (!course)
    return res.status(404).send("The course with the given ID was not found");
  res.send(course);
});

app.post("/api/courses", (req, res) => {
  const { error } = validateCourse(req.body);
  if (error) {
    return res.status(400).send(result.error.details[0].message);
  }
  const course = {
    id: courses.length + 1,
    name: req.body.name,
  };
  courses.push(course);
  res.send(course);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

app.put("/api/courses/:id", (req, res) => {
  const course = courses.find((c) => c.id === parseInt(req.params.id));
  if (!course) {
    res.status(404).send("The course with the given ID was not found");
    return;
  }

  const { error } = validateCourse(req.body);
  if (error) {
    return res.status(400).send(result.error.details[0].message);
  }

  course.name = req.body.name;
  res.send(course);
});

function validateCourse(course) {
  const schema = {
    name: Joi.string().min(3).required(),
  };
  return Joi.validate(course, schema);
}

app.delete("/api/courses/:id", (req, res) => {
  // Look up the course
  // Not existing, return 404
  // Delete
  // Return the same course
  const course = courses.find((c) => c.id === parseInt(req.params.id));
  if (!course)
    return res.status(404).send("The course with the given ID was not found");

  const index = courses.indexOf(course);
  courses.splice(index, 1);
  res.send(course);
});

*/
