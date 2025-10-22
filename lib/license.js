// lib/license.js
const crypto = require("crypto");

const SECRET = process.env.LICENSE_SECRET || "dev_secret_change_me";
// Presets por tipo de licencia
const PRESETS = {
  basica: 3,
  mediana: 7,
  pro: 10,
};

function hashLicenseKey(key) {
  // HMAC-SHA256 con SECRET
  return crypto.createHmac("sha256", SECRET).update(key).digest("hex");
}

function generateKeyPlaintext() {
  // Genera clave legible y formateada, ejemplo: "A1B2-C3D4-E5F6"
  const raw = crypto.randomBytes(9).toString("hex").toUpperCase(); // 18 hex chars
  return raw.match(/.{1,4}/g).join("-");
}

module.exports = {
  PRESETS,
  hashLicenseKey,
  generateKeyPlaintext,
};
