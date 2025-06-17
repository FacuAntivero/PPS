// generate-hash.js
const bcrypt = require("bcrypt");

async function generateHash() {
  try {
    const plainPassword = "user123"; // Tu contraseña en texto plano
    const saltRounds = 10; // Mismo valor que usas en index.js

    const hash = await bcrypt.hash(plainPassword, saltRounds);
    console.log("------------------------------------------");
    console.log("CONTRASEÑA ORIGINAL:", plainPassword);
    console.log("HASH GENERADO:", hash);
    console.log("------------------------------------------");

    // Copia este hash y úsalo en el INSERT de SQLite
  } catch (error) {
    console.error("Error generando hash:", error);
  }
}

generateHash();
