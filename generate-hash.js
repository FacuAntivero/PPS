// generate-hash.js
const bcrypt = require("bcrypt");

async function generateHash() {
  try {
    const plainPassword = process.argv[2];
    const saltRounds = 10;

    const hash = await bcrypt.hash(plainPassword, saltRounds);
    console.log("------------------------------------------");
    console.log("CONTRASEÑA ORIGINAL:", plainPassword);
    console.log("HASH GENERADO:", hash);
    console.log("------------------------------------------");
  } catch (error) {
    console.error("Error generando hash:", error);
  }
}

generateHash();
