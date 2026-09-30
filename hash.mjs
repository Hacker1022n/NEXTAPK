import { scryptSync, randomBytes } from "node:crypto";
const pw = process.argv[2]; if (!pw || pw.length < 12) { console.error("Usage: npm run hash -- '<password of 12+ chars>'"); process.exit(1); }
const salt = randomBytes(16).toString("hex");
console.log(`ADMIN_PASSWORD_HASH=${salt}:${scryptSync(pw, salt, 64).toString("hex")}\nSESSION_SECRET=${randomBytes(32).toString("hex")}`);
