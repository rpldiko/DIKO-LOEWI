require("dotenv").config();
const bcrypt = require("bcryptjs");
const { initDatabase, one, run, transaction, saveDatabase } = require("./database");

const participants = [
  [1, "Ken", "HC3B", 19],
  [2, "Gatot", "HC3B", 17],
  [3, "Jason", "HC3SB", 15],
  [4, "Mesach", "HC3SB", 6],
  [5, "Ojan", "HC3B", 6],
  [6, "Pamungkas", "HC3B", 3],
  [7, "Nico", "HC3B", 2],
  [8, "Dion", "HC3B", 1],
  [9, "Aldo", "HC3B", -1],
  [10, "Dimas", "HC3B", -1],
  [11, "Jere", "HC3SB", -4],
  [12, "Diko", "HC3SB", -16]
];

(async () => {
  await initDatabase();
  const username = (process.env.ADMIN_USERNAME || "admin").trim();
  const password = process.env.ADMIN_PASSWORD || "ChangeMe-Immediately-123!";

  if (!one("SELECT id FROM admins WHERE username = ?", [username])) {
    const hash = await bcrypt.hash(password, 12);
    run("INSERT INTO admins (username, password_hash) VALUES (?, ?)", [username, hash]);
    console.log(`Admin awal dibuat: ${username}`);
    if (!process.env.ADMIN_PASSWORD) console.warn("PERINGATAN: ganti password admin awal melalui file .env sebelum dipublikasikan.");
  } else {
    console.log("Admin sudah ada, tidak diubah.");
  }

  if (!one("SELECT id FROM participants LIMIT 1")) {
    transaction(() => {
      for (const [number, name, level, points] of participants) {
        run(
          "INSERT INTO participants (participant_number, name, level, points) VALUES (?, ?, ?, ?)",
          [number, name, level, points]
        );
      }
    });
    console.log("12 peserta contoh berhasil ditambahkan.");
  } else {
    console.log("Data peserta sudah ada, seed tidak dijalankan ulang.");
  }
  saveDatabase();
  process.exit(0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
