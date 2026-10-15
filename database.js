const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, "data");
const DB_PATH = process.env.SQLITE_PATH ? path.resolve(process.env.SQLITE_PATH) : path.join(DATA_DIR, "loewi_race7.db");
let db;

async function initDatabase() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const SQL = await initSqlJs();
  db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  db.run("PRAGMA foreign_keys = ON");
  const schema = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  db.run(schema);
  saveDatabase();
  return db;
}

function saveDatabase() {
  if (!db) throw new Error("Database belum diinisialisasi");
  const bytes = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(bytes));
}

function getDb() {
  if (!db) throw new Error("Database belum diinisialisasi");
  return db;
}

function all(sql, params = []) {
  const stmt = getDb().prepare(sql);
  try {
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    return rows;
  } finally {
    stmt.free();
  }
}

function one(sql, params = []) {
  return all(sql, params)[0] || null;
}

function run(sql, params = []) {
  getDb().run(sql, params);
  const changes = getDb().getRowsModified();
  const idRow = one("SELECT last_insert_rowid() AS id");
  return { changes, lastInsertRowid: idRow ? idRow.id : null };
}

function transaction(callback) {
  getDb().run("BEGIN");
  try {
    const result = callback();
    getDb().run("COMMIT");
    saveDatabase();
    return result;
  } catch (error) {
    getDb().run("ROLLBACK");
    throw error;
  }
}

module.exports = { initDatabase, saveDatabase, getDb, all, one, run, transaction, DB_PATH };
