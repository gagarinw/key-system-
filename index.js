const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const db = new sqlite3.Database("keys.db");

// таблица
db.run(`
CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY,
    type TEXT,
    expires INTEGER
)
`);

// 🔐 хэш пароля (потом заменишь)
const ADMIN_PASSWORD_HASH = "$2b$10$N80XQ7.VN0/nk2Zqe37sy.D2MPaE1mYNmPZb8txXCQRZOjZhASxYy";

// генерация ключа
function generateKey(prefix) {
    return prefix + Math.random().toString(36).substring(2, 10).toUpperCase();
}

//
// 🟦 Обычный ключ (beta_ + 1 день)
//
app.post("/api/generate", (req, res) => {
    const key = generateKey("beta_");
    const expires = Date.now() + 86400000; // 1 день

    db.run("INSERT INTO keys VALUES (?, ?, ?)", [key, "normal", expires]);

    res.json({ key });
});

//
// 🟥 Админ ключ (admin_ + навсегда)
//
app.post("/api/generate-admin", async (req, res) => {
    const { password } = req.body;

    const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!valid) return res.status(403).send("wrong password");

    const key = generateKey("admin_");

    db.run("INSERT INTO keys VALUES (?, ?, ?)", [key, "admin", null]);

    res.json({ key });
});

//
// ✅ Проверка ключа
//
app.get("/api/check", (req, res) => {
    const key = req.query.key;

    db.get("SELECT * FROM keys WHERE key = ?", [key], (err, row) => {
        if (!row) return res.json({ status: "invalid" });

        if (row.type === "normal" && Date.now() > row.expires) {
            return res.json({ status: "expired" });
        }

        res.json({
            status: "valid",
            type: row.type
        });
    });
});

app.listen(process.env.PORT || 3000, () => {
    console.log("Server started");
});