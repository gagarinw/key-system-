const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const DB_FILE = "keys.json";

// загрузка базы
let db = { keys: [] };

if (fs.existsSync(DB_FILE)) {
    db = JSON.parse(fs.readFileSync(DB_FILE));
}

function saveDB() {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function generateKey(prefix) {
    return prefix + Math.random().toString(36).substring(2, 10).toUpperCase();
}

// обычный ключ
app.post("/api/generate", (req, res) => {
    const key = generateKey("beta_");
    const expires = Date.now() + 86400000;

    db.keys.push({ key, type: "normal", expires });
    saveDB();

    res.json({ key });
});

// админ ключ
const ADMIN_PASSWORD_HASH = "$2b$10$examplehash";

app.post("/api/generate-admin", async (req, res) => {
    const { password } = req.body;

    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!ok) return res.status(403).send("wrong password");

    const key = generateKey("admin_");

    db.keys.push({ key, type: "admin", expires: null });
    saveDB();

    res.json({ key });
});

// проверка
app.get("/api/check", (req, res) => {
    const key = req.query.key;

    const found = db.keys.find(k => k.key === key);

    if (!found) return res.json({ status: "invalid" });

    if (found.type === "normal" && Date.now() > found.expires) {
        return res.json({ status: "expired" });
    }

    res.json({
        status: "valid",
        type: found.type
    });
});

app.listen(process.env.PORT || 3000, () => {
    console.log("Server started");
});
