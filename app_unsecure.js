
// Version intentionnellement vulnérable de l'application

const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors()); 

const secretKey = "supersecretkey"; 

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "users_db"
});

db.connect(err => {
    if (err) throw err;
    console.log("Connecté à MySQL");
});

app.get("/user", (req, res) => {
    db.query("SELECT * FROM users WHERE email = '" + req.query.email + "'", (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});


app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email et mot de passe requis" });
    }
    db.query("SELECT * FROM users WHERE email = '" + email + "'", (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ error: "Utilisateur non trouvé" });
        }
        const user = results[0];
        if (password !== user.password) { 
            return res.status(401).json({ error: "Mot de passe incorrect" });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, secretKey); 
        res.json({ token });
    });
});

app.listen(3000, () => console.log("Serveur vulnérable démarré sur le port 3000"));
