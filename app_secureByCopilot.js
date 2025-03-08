// Version intentionnellement vulnérable de l'application
// update

const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss-clean");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use(helmet());
app.use(xss());

const secretKey = "supersecretkey";
const tokenExpiry = "1h"; // Ajouter une expiration pour les tokens JWT

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "users_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connecté à MySQL");
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.get("/user", (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email requis" });
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    if (err)
      return res.status(500).json({ error: "Erreur de base de données" });
    res.json(result);
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ error: "Mot de passe incorrect" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, secretKey, {
        expiresIn: tokenExpiry,
      });
      res.json({ token });
    });
  });
});

app.listen(3000, () =>
  console.log("Serveur sécurisé démarré sur le port 3000")
);
