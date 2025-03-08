// Fichier: app.js
// Application Node.js Express avec des vulnérabilités OWASP intégrées
// Correction

require("dotenv").config(); // Chargement des variables d'environnement
const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const winston = require("winston");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(helmet()); // Sécurisation des headers

// Configuration des CORS avec restriction d'origine
const corsOptions = {
  origin: "https://trusteddomain.com",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

// Configuration de Winston pour la journalisation
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
  ],
});

const secretKey =
  process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    logger.error("Erreur de connexion à la base de données", err);
    throw err;
  }
  console.log("Connecté à MySQL");
});

// Protection contre le brute-force
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limite chaque IP à 100 requêtes
  message: "Trop de requêtes. Réessayez plus tard.",
});
app.use(limiter);

// Endpoint sécurisé avec requêtes préparées
app.get("/user", (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email requis" });
  }
  db.execute("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    if (err) {
      logger.error("Erreur SQL", err);
      return res.status(500).json({ error: "Erreur interne" });
    }
    res.json(result);
  });
});

// Endpoint de création de JWT sécurisé
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  db.execute(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err || results.length === 0) {
        logger.warn("Tentative de connexion avec email inconnu");
        return res.status(401).json({ error: "Utilisateur non trouvé" });
      }
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        logger.warn("Échec d'authentification pour l'utilisateur", email);
        return res.status(401).json({ error: "Mot de passe incorrect" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, secretKey, {
        expiresIn: "1h",
      });
      res.cookie("token", token, { httpOnly: true, secure: true });
      res.json({ message: "Connexion réussie" });
    }
  );
});

app.listen(3000, () => console.log("Serveur démarré sur le port 3000"));
