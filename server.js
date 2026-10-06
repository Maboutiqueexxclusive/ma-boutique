require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./db');

const app = express();

app.use(cors());
app.use(express.json());

// Configuration du transporteur d'email
const transporter = nodemailer.createTransport({
  service: 'gmail', // Changez si vous utilisez OVH, Outlook, Mailtrap, etc.
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// 1. Route d'inscription (Génère le code et envoie le mail)
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Générer un code à 6 chiffres
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Le code expire après 15 minutes
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // Insertion en BDD (compte non vérifié par défaut)
    const [result] = await db.query(
      'INSERT INTO users (email, password_hash, verification_code, code_expires_at, is_verified) VALUES (?, ?, ?, ?, 0)',
      [email, hashedPassword, verificationCode, expiresAt]
    );

    // Envoi de l'email avec le code de confirmation
    const mailOptions = {
      from: `"Ma Boutique" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Code de confirmation d\'inscription',
      html: `
        <h2>Bienvenue !</h2>
        <p>Merci de vous être inscrit. Voici votre code de confirmation :</p>
        <h1 style="color: #007bff; letter-spacing: 4px;">${verificationCode}</h1>
        <p>Ce code expire dans 15 minutes.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      success: true, 
      message: 'Inscription réussie. Un code de confirmation vous a été envoyé par email.',
      userId: result.insertId 
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Email déjà utilisé ou erreur lors de l\'inscription.' });
  }
});

// 2. Route de vérification du code de confirmation
app.post('/api/verify-code', async (req, res) => {
  const { email, code } = req.body;

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé.' });

    const user = users[0];

    if (user.is_verified) {
      return res.status(400).json({ error: 'Ce compte est déjà vérifié.' });
    }

    // Vérifier si le code est correct et non expiré
    const now = new Date();
    if (user.verification_code !== code) {
      return res.status(400).json({ error: 'Code de confirmation incorrect.' });
    }

    if (new Date(user.code_expires_at) < now) {
      return res.status(400).json({ error: 'Le code a expiré. Veuillez en demander un nouveau.' });
    }

    // Valider le compte et effacer le code de la BDD
    await db.query(
      'UPDATE users SET is_verified = 1, verification_code = NULL, code_expires_at = NULL WHERE email = ?',
      [email]
    );

    res.json({ success: true, message: 'Compte vérifié avec succès ! Vous pouvez maintenant vous connecter.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Route de connexion (Vérifie si le compte est validé)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Utilisateur non trouvé.' });

    const user = users[0];

    // Bloquer la connexion si le compte n'a pas été validé par email
    if (!user.is_verified) {
      return res.status(403).json({ error: 'Veuillez confirmer votre compte via le code reçu par email avant de vous connecter.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Mot de passe incorrect.' });

    // Générer un jeton (token) de connexion
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'cle_secrete_defaut', { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Route d'accès au roman (Protégée)
app.get('/api/roman', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Non autorisé.' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cle_secrete_defaut');
    
    // Vérifier en BDD si l'utilisateur a payé
    const [purchases] = await db.query(
      'SELECT * FROM purchases WHERE user_id = ? AND status = "completed"',
      [decoded.userId]
    );

    if (purchases.length === 0) {
      return res.status(403).json({ error: 'Accès refusé. Veuillez acheter le roman pour le lire.' });
    }

    // Si tout est bon, on renvoie le contenu du roman
    res.json({
      title: "Mon Roman Réservé",
      content: "Voici le texte secret du roman réservé uniquement aux acheteurs..."
    });
  } catch (err) {
    res.status(403).json({ error: 'Jeton invalide ou expiré.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`));