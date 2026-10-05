require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();

app.use(cors());
app.use(express.json());

// 1. Route d'inscription
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, hashedPassword]
    );
    res.json({ success: true, userId: result.insertId });
  } catch (err) {
    res.status(400).json({ error: 'Email déjà utilisé ou données invalides.' });
  }
});

// 2. Route de connexion
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Utilisateur non trouvé.' });

    const user = users[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Mot de passe incorrect.' });

    // Générer un jeton (token) de connexion
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'cle_secrete_defaut', { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Route d'accès au roman (Protégée)
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