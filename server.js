const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5500;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_123';

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL Connection Pool
const pool = new Pool({
    user: process.env.PGUSER || 'postgres',
    host: process.env.PGHOST || 'localhost',
    database: process.env.PGDATABASE || 'taskdb',
    password: process.env.PGPASSWORD || 'dehnow',
    port: process.env.PGPORT || 5432,
});

// Test Database Connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring PostgreSQL client:', err.stack);
    }
    console.log('Connected to PostgreSQL database successfully.');
    release();
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ---------------- API ROUTES ----------------

// Register User
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const userCheck = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Username already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
            [username, hashedPassword]
        );

        res.status(201).json({
            message: 'User registered successfully',
            user: result.rows[0]
        });
    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login User
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid username or password.' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid username or password.' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

        res.json({
            token,
            username: user.username
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get User Tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, title, completed FROM tasks WHERE user_id = $1 ORDER BY id ASC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch Tasks Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create Task
app.post('/api/tasks', authenticateToken, async (req, res) => {
    const { title } = req.body;

    if (!title || !title.trim()) {
        return res.status(400).json({ error: 'Task title is required.' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO tasks (user_id, title) VALUES ($1, $2) RETURNING id, title, completed',
            [req.user.id, title.trim()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Add Task Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});