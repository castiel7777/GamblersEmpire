// backend/server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const app = express();
const port = 3000; // You can change this port if it's in use

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files (your frontend HTML, CSS, JS, images) from the parent directory
// This means requests like http://localhost:3000/index.html will serve your frontend
app.use(express.static(path.join(__dirname, '..')));

// Initialize SQLite database
const db = new sqlite3.Database(path.join(__dirname, 'database.db'), (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_pic_url TEXT DEFAULT '/images/default-profile.png' -- Added profile picture URL
        )`, (createErr) => {
            if (createErr) {
                console.error('Error creating users table:', createErr.message);
            } else {
                console.log('Users table ready.');
            }
        });
        // Create playing_history table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS playing_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            game_type TEXT NOT NULL,
            score INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`, (createErr) => {
            if (createErr) {
                console.error('Error creating playing_history table:', createErr.message);
            } else {
                console.log('Playing history table ready.');
            }
        });
    }
});

// --- API Endpoints ---

// User Signup
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const password_hash = await bcrypt.hash(password, 10); // Hash password with salt rounds = 10
        // Insert with default profile_pic_url
        db.run(`INSERT INTO users (username, password_hash, profile_pic_url) VALUES (?, ?, ?)`, [username, password_hash, '/images/default-profile.png'], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: 'Username already exists.' });
                }
                console.error('Signup DB error:', err.message);
                return res.status(500).json({ message: 'Error creating user.' });
            }
            // Return username and profile_pic_url on successful signup
            res.status(201).json({ message: 'User registered successfully!', userId: this.lastID, username: username, profilePic: '/images/default-profile.png' });
        });
    } catch (hashError) {
        console.error('Password hashing error:', hashError);
        res.status(500).json({ message: 'Internal server error during signup.' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Select username, id, and profile_pic_url
    db.get(`SELECT id, username, password_hash, profile_pic_url FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) {
            console.error('Login DB error:', err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            // Return username and profile_pic_url along with userId
            res.status(200).json({ message: 'Login successful!', userId: user.id, username: user.username, profilePic: user.profile_pic_url });
        } else {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
    });
});

// Save Playing History
app.post('/api/history/save', (req, res) => {
    const { userId, gameType, score } = req.body;

    if (!userId || !gameType || score === undefined) {
        return res.status(400).json({ message: 'Missing playing history data (userId, gameType, score).' });
    }

    db.run(`INSERT INTO playing_history (user_id, game_type, score) VALUES (?, ?, ?)`,
        [userId, gameType, score], function(err) {
            if (err) {
                console.error('Save history DB error:', err.message);
                return res.status(500).json({ message: 'Error saving playing history.' });
            }
            res.status(201).json({ message: 'Playing history saved successfully!', historyId: this.lastID });
        });
});

// Get Playing History for a specific user
app.get('/api/history/:userId', (req, res) => {
    const { userId } = req.params;

    db.all(`SELECT * FROM playing_history WHERE user_id = ? ORDER BY timestamp DESC`, [userId], (err, rows) => {
        if (err) {
            console.error('Get history DB error:', err.message);
            return res.status(500).json({ message: 'Error retrieving playing history.' });
        }
        res.status(200).json(rows);
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log(`Access your application at http://localhost:${port}/index.html`);
});