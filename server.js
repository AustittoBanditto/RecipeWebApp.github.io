const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const exphbs = require('express-handlebars');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');

const app = express();
const PORT = 3000;
const JWT_SECRET = '6c648f4fa323c74f8825d3535f3f327f287d3bf408cb859f9020e84b37c82cfb';


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Handlebars setup
const hbs = exphbs.create({
    helpers: {
        eq: function (a, b) {
            return a === b;
        },
        add: function(a, b) {
            return a + b;
        },
        split: function(text, delimiter) {
            return text ? text.split(delimiter) : [];
        }
    }
});

app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

// Database setup
const db = new sqlite3.Database('recipes.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS recipes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        ingredients TEXT,
        instructions TEXT,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Create default admin users
    const adminPassword = bcrypt.hashSync('admin123', 10);
    const admin2Password = bcrypt.hashSync('admin456', 10);
    
    db.run(`INSERT OR IGNORE INTO users (username, password, role) 
            VALUES ('admin', ?, 'admin')`, [adminPassword]);
            
    db.run(`INSERT OR IGNORE INTO users (username, password, role) 
            VALUES ('admin2', ?, 'admin')`, [admin2Password]);
});

// Authentication middleware
const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.redirect('/login');
    }
};

// Spoonacular API key
const SPOONACULAR_API_KEY = '80a4d0ffc71b4f8a8ed3820bc4419d98';

// Update the root route to check for existing login
app.get('/', (req, res) => {
    const token = req.cookies.token;
    if (token) {
        try {
            jwt.verify(token, JWT_SECRET);
            return res.redirect('/dashboard');
        } catch (err) {
            res.clearCookie('token');
        }
    }
    res.render('login');
});

// Add logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Route to display the registration form
app.get('/register', (req, res) => {
    res.render('register');
});

// Handle user registration - creates new user with hashed password
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
        [username, hashedPassword, 'guest'],
        (err) => {
            if (err) return res.status(400).json({ error: 'Username already exists' });
            res.redirect('/');
        }
    );
});

// Handle user login - authenticates user and creates JWT token
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.render('login', { 
                error: 'User not found! Please check your username or register a new account.'
            });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.render('login', { 
                error: 'Invalid password! Please try again.'
            });
        }
        
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
        res.cookie('token', token);
        res.redirect('/dashboard');
    });
});

// Update dashboard route to include user info
app.get('/dashboard', auth, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// API endpoint to search recipes from Spoonacular
app.get('/search-recipes', auth, async (req, res) => {
    const { query } = req.query;
    const response = await fetch(
        `https://api.spoonacular.com/recipes/complexSearch?apiKey=${SPOONACULAR_API_KEY}&query=${query}&number=30`
    );
    const data = await response.json();
    res.json(data);
});

// Create a new recipe in the database
app.post('/recipes', auth, (req, res) => {
    const { title, ingredients, instructions } = req.body;
    db.run(
        'INSERT INTO recipes (title, ingredients, instructions, user_id) VALUES (?, ?, ?, ?)',
        [title, ingredients, instructions, req.user.id],
        (err) => {
            if (err) return res.status(400).json({ error: 'Error creating recipe' });
            res.redirect('/my-recipes');
        }
    );
});

// Update my-recipes route to include user info
app.get('/my-recipes', auth, (req, res) => {
    db.all('SELECT * FROM recipes WHERE user_id = ?', [req.user.id], (err, recipes) => {
        if (err) return res.status(400).json({ error: 'Error fetching recipes' });
        res.render('my-recipes', { recipes, user: req.user });
    });
});

// Delete a specific recipe by ID
app.delete('/recipes/:id', auth, (req, res) => {
    db.run(
        'DELETE FROM recipes WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.id],
        (err) => {
            if (err) return res.status(400).json({ error: 'Error deleting recipe' });
            res.json({ message: 'Recipe deleted successfully' });
        }
    );
});

// Admin route to view all users - requires admin role
app.get('/admin/users', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    db.all('SELECT id, username, role FROM users', (err, users) => {
        if (err) return res.status(400).json({ error: 'Error fetching users' });
        res.render('admin-users', { users });
    });
});

// Route to get detailed recipe information from Spoonacular API
app.get('/recipe/:id', auth, async (req, res) => {
    try {
        const response = await fetch(
            `https://api.spoonacular.com/recipes/${req.params.id}/information?apiKey=${SPOONACULAR_API_KEY}`
        );
        const recipe = await response.json();
        res.render('recipe-detail', { recipe, user: req.user });
    } catch (err) {
        res.status(500).json({ error: 'Error fetching recipe details' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('\nAdmin Credentials:');
    console.log('1. Username: admin    Password: admin123');
    console.log('2. Username: admin2   Password: admin456\n');
});
