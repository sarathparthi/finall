const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const cors = require('cors'); // For handling CORS
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors()); // Allow cross-origin requests

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',  // Update if necessary
    user: 'root',       // Your MySQL username
    password: 'Mrwizard@19', // Your MySQL password
    database: 'base'    // Your database name
});

// Connect to MySQL
db.connect(err => {
    if (err) {
        console.error('MySQL connection error:', err);
        throw err;
    }
    console.log('MySQL Connected');
});

// Register new user
app.post('/register', (req, res) => {
    const { email, password } = req.body;

    // Check if all required fields are provided
    if (!email || !password) {
        return res.status(400).send('Please provide both email and password.');
    }

    // Check if the user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).send('Server error.');
        }
        if (result.length > 0) {
            return res.status(400).send('User already exists!');
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Error hashing the password:', err);
                return res.status(500).send('Error saving the user.');
            }

            // Insert the new user into the database using only email and hashed password
            db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash], (err, result) => {
                if (err) {
                    console.error('Error inserting the user into the database:', err);
                    return res.status(500).send('Server error.');
                }
                res.status(201).send('User registered successfully!');
            });
        });
    });
});

// Login existing user
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if all required fields are provided
    if (!email || !password) {
        return res.status(400).send('Please provide both email and password.');
    }

    // Check if the user exists by email
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).send('Server error.');
        }
        if (result.length === 0) {
            return res.status(400).send('User not found!');
        }

        // Compare the password with the hashed password in the database
        bcrypt.compare(password, result[0].password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).send('Server error.');
            }
            if (isMatch) {
                res.send('You successfully logged in!');
            } else {
                res.status(401).send('Incorrect password!');
            }
        });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
