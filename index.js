const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_user}:${process.env.DB_pass}@cluster0.ihuxcck.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function dbConnect() {
    try {
        await client.connect();
        console.log("Database Connected Successfully");
    } catch (error) {
        console.error("Database connection error:", error);
    }
}
dbConnect();

const usersCollection = client.db('expenseTracker').collection('users');
const expensesCollection = client.db('expenseTracker').collection('expenses');

// Root Route
app.get('/', (req, res) => {
    res.send('Expense Tracker API is running');
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Authentication token is missing' });

        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// Register
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required' });

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await usersCollection.insertOne({ username, email, password: hashedPassword, created_at: new Date() });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed', error: error.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const user = await usersCollection.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ sub: user._id, email: user.email, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('accessToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 604800000 });
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ message: 'Login failed', error: error.message });
    }
});

// Logout
app.post('/logout', (req, res) => {
    try {
        res.clearCookie('accessToken', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
        res.status(500).json({ message: 'Logout failed', error: error.message });
    }
});

// Validate Expense
function validateExpense({ title, amount, date }) {
    if (!title || title.length < 3) return "Title must be at least 3 characters long";
    if (!amount || isNaN(amount) || Number(amount) <= 0) return "Amount must be a number greater than 0";
    if (!date || isNaN(new Date(date).getTime())) return "Invalid date";
    return null;
}

// Add Expense
app.post('/expenses', authMiddleware, async (req, res) => {
    const error = validateExpense(req.body);
    if (error) return res.status(400).json({ message: error });

    const { title, amount, category, date } = req.body;
    await expensesCollection.insertOne({
        userId: req.user.sub,
        title,
        amount: Number(amount),
        category,
        date: new Date(date),
        createdAt: new Date()
    });
    res.status(201).json({ message: 'Expense added successfully' });
});

// Get All Expenses (User-specific)
app.get('/expenses', authMiddleware, async (req, res) => {
    const expenses = await expensesCollection.find({ userId: req.user.sub }).sort({ date: -1 }).toArray();
    res.json(expenses);
});

// Update Expense
app.patch('/expenses/:id', authMiddleware, async (req, res) => {
    const error = validateExpense(req.body);
    if (error) return res.status(400).json({ message: error });

    const { id } = req.params;
    const { title, amount, category, date } = req.body;

    await expensesCollection.updateOne(
        { _id: new ObjectId(id), userId: req.user.sub },
        { $set: { title, amount: Number(amount), category, date: new Date(date) } }
    );

    res.json({ message: 'Expense updated successfully' });
});

// Delete Expense
app.delete('/expenses/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    await expensesCollection.deleteOne({ _id: new ObjectId(id), userId: req.user.sub });
    res.json({ message: 'Expense deleted successfully' });
});

// Start Server
app.listen(port, () => console.log(`Server running on port ${port}`));
