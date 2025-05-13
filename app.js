require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 8000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const client = new MongoClient(process.env.MONGODB_HOST);
let db;
async function connectDB() {
    await client.connect();
    db = client.db(process.env.MONGODB_DATABASE);
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);

const isProduction = process.env.NODE_ENV === 'production';
if (!process.env.NODE_SESSION_SECRET) {
    console.error('NODE_SESSION_SECRET is not set. Using a temporary secret.');
    process.env.NODE_SESSION_SECRET = require('crypto').randomBytes(32).toString('hex');
}
if (!process.env.MONGODB_SESSION_SECRET) {
    console.error('MONGODB_SESSION_SECRET is not set. Using a temporary secret.');
    process.env.MONGODB_SESSION_SECRET = require('crypto').randomBytes(32).toString('hex');
}
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        client,
        dbName: process.env.MONGODB_DATABASE,
        collectionName: 'sessions',
        ttl: 60 * 60,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60 * 60 * 1000,
        secure: isProduction,
        httpOnly: true,
        sameSite: 'strict'
    }
}));

const RENDER_URL = 'https://comp2537-assign2-2m41.onrender.com';
const PING_INTERVAL = 14 * 60 * 1000;
function keepAlive() {
    axios.get(RENDER_URL)
        .then(() => {})
        .catch(() => {});
}
setInterval(keepAlive, PING_INTERVAL);

const isLoggedIn = (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    next();
};

const isAdmin = (req, res, next) => {
    if (req.session.user.user_type !== 'admin') {
        res.status(403).render('error', { error: 'Not authorized', status: 403, user: req.session.user || null, pathname: '/error' });
        return;
    }
    next();
};

app.get('/', (req, res) => {
    res.render('index', { user: req.session.user || null, pathname: '/' });
});

app.get('/signup', (req, res) => {
    res.render('signup', { user: req.session.user || null, error: null, pathname: '/signup' });
});

app.post('/signupSubmit', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().pattern(/^[a-zA-Z0-9]+$/).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().pattern(/^[a-zA-Z0-9!@#$%^&*]+$/).max(20).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.render('signup', { error: error.details[0].message, user: null, pathname: '/signup' });
    }

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const userCollection = db.collection('users');
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.render('signup', { error: 'Email already exists', user: null, pathname: '/signup' });
        }

        await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });
        req.session.user = { name, email, user_type: 'user' };
        res.redirect('/members');
    } catch (err) {
        res.render('signup', { error: 'Database error', user: null, pathname: '/signup' });
    }
});

app.get('/login', (req, res) => {
    res.render('login', { user: req.session.user || null, error: null, pathname: '/login' });
});

app.post('/loginSubmit', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().pattern(/^[a-zA-Z0-9!@#$%^&*]+$/).max(20).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.render('login', { error: error.details[0].message, user: null, pathname: '/login' });
    }

    const { name, email, password } = req.body;

    try {
        const userCollection = db.collection('users');
        const user = await userCollection.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: 'Invalid email or password', user: null, pathname: '/login' });
        }

        req.session.user = { name: user.name, email, user_type: user.user_type || 'user' };
        res.redirect('/members');
    } catch (err) {
        res.render('login', { error: 'Database error', user: null, pathname: '/login' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

app.get('/members', isLoggedIn, (req, res) => {
    res.render('members', { user: req.session.user, pathname: '/members' });
});

app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
    const users = await db.collection('users').distinct('name').then(async (names) => {
        return await db.collection('users').find({ name: { $in: names } }).toArray();
    });
    res.render('admin', { users, user: req.session.user, userLoggedIn: req.session.user, pathname: '/admin' });
});

app.get('/admin/promote/:id', isLoggedIn, isAdmin, async (req, res) => {
    const schema = Joi.object({
        id: Joi.string().required()
    });
    const { error } = schema.validate({ id: req.params.id });
    if (error) return res.redirect('/admin');

    await db.collection('users').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

app.get('/admin/demote/:id', isLoggedIn, isAdmin, async (req, res) => {
    const schema = Joi.object({
        id: Joi.string().required()
    });
    const { error } = schema.validate({ id: req.params.id });
    if (error) return res.redirect('/admin');

    await db.collection('users').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

app.use((req, res) => {
    res.status(404).render('404', { user: req.session.user || null, pathname: '/404' });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});