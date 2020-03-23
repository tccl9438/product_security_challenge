if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const initializePassport = require('./passport-config')
const {check, validationResult} = require('express-validator')

initializePassport(
    passport, 
    username => users.find(user => user.username === username),
    id => users.find(user => user.id === id)
)

const users = []

app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended:false}))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUnitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))
app.use(express.json())

app.get('/', checkAuthenticated, (req, res) => {
    res.render('prof.ejs', {name:req.user.username})
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

app.post('/register', 
        [   check('username')
                .isLength({min:6}).withMessage('Username should be of at least 6 characters long'),
            check('email').isEmail().withMessage('Please enter a valid email address'), 
            check('password')
                .isLength({min:6}).withMessage('Password should be of at least 6 characters long')
                .not().isIn(['123', 'password', 'god', 'abc']).withMessage('Password is too weak. Please re-enter password')
                .matches(/\d/).withMessage('Password should contain at least a number') 
        ], checkNotAuthenticated, async (req, res) =>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){

        console.log(errors.array())
        return res.status(422).json({"error": errors.array()})
    }
    const username = req.body.username
    const email = req.body.email
    const password = req.body.password
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        })
        console.log(users)
        res.redirect('/login')
    } catch{
        res.redirect('/register')
    }
})

app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next()
    }
    res.redirect('login')
}

function checkNotAuthenticated(req, res, next) {
    if(req.isAuthenticated()){
        return res.redirect('/')
    }
    next()
}
app.listen(3000)