const express = require('express');
const connectDB = require('./config/db');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Data = require('./models/Data');
const app = express();
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('./middleware/auth');
const notauth = require('./middleware/notauth');
const { render } = require('ejs');
// var popup = require('popups');

// connect database
connectDB();
app.set('view-engine', 'ejs');

// middle ware for post body
// helps us to get data from req.body
app.use(express.json({}));
// very imp for sending data from form to server
app.use(express.urlencoded({ extended: false }));

app.use('/public', express.static('public'));

app.get('/', auth, (req, res) => res.render('index.ejs',{error: ''}));
// app.get('/', (req, res) => res.render('index.ejs',{error: ''}));

app.get('/login',notauth, (req, res) => {
    res.render('login.ejs',{error: ''});
}); 
app.get('/register',notauth, (req, res) => {
    res.render('register.ejs',{error: ''});
}); 

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

app.get('/map',(req,res)=>{
    res.redirect('/index');
})

app.post('/map',async (req,res)=>{
    const {loc} = req.body;
    // res.send(loc);

    try{
        let data = await Data.findOne({"name":loc});
        if(!data){
            return res.render('index.ejs',{error: 'No data found'});
        }
        res.render('map.ejs',{data});

        // let user = new Data({ // create new user instance
        //     name:loc,
        //     iframe:"https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3781.2698969083467!2d73.87289781424344!3d18.606926387358744!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3bc2c70090000001%3A0x160a20f3d0273495!2sArmy%20Institute%20of%20Technology!5e0!3m2!1sen!2sus!4v1671827061260!5m2!1sen!2sus",
        //     data:"data1"
        // });

        // await user.save(); // save user to database
    }catch(err){
        console.error(err.message);
        res.status(500).render('index.ejs', {error: 'Server Error'});
    }

})

// post request for register
app.post('/register',notauth, async (req, res) => {
    const {name, email, password,address,phone} = await req.body; // destructure

    try {
        let user = await User.findOne({email});
        if(user){ // return error of type as above if user exists 
            return res.status(500).render('register.ejs', {error: 'User already exists'});
        }

        user = new User({ // create new user instance
            name,
            email,
            password,
            address,
            phone
        });

        const salt = await bcrypt.genSalt(10); // generate salt
        user.password = await bcrypt.hash(password, salt); // hash password


        await user.save(); // save user to database
        return res.redirect('/login');

    } catch(err){
        console.error(err.message);
        res.status(500).render('register.ejs', {error: 'Server Error'});
    }   
});

// post request for login
app.post('/login',notauth,
async (req,res)=>{
    
    const {email, password} = req.body; // destructure

    try {

        let user = await User.findOne({email});
        if(!user){ // return error of type as above if user exists
            return res.render('login.ejs',{error: 'Invalid Credentials'});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.render('login.ejs',{error: 'Invalid Credentials'});
        }

        const payload = {
            user: {
                id: user.id
            }
        }
        // defining the token and sending it back to the client
        jwt.sign(payload, config.get('jwtSecret'), (err, token)=>{
            req.header['x-auth-token'] = token;
            console.log(req.header['x-auth-token']);
            if(err) throw err;
            res.redirect('/');
        });

        // res.redirect('/');

    } catch(err){
        console.error(err.message);
        res.status(500).render('login.ejs', {error: 'Server Error'});
    }   
}
);

const port = 3000;

app.listen(port, () => console.log(`Listening on port ${port}`));