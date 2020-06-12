const fs = require('fs')
const http = require('http')
const path = require('path')

const bcrypt = require('bcrypt')
const bodyParser = require('body-parser')
const connect = require('connect')
const cookieSession = require('cookie-session')
const serveStatic = require('serve-static')
const expand_home_dir = require('expand-home-dir')
const shell = require('shelljs')

const PORT = (process.argv[2] ? parseInt(process.argv[2]) : 3000)
const DATA_PATH = expand_home_dir('~/user_login_demo_data')
const USERS_PATH = path.join(DATA_PATH, 'email_to_user.json')

let email_to_user = {}
if(fs.existsSync(USERS_PATH)) {
  const users_json = fs.readFileSync(USERS_PATH, 'utf8')
  email_to_user = JSON.parse(users_json)
}

function get_email(req) {
  return req.body.email.toLowerCase()
}

function create_account_post(req, res) {
  const email = get_email(req)
  if(!email.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}/)) {
    res.statusCode = 400
    res.end('invalid email')
    return
  }

  if(email_to_user[email]) {
    login_post(req, res)
    return
  }

  const saltRounds = 10;
  bcrypt.genSalt(saltRounds, function(err, salt) {
      bcrypt.hash(req.body.password, salt, function(err, password_hash) {
        const user_id = Math.round(Math.random() * Math.pow(10, 10))

        const user = email_to_user[email] = {
          email: email,
          salt: salt,
          password_hash: password_hash,
          user_id: user_id
        }

        const users_json = JSON.stringify(email_to_user, null, 2)
        if(!fs.existsSync(DATA_PATH))
          shell.mkdir('-p', DATA_PATH)
        fs.writeFileSync(USERS_PATH, users_json, 'utf8')

        req.session.auth_token = user.auth_token = Math.random()
        req.session.email  = get_email(req)
        res.writeHead(302, {'Location': '/secret_page'})
        res.end()
      });
  });
}

function login_post(req, res) {
  const user = email_to_user[get_email(req)]

  if(!user) {
    res.statusCode = 401
    res.end('user not found')
    return
  }

  bcrypt.compare(req.body.password, user.password_hash, function(err, is_match) {
    if(is_match) {
      req.session.auth_token = email_to_user[get_email(req)].auth_token = Math.random()
      req.session.email = get_email(req)
      res.writeHead(302, {'Location': `/secret-page`})
      res.end()
    }
    else {
      res.statusCode = 401
      res.end('wrong password')
    }
  });
}

const app = connect();

app.use(cookieSession({keys: ['auth_token']}));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

app.use(function(req, res, next){
  const ip_address = req.connection.remoteAddress
  console.log(`${new Date().toUTCString()} request from: ${ip_address}, ${req.url}`);

  let response_string = ''

  if(req.method == 'POST') {
    if(req.url == '/login')
      return create_account_post(req, res)
  }
  else {
    if(req.url == '/')
      response_string = fs.readFileSync('page_templates/index.html', 'utf8')
    else if(req.url == '/log-in')
      response_string = fs.readFileSync('page_templates/log-in.html', 'utf8')
    else if(req.url == '/create-account')
      response_string = fs.readFileSync('page_templates/create-account.html', 'utf8')
    else if(req.url == '/secret-page') {
      const auth_token = req.session.auth_token
      const user = email_to_user[req.session.email]
      if(auth_token && user && auth_token == user.auth_token)
        response_string = fs.readFileSync('page_templates/secret-page.html', 'utf8')
      else {
        res.statusCode = 401
        res.end('unauthorized')
      }
    }
    else {
      next()
      return
    }

    res.statusCode = 200
    res.setHeader('Content-Type', 'text/html')
    res.end(response_string)
    return
  }

  res.statusCode = 404
  res.setHeader('Content-Type', 'text/html')
  res.end('Page not found')
})

const static = serveStatic('static')
app.use(function(req, res, next) {
  static(req, res, next)
})

http.createServer(app).listen(PORT)
console.log(`listening on ${PORT}`)
