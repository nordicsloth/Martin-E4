const express = require('express');
const app = express();

// added so we can serve index.html...
var http = require('http');
var fs = require('fs');

var mysql = require('mysql');

// install first using npm install bcrypt
const bcrypt = require('bcrypt');

const conInfo = 
{
    host: process.env.IP,
    user: process.env.C9_USER,
    password: "",
    database: "TODODB"
};

var session = require('express-session'); 
app.use(session({ secret: 'happy jungle', 
                  resave: false, 
                  saveUninitialized: false, 
                  cookie: { maxAge: 600000 }}))

app.all('/', serveIndex);                  
app.all('/whoIsLoggedIn', whoIsLoggedIn);                  
app.all('/register', register);
app.all('/login', login);
app.all('/logout', logout);
app.all('/listTasks', listTasks);
app.all('/addTask', addTask);
app.all('/removeTask', removeTask);
app.all('/completeTask', completeTask);

app.listen(process.env.PORT,  process.env.IP, startHandler())

function startHandler()
{
  console.log('Server listening on port ' + process.env.PORT)
}

function listTasks(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }

  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      con.query("SELECT * FROM TODO WHERE USER_ID = ? ORDER BY TODO_PRIORITY", [req.session.user.result.id], function (err, result, fields) 
      {
        if (err) 
          writeResult(req, res, {'error' : err});
        else
          writeResult(req, res, {'result' : result});
      });
    }
  });
}

function addTask(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }
  
  if (req.query.task == undefined)
    writeResult(req, res, {'error' : "add requires you to enter a task"});
  else
  {
    var con = mysql.createConnection(conInfo);
    con.connect(function(err) 
    {
      if (err) 
        writeResult(req, res, {'error' : err});
      else
      {
        con.query('INSERT INTO TODO (TODO_TASK, TODO_PRIORITY, USER_ID) VALUES (?, ?, ?)', [req.query.task, req.query.priority, req.session.user.result.id], function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
          {
            con.query("SELECT * FROM TODO WHERE USER_ID = ? ORDER BY TODO_PRIORITY", [req.session.user.result.id], function (err, result, fields) 
            {
              if (err) 
                writeResult(req, res, {'error' : err});
              else
                writeResult(req, res, {'result' : result});
            });
          }
        });
      }
    });
  }
}

function removeTask(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }

  if (req.query.task == undefined)
    writeResult(req, res, {'error' : "remove requires you to specify a task id"});
  else
  {
    var con = mysql.createConnection(conInfo);
    con.connect(function(err) 
    {
      if (err) 
        writeResult(req, res, {'error' : err});
      else
      {
        con.query('DELETE FROM TODO WHERE TODO_ID = ? AND USER_ID = ?', [req.query.task, req.session.user.result.id], function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
          {
            con.query("SELECT * FROM TODO WHERE USER_ID = ? ORDER BY TODO_PRIORITY", [req.session.user.result.id], function (err, result, fields) 
            {
              if (err) 
                writeResult(req, res, {'error' : err});
              else
                writeResult(req, res, {'result' : result});
            });
          }
        });
      }
    });
  }
}

function completeTask(req, res)
{
    if (req.session.user == undefined)
    {
        writeResult(req, res, {'error' : "Please login."});
        return;
    }
    
    if (req.query.complete == undefined)
    writeResult(req, res, {'error' : "complete requires you to specify a task id"});
  else
  {
    var con = mysql.createConnection(conInfo);
    con.connect(function(err) 
    {
      if (err) 
        writeResult(req, res, {'error' : err});
      else
      {
        con.query('INSERT INTO TODO (TODO_COMPLETE) VALUES(?)', [req.query.complete], function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
          {
            con.query("SELECT * FROM TODO WHERE USER_ID = ? ORDER BY TODO_PRIORITY", [req.session.user.result.id], function (err, result, fields) 
            {
              if (err) 
                writeResult(req, res, {'error' : err});
              else
                writeResult(req, res, {'result' : result});
            });
          }
        });
      }
    });
  }
}

function whoIsLoggedIn(req, res)
{
  if (req.session.user == undefined)
    writeResult(req, res, {'error' : 'Nobody is logged in.'});
  else
    writeResult(req, res, req.session.user);
}

function register(req, res)
{
  if (req.query.email == undefined || !validateEmail(req.query.email))
  {
    writeResult(req, res, {'error' : "Please specify a valid email"});
    return;
  }

  if (req.query.password == undefined || !validatePassword(req.query.password))
  {
    writeResult(req, res, {'error' : "Password must have a minimum of eight characters, at least one letter and one number"});
    return;
  }

  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      // bcrypt uses random salt is effective for fighting
      // rainbow tables, and the cost factor slows down the
      // algorithm which neutralizes brute force attacks ...
      let hash = bcrypt.hashSync(req.query.password, 12);
      con.query("INSERT INTO USER (USER_EMAIL, USER_PASS) VALUES (?, ?)", [req.query.email, hash], function (err, result, fields) 
      {
        if (err) 
        {
          if (err.code == "ER_DUP_ENTRY")
            err = "User account already exists.";
          writeResult(req, res, {'error' : err});
        }
        else
        {
          con.query("SELECT * FROM USER WHERE USER_EMAIL = ?", [req.query.email], function (err, result, fields) 
          {
            if (err) 
              writeResult(req, res, {'error' : err});
            else
            {
              req.session.user = {'result' : {'id': result[0].USER_ID, 'email': result[0].USER_EMAIL}};
              writeResult(req, res, req.session.user);
            }
          });
        }
      });
    }
  });
  
}

function login(req, res)
{
  if (req.query.email == undefined)
  {
    writeResult(req, res, {'error' : "Email is required"});
    return;
  }

  if (req.query.password == undefined)
  {
    writeResult(req, res, {'error' : "Password is required"});
    return;
  }
  
  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      con.query("SELECT * FROM USER WHERE USER_EMAIL = ?", [req.query.email], function (err, result, fields) 
      {
        if (err) 
          writeResult(req, res, {'error' : err});
        else
        {
          if(result.length == 1 && bcrypt.compareSync(req.query.password, result[0].USER_PASS))
          {
            req.session.user = {'result' : {'id': result[0].USER_ID, 'email': result[0].USER_EMAIL}};
            writeResult(req, res, req.session.user);
          }
          else 
          {
            writeResult(req, res, {'error': "Invalid email/password"});
          }
        }
      });
    }
  });
}

function logout(req, res)
{
  req.session.user = undefined;
  writeResult(req, res, {'error' : 'Nobody is logged in.'});
}

function writeResult(req, res, obj)
{
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.write(JSON.stringify(obj));
  res.end('');
}

function validateEmail(email) 
{
  if (email == undefined)
  {
    return false;
  }
  else
  {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
  }
}

function validatePassword(pass)
{
  if (pass == undefined)
  {
    return false;
  }
  else
  {
    var re = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return re.test(pass);
  }
}

function serveIndex(req, res)
{
  res.writeHead(200, {'Content-Type': 'text/html'});
  var index = fs.readFileSync('index.html');
  res.end(index);
}