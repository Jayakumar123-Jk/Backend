require("dotenv").config(); // Load environment variables from .env file

const jwt = require("jsonwebtoken"); // npm install jsonwebtoken dotenv
const sanitizehtml = require("sanitize-html"); // npm install sanitize-html
const bcrypt = require("bcrypt"); // npm install bcrypt
const express = require("express");
const cookieParser = require("cookie-parser");
const db = require("better-sqlite3")("myapp.db"); // npm install better-sqlite3

db.pragma("journal_mode = WAL"); // WAL mode for better performance

// Database setup
const createtable = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createDate TEXT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      authorid INTEGER,
      FOREIGN KEY(authorid) REFERENCES users(id)
    )
  `
  ).run();
});
createtable();

const app = express();

app.set("view engine", "ejs"); // it is used to generate dynamic web pages
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

// Middleware to read JWT cookie
app.use(function (req, res, next) {
  res.locals.errors = [];

  console.log("All cookies:", req.cookies);
  console.log("JWTSECRET:", process.env.JWTSECRET);

  try {
    const decoded = jwt.verify(req.cookies.oursimpleapp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    console.error("JWT verify error:", err.message);
    req.user = false;
  }

  res.locals.user = req.user;
  console.log("Decoded user:", req.user);
  next();
});

// Routes

app.get("/", (req, res) => {
  if (req.user) {
    const poststatement= db.prepare("SELECT * FROM posts WHERE authorid  =?")
    const posts=poststatement.all(req.user.id)
    return res.render("dashboard",{posts});
  }
  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.clearCookie("oursimpleapp");
  res.redirect("/");
});

app.post("/login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  if (req.body.username.trim() === "") errors.push("invalid username");
  if (req.body.password.trim() === "") errors.push("invalid password");

  if (errors.length) {
    return res.render("login", { errors });
  }

  const userinquestionstatement = db.prepare("SELECT * FROM users WHERE username = ?");
  const userinquestion = userinquestionstatement.get(req.body.username.trim());

  if (!userinquestion) {
    errors = ["invalid username/password"];
    return res.render("login", { errors });
  }

  const matchornot = bcrypt.compareSync(req.body.password, userinquestion.password);
  if (!matchornot) {
    errors = ["invalid username/password"];
    return res.render("login", { errors });
  }

  const ourtokenvalue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skycolor: "blue", // custom value
      id: userinquestion.id,
      username: userinquestion.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("oursimpleapp", ourtokenvalue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  console.log("Token created and cookie set:", ourtokenvalue);

  res.redirect("/"); // Redirect instead of res.send()
});

// Middleware to protect routes
function mustbeloggedin(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}


// for createpost
app.get("/createpost", mustbeloggedin, (req, res) => {
  res.render("create-post");
});

// Validation helper
function sharedPostValidation(req) {
  const errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // trim + sanitize
  req.body.title = sanitizehtml(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: [],
  }); // used to remove the malicious html and javascript
  req.body.body = sanitizehtml(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: [],
  });

  if (!req.body.title) errors.push("you must provide a title");
  if (!req.body.body) errors.push("you must provide a content");

  return errors;
}
app.get("/edit-post/:id",(req,res)=>{
  /// try to lookup the post in question
  const statement=db.prepare("SELECT * FROM posts WHERE id=?")
  const post=statement.get(req.params.id)


  //if you're not the author,redirected to home page
  if(post.authorid !== req.user.userid){
    return res.redirect("/") 
  }
   

  //otherwise render the edit post template
  res.render("edit-post",{ post })
})
app.get("/post/:id", (req, res) => {
  const id = parseInt(req.params.id); // Ensure it's a number

  // Join to fetch post + author's username
  const statement = db.prepare(`
    SELECT posts.*, users.username 
    FROM posts 
   INNER JOIN users ON posts.authorid = users.id 
    WHERE posts.id = ?
  `);
  const post = statement.get(id);

  if (!post) {
    return res.redirect("/"); // Redirect if post not found
  }

  res.render("single-post", { post });
});


app.post("/create-post", mustbeloggedin, (req, res) => {
  const errors = sharedPostValidation(req);

  if (errors.length) {
    return res.render("create-post", { errors });
  }

  const ourstatement = db.prepare(
    "INSERT INTO posts (title, body, authorid, createDate) VALUES (?, ?, ?, ?)"
  );
  const result = ourstatement.run(
    req.body.title,
    req.body.body,
    req.user.id,
    new Date().toISOString()
  );

  const getpoststatement = db.prepare("SELECT * FROM posts WHERE rowid = ?");
  const realpost = getpoststatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realpost.id}`);
});

app.post("/register", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("Enter username!!");
  if (req.body.username.length > 10)
    errors.push("Username cannot exceed more than 10 characters");
  if (req.body.password.length < 7)
    errors.push("Password must be at least 7 characters");

  // check if username exists already
  const usernamestatement = db.prepare("SELECT * FROM users WHERE username = ?");
  const usernamecheck = usernamestatement.get(req.body.username);

  if (usernamecheck) errors.push("that username is already taken !");

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const ourstatement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  );
  const result = ourstatement.run(req.body.username, req.body.password);

  const lookupstatement = db.prepare("SELECT * FROM users WHERE rowid=?");
  const ouruser = lookupstatement.get(result.lastInsertRowid);

  const ourtokenvalue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skycolor: "blue",
      id: ouruser.id,
      username: ouruser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("oursimpleapp", ourtokenvalue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  console.log("Token created and cookie set:", ourtokenvalue);

  res.redirect("/"); // Redirect instead of res.send()
});

// Start the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
