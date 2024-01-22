const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const port = 3000;

// Anslut till MongoDB
mongoose.connect("mongodb://localhost:27017/blog", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("Connected to MongoDB"));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true })
);

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// User model
const User = mongoose.model("User", {
  username: String,
  password: String,
});

// Routes
app.get("/", (req, res) => {
  const user = req.session.user;
  res.render("index", { user });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.user = { username: user.username };
    res.redirect("/");
  } else {
    res.send("Invalid username or password");
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.redirect("/login");
});

app.get("/create-post", (req, res) => {
  const user = req.session.user;

  if (user) {
    res.render("create-post");
  } else {
    res.redirect("/login");
  }
});

app.post("/create-post", (req, res) => {
  // Implementera logik för att skapa ett inlägg här
  res.send("Post created successfully");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Starta servern
app.listen(port, () =>
  console.log(`Server is running on http://localhost:${port}`)
);
