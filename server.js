// Importera nödvändiga paket och moduler
const helmet = require("helmet");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const methodOverride = require("method-override");
const MongoStore = require("connect-mongo");

const app = express();
const port = 3000;

// Anslut till MongoDB-databasen
mongoose.connect("mongodb://localhost/blog", {});

// Konfigurera session med MongoStore
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: "mongodb://localhost/blog",
      collectionName: "sessions",
    }),
    cookie: { maxAge: 1000 * 60 * 60 },
  })
);

// Använd middleware för säkerhet och hantering av inkommande data
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));

// Konfigurera EJS som vy-motor och använd statiska filer från 'public'-mappen
app.set("view engine", "ejs");
app.use(express.static("public"));

// Definiera scheman och modeller för användare och blogginlägg
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  signature: String,
  isAdmin: { type: Boolean, default: false },
});
const User = mongoose.model("User", userSchema);

const Post = mongoose.model("Post", {
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  signature: String,
  createdAt: { type: Date, default: Date.now },
});

// Middleware för att kontrollera admin-behörighet
const isAdmin = async (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).send("Du måste vara inloggad");
  }

  try {
    const user = await User.findById(req.session.userId);
    if (user && user.isAdmin) {
      return next();
    } else {
      return res
        .status(403)
        .send("Endast administratörer har tillgång till denna funktion");
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internt serverfel");
  }
};

// Middleware för att kontrollera om användaren är inloggad
const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
    res.redirect("/login");
  } else {
    next();
  }
};

// Definiera routes för användarregistrering, inloggning, utloggning, och skapande av inlägg
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.userId = user._id;
      res.redirect("/");
    } else {
      res
        .status(401)
        .send("Du har angivit felaktiga uppgifter. YOU SHALL NOT PASS");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internt serverfel");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/"),
  async (req, res) => {
    try {
      let user = null;
      if (req.session.userId) {
        user = await User.findById(req.session.userId).exec();
      }
      const posts = await Post.find().sort({ createdAt: "desc" }).exec();
      res.render("index", { user, posts });
    } catch (error) {
      console.error(error);
      res.redirect("/");
    }
  };
