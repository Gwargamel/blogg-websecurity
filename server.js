// Importering av moduler
const helmet = require("helmet"); // Ökar säkerheten med hjälp av HTTP-headers
const express = require("express"); // Ramverk för att skapa webbapplikationer med Node.js
const mongoose = require("mongoose"); // ODM (Object Data Modeling) för att arbeta med databaser i MongoDB
const session = require("express-session"); // Middleware för sessionshantering i Express
const bcrypt = require("bcrypt"); // Hashar lösenord
const methodOverride = require("method-override"); // Middleware för PUT och DELETE

// Skapande av express app
const app = express();
const port = 3000;

// Kopplar upp till servern mongoDB
mongoose.connect("mongodb://localhost/blog", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Definierar mongoose modeller för databasens struktur
const Post = mongoose.model("Post", {
  title: String,
  content: String,
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  signature: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", {
  username: String,
  password: String,
  signature: String,
});

// Middleware-inställningar
app.use(helmet()); // Används för att ställa in olika HTTP-headers för ökad säkerhet
app.use(express.urlencoded({ extended: true })); // Tolkar url-kodad data i POST-förfrågningar
app.use(methodOverride("_method")); // Använder HTTP-metoder som PUT och DELETE
app.use(
  session({
    secret: "your-secret-key",
    resave: true,
    saveUninitialized: true,
    cookie: { expires: (maxAge = 1000 * 60 * 60) },
  })
);

//Kontrollerar att användaren är inloggad
const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
    res.redirect("/login");
  } else {
    next();
  }
};

//Anger vy-motorn
app.set("view engine", "ejs");
app.use(express.static("public"));

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = new User({
    username: username,
    password: hashedPassword,
  });

  await newUser.save();

  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username: username });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.userId = user._id;
    res.redirect("/");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/", async (req, res) => {
  try {
    const user = req.session.userId
      ? await User.findById(req.session.userId).exec()
      : null;
    const posts = await Post.find().sort({ createdAt: "desc" }).exec();

    res.render("index", { user: user, posts: posts });
  } catch (error) {
    console.error(error);
    res.redirect("/");
  }
});

app.get("/create-post", requireLogin, async (req, res) => {
  try {
    const user = req.session.userId
      ? await User.findById(req.session.userId).exec()
      : null;

    res.render("create-post", { user: user });
  } catch (error) {
    console.error(error);
    res.redirect("/");
  }
});

app.post("/create-post", requireLogin, async (req, res) => {
  const { title, content } = req.body;

  try {
    const user = await User.findById(req.session.userId);

    if (!user) {
      throw new Error("User not found");
    }

    const newPost = new Post({
      title: title,
      content: content,
      author: user._id,
      signature: user.username,
    });

    await newPost.save();
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.redirect("/create-post");
  }
});

app.delete("/delete-post/:id", requireLogin, async (req, res) => {
  try {
    const postId = req.params.id;

    const post = await Post.findOne({
      _id: postId,
      author: req.session.userId,
    });

    if (!post) {
      res.status(403).send("Forbidden");
      return;
    }

    await Post.findByIdAndDelete(postId);

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
