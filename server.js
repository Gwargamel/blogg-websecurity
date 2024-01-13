// Importering av moduler
const helmet = require("helmet");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const methodOverride = require("method-override");

// Skapande av express app
const app = express();
const port = 3000;

// Koppla upp till servern mongoDB
mongoose.connect("mongodb://localhost/blog", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Definiera mongoose modeller
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
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method")); // Använd method-override
app.use(
  session({
    secret: "your-secret-key",
    resave: true,
    saveUninitialized: true,
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

//Anger vy-motorn---
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
