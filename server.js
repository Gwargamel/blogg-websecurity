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

// Första steget är att få en access code från GitHub.
// Vi omdirigerar requests till Github där man sedan får logga in.
app.get("/auth/github", (_req, res) => {
  const authUrl =
    "https://github.com/login/oauth/authorize?client_id=b68e6874e5f21942b543"; //Client ID finns i inställningarna för GitHub.
  res.redirect(authUrl);
});
// Hit kommer vi med en kod som kan användas för att bytas mot en token.
app.get("/auth/github/callback", async (req, res) => {
  const code = req.query.code;
  // Här får vi själva access_token
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: "169b8ab064c8f1386757",
      client_secret: "3eb04288fa9da0d1f205db2c7215474eff9d997a", //Din nyckel
      code: code,
    }),
    // Vi vill ha vår token i JSON-format
    headers: {
      Accept: "application/json",
    },
  });
  const jsonResponse = await response.json();
  req.session.username = await getUserInfoFromGitHub(jsonResponse.access_token);
  res.send("Authentication successful!");
});
const getUserInfoFromGitHub = async (access_token) => {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${access_token}`,
    },
  });
  return await response.json();
};
//Hämtar användarinformation med token
app.get("/user", async (req, res) => {
  if (!req.session.access_token) {
    res.status(403).send("Access Denied.");
  }
  res.send(await response.json());
});

//En expressrutt hanterar GET-förfrågningar till rot-URL
app.get("/", async (req, res) => {
  try {
    let user; //Anger variabeln user

    //En if-else-sats kontrollerar om det finns ett userId i sessionen
    if (req.session.userId) {
      //Om userId finns, hämtas användaren från databasen
      user = await User.findById(req.session.userId).exec();
    } else {
      //Om userId ej finns sätts user till null
      user = null;
    }

    // Hämtar alla blogginlägg, sorterade efter datum
    const posts = await Post.find().sort({ createdAt: "desc" }).exec();

    // Renderar en sida med användar- och inläggsdata
    res.render("index", { user: user, posts: posts });
  } catch (error) {
    //Catch fångar upp eventuella fel
    console.error(error); //Felmeddelande loggas i konsollen
    res.redirect("/"); //Omdirigerar användaren tillbaka till startsidan
  }
});

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

// /create-post-rutten renderar en vy där användaren kan skapa ett blogginlägg
app.get("/create-post", requireLogin, async (req, res) => {
  //Asyncron-funktion som hanterar inkommande GET-förfrågningar
  //requireLogin kontrollerar att användaren är inloggad vilket krävs för att skriva ett inlägg
  try {
    //Kontrollerar om det finns ett userId i den aktuella sessionen
    const user = req.session.userId //En ternär operator, ?, används istället för if-else
      ? await User.findById(req.session.userId).exec() //Hämtar användarens information från databasen
      : null; //Om användaren ej är inloggad sätts userId till null

    res.render("create-post", { user: user }); //Skickar en HTML-sida till klienten med datan user
  } catch (error) {
    //Fångar upp eventuella fel
    console.error(error); //Felmeddelande loggas i konsollen
    res.redirect("/"); //Omdirigerar användaren tillbaka till startsidan
  }
});

//Hanterar POST-förfrågan om att skapa nya blogginlägg
app.post("/create-post", requireLogin, async (req, res) => {
  //skapar en route-hanterare för POST-förfrågningar till /create-post.
  //requireLogin är en middleware-funktion som körs före den asynkrona callback-funktionen och
  //kräver att en användare är inloggad för att kunna publicera ett inlägg
  const { title, content } = req.body;

  try {
    //try-catch används för att fånga upp eventuella fel
    const user = await User.findById(req.session.userId);
    //Hämtar användardata från databasen baserat på användarens ID i sessionen

    if (!user) {
      throw new Error("User not found"); //Om user inte hittas uppstår ett fel
    }

    //Skapar ett nytt blogginlägg som innehåller: titel, text, författarens id och användarnamn
    const newPost = new Post({
      title: title,
      content: content,
      author: user._id,
      signature: user.username,
    });

    await newPost.save(); //Det nya inlägget sparas i databasen
    res.redirect("/"); //Användaren omdirigeras till startsidan
  } catch (error) {
    //Fångar upp eventuella fel under processen
    console.error(error); //Ett felmeddelande loggas i konsollen
    res.redirect("/create-post"); //Användaren omdirigeras tillbaka till formuläret för att skapa nytt inlägg
  }
});

// Middleware för att kontrollera om användaren kan radera inlägget
const canDeletePost = async (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).send("Du måste vara inloggad");
  }

  try {
    const post = await Post.findById(req.params.id).exec();
    const user = await User.findById(req.session.userId);

    if (!post) {
      return res.status(404).send("Inlägget hittades inte");
    }

    // Tillåt radering om användaren är administratör eller ägare av inlägget
    if (user.isAdmin || post.author.equals(user._id)) {
      return next();
    } else {
      return res
        .status(403)
        .send("Du har inte behörighet att radera detta inlägg");
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internt serverfel");
  }
};

// Uppdaterad route för att radera inlägg
app.delete(
  "/delete-post/:id",
  requireLogin,
  canDeletePost,
  async (req, res) => {
    try {
      await Post.findByIdAndDelete(req.params.id);
      res.redirect("/");
    } catch (error) {
      console.error(error);
      res.status(500).send("Internt serverfel");
    }
  }
);

// Starta servern
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
