// Importera nödvändiga paket och moduler
const helmet = require("helmet"); // Ökar säkerheten genom att ställa in olika HTTP-headers
const express = require("express"); // Ramverk för att skapa webbapplikationer
const mongoose = require("mongoose"); // Används för att arbeta med MongoDB-databaser
const session = require("express-session"); // Middleware för sessionshantering
const bcrypt = require("bcrypt"); // Används för att kryptera lösenord
const methodOverride = require("method-override"); // Middleware för att stödja PUT och DELETE requests i formulär
const MongoStore = require("connect-mongo"); // Används för att lagra sessionsdata i MongoDB
// const passport = require("passport"); // Används för autentisering (kommenterad eftersom den inte används i den här koden)
// const GitHubStrategy = require("passport-github").Strategy; // GitHub strategi för passport (kommenterad eftersom den inte används i den här koden)

const app = express(); // Skapar en Express-applikation
const port = 3000; // Port som servern kommer att lyssna på

// Anslut till MongoDB-databasen
mongoose.connect("mongodb://localhost/blog", {});

// Konfigurera sessionshantering med MongoStore
app.use(
  session({
    secret: "your-secret-key", // Hemlig nyckel för att signera session-ID-cookies
    resave: false, // Hindrar sessionen från att sparas tillbaka till session store om den inte ändrats
    saveUninitialized: false, // Hindrar omodifierade sessioner från att sparas
    store: MongoStore.create({
      mongoUrl: "mongodb://localhost/blog", // MongoDB URL där sessionsdata lagras
      collectionName: "sessions", // MongoDB-samling där sessionsdata lagras
    }),
    cookie: { maxAge: 1000 * 60 * 60 }, // Sätter max livslängd på cookies (1 timme)
  })
);

// Middleware för ökad säkerhet och hantering av inkommande data
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));

// Ställ in EJS som vy-motor och använd statiska filer från 'public'-mappen
app.set("view engine", "ejs");
app.use(express.static("public"));

// Schema och modell för användare och blogginlägg
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

// Middleware för att kontrollera om en användare har admin-behörighet
const isAdmin = async (req, res, next) => {
  // ... (Koden för isAdmin-middleware här) ...
  //Kontrollerar om en användare har admin-behörighet
  if (!req.session.userId) {
    return res.status(401).send("Du måste vara inloggad");
  }

  try {
    const user = await User.findById(req.session.userId);
    if (user && user.isAdmin) {
      return next(); // Användaren är admin och kan fortsätta
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
  // ... (Koden för requireLogin-middleware här) ...
  //Arrowfunktion som kontrollerar förfrågan (req) och svaret (res)
  if (!req.session.userId) {
    //Kontrollerar om userID finns i användarens session
    res.redirect("/login"); //Omdirigerar användaren till inloggningssidan
  } else {
    next(); //Callbackfunktion som skickar en inloggad användare vidare till nästa middleware i kedjan
  }
};

// Routes för användarregistrering, inloggning, utloggning och skapande av blogginlägg
// ... (Koden för dessa routes här) ...
// /register-rutten renderar en vy där användaren kan skapa ett konto
// via ett formulär
app.get("/register", (req, res) => {
  res.render("register");
});

// Hanterar POST-förfrågningar för registrering av nya användare
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds); //Bcrypt hashar det angivna lösenordet

  //De angivna uppgifterna sparas som en ny användare i databasen
  const newUser = new User({
    username: username,
    password: hashedPassword,
  });

  await newUser.save();

  res.redirect("/"); //När registreringen lyckats blir användaren omdirigerad till inloggningssidan
});

// /login-rutten renderar en inloggningssida
app.get("/login", (req, res) => {
  res.render("login");
});

//Hanterar POST-förfrågningar när en användare vill logga in
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username: username });
    //Bcrypt jämför det angivna lösenordet med det som ligger hashat i databasen
    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.userId = user._id;
      res.redirect("/"); //Om användaren angivit korrekt information omdirigeras de till startsidan
    } else {
      //Om användaren angivit felaktiga inloggningsuppgifter får de ett felmeddelande
      res
        .status(401)
        .send("Du har angivit felaktiga uppgifter. YOU SHALL NOT PASS");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internt serverfel"); //Felmeddelande loggas i konsollen
  }
});

// /logout-rutten avslutar sessionen och användaren kan inte återgå till sin inloggade sida
//igen genom att t.ex. klicka på bakåtknappen
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/"); //Användaren skickas tillbaka till startsidan
  });
});


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
   catch (error) {
    //Catch fångar upp eventuella fel
    console.error(error); //Felmeddelande loggas i konsollen
    res.redirect("/"); //Omdirigerar användaren tillbaka till startsidan
  }

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

// Route för att hantera OAuth-autentisering med GitHub (kan tas bort om inte använd)
app.get("/auth/github", (_req, res) => {
  // ... (Koden för GitHub OAuth-autentisering här) ...
  const authUrl =
    "https://github.com/login/oauth/authorize?client_id=169b8ab064c8f1386757"; //Client ID finns i inställningarna för GitHub.
  res.redirect(authUrl);
});

app.get("/auth/github/callback", async (req, res) => {
  // ... (Koden för GitHub OAuth callback här) ...
  // Hit kommer vi med en kod som kan användas för att bytas mot en token.
  const code = req.query.code;
  // Här får vi själva access_token
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: "b68e6874e5f21942b543",
      client_secret: "", //Din nyckel
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

// Starta servern
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
