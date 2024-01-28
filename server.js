//Importerar nödvändiga paket och moduler (de skall finnas angivna i package.json)
//som behövs för att bygga och köra webapplikationen d.v.s. själva bloggen
const helmet = require("helmet"); //Ökar säkerheten med hjälp av HTTP-headers
const express = require("express"); //Ramverk för att skapa webbapplikationer med Node.js
const mongoose = require("mongoose"); //Behövs för att arbeta med databaser i MongoDB
const session = require("express-session"); // Middleware för sessionshantering i Express
const bcrypt = require("bcrypt"); //Krypterar användarnas lösenord genom att hasha dem
const methodOverride = require("method-override"); // Middleware för PUT och DELETE

const app = express(); // Skapar en instans av appen express som använder
//middleware-funktioner för att behandla förfrågningar via reg och res
const port = 3000; //Anger porten som appen express ska lyssna på

//Ansluter till databasen (MongoDB) via Mongoose
mongoose.connect("mongodb://localhost/blog", {});

// Variabel som definierar blogginläggens struktur
const Post = mongoose.model("Post", {
  title: String,
  content: String, //Titel och innehåll anges i formen av strängar
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User", //Användarnamnet publiceras vid inlägget
  },
  signature: String,
  createdAt: {
    type: Date,
    default: Date.now, //Datum när blogginlägget skapades pupliceras också
  },
});

//Variabel som anger att användarnamn, lösenord och signatur anges i sträng-form
const User = mongoose.model("User", {
  username: String,
  password: String,
  signature: String,
});

// Middleware-inställningar som ökar säkerheten och hanterar klientförfrågningar samt användarsessioner
app.use(helmet()); //Använder HTTP-headers för att förhindra t.ex. XSS-attacker, klickjacking etc
app.use(express.urlencoded({ extended: true })); //Tolkar url-kodad data i POST-förfrågningar
app.use(methodOverride("_method")); //Tillåter användandet av HTTP-metoder som PUT och DELETE där det ej stöds av klient
app.use(
  session({
    secret: "your-secret-key", //Signerar sessions-ID-cookies
    resave: true,
    saveUninitialized: true,
    cookie: { expires: (maxAge = 1000 * 60 * 60) }, //Loggar ut användaren efter 1h: millisek*sek*min
  })
);

//Kontrollerar att användaren är inloggad
const requireLogin = (req, res, next) => {
  //Arrowfunktion som kontrollerar förfrågan (req) och svaret (res)
  if (!req.session.userId) {
    //Kontrollerar omu serID finns i användarens session
    res.redirect("/login"); //Omdirigerar användaren till inloggningssidan
  } else {
    next(); //Callbackfunktion som skickar en inloggad användare vidare till nästa middleware i kedjan
  }
};

//Anger EJS (Embedded javascript) som vy-motor för att rendera HTML-sidor
app.set("view engine", "ejs");
app.use(express.static("public")); //Express hämtar statiska filer (styles.css) från projektmappen public

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

  const user = await User.findOne({ username: username });

  //Bcrypt jämför det angivna lösenordet med det som ligger hashat i databasen
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.userId = user._id;
    res.redirect("/"); // Om användaren angivit korrekt information omdirigeras de till startsidan
  } else {
    res.send("Invalid username or password");
    //res.redirect("/login"); //Om användaren angivit felaktig information omdirigeras de till inloggningssidan igen
  }
});

// /logout-rutten avslutar sessionen och användaren kan inte återgå till sin inloggade sida
//genom att t.ex. klicka på bakåtknappen
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/"); //Användaren skickas tillbaka till startsidan
  });
});

app.get("/", async (req, res) => {
  try {
    let user; // Deklarera variabeln 'user'

    // Kontrollerar om det finns ett 'userId' i sessionen
    if (req.session.userId) {
      // Om 'userId' finns, hämta användaren från databasen
      user = await User.findById(req.session.userId).exec();
    } else {
      // Om det inte finns något 'userId', sätt 'user' till null
      user = null;
    }

    // Hämta alla blogginlägg, sorterade efter skapelsedatum i fallande ordning
    const posts = await Post.find().sort({ createdAt: "desc" }).exec();

    // Rendera sidan med användar- och inläggsdata
    res.render("index", { user: user, posts: posts });
  } catch (error) {
    // Hantera eventuella fel
    console.error(error);
    res.redirect("/");
  }
});

// /create-post-rutten renderar en vy där användaren kan skapa ett blogginlägg
app.get("/create-post", requireLogin, async (req, res) => {
  //Funktionen använder try-catch för att fånga upp eventuella fel
  try {
    const user = req.session.userId
      ? await User.findById(req.session.userId).exec() //Kontrollerar om det finns ett userId i den aktuella sessionen
      : null; //Om användaren ej är inloggad sätts userId till null

    res.render("create-post", { user: user }); //Skickar en HTML-sida till klienten med datan user
  } catch (error) {
    //Fångar upp eventuella fel i de asynkrona operationerna
    console.error(error);
    res.redirect("/"); //Omdirigerar användaren tillbaka till startsidan
  }
});

//Hanterar POST-förfrågan om att skapa nya blogginlägg
app.post("/create-post", requireLogin, async (req, res) => {
  //skapar en route-hanterare för POST-förfrågningar till /create-post.
  //requireLogin är enmiddleware-funktion som körs före den asynkronacallback-funktionen och
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

//Hanterar förfrågningar om att radera blogginlägg
app.delete("/delete-post/:id", requireLogin, async (req, res) => {
  //requireLogin säkerställer att endast inloggade användare kan radera blogginlägg
  try {
    //try-catch används för att fånga upp eventuella fel
    const postId = req.params.id; //hämtar inläggets ID från URL-parametern

    const post = await Post.findOne({
      _id: postId,
      author: req.session.userId,
    }); //Säkerställer att den inloggade användaren är författare till inlägget som skall raderas

    if (!post) {
      res.status(403).send("Forbidden"); //Om ett fel hittas skickas ett felmeddelande
      return;
    }

    await Post.findByIdAndDelete(postId); //Om uppgifterna matchar varandra raderas inlägget från databasen

    res.redirect("/"); //Efter radering omdirigeras användaren tillbaka till startsidan
  } catch (error) {
    //Catch hanterar eventuella fel
    console.error(error); //Ett felmeddelande loggas i konsollen
    res.status(500).send("Internal Server Error"); //Användaren får ett felmeddelande till svar
  }
});

//Startar servern genom att åkalla variabeln port
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
