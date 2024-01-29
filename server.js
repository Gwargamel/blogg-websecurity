//Importerar nödvändiga paket och moduler (de skall finnas angivna i package.json)
//som behövs för att bygga och köra webapplikationen d.v.s. själva bloggen
const helmet = require("helmet"); //Ökar säkerheten med hjälp av HTTP-headers
const express = require("express"); //Ramverk för att skapa webbapplikationer med Node.js
const mongoose = require("mongoose"); //Behövs för att arbeta med databaser i MongoDB
const session = require("express-session"); // Middleware för sessionshantering i Express
const bcrypt = require("bcrypt"); //Krypterar användarnas lösenord genom att hasha dem
const methodOverride = require("method-override"); // Middleware för PUT och DELETE
const MongoStore = require("connect-mongo"); //Används för att lagra sessionsdata

const app = express(); // Skapar en instans av appen express som använder
//middleware-funktioner för att behandla förfrågningar via reg och res
const port = 3000; //Anger porten som appen express ska lyssna på

//Ansluter till databasen (MongoDB) via Mongoose
mongoose.connect("mongodb://localhost/blog", {});

//Konfigurerar användningen av MongoStore för att spara sessionsdata
app.use(
  session({
    secret: "your-secret-key", //Använder en hemlig nyckel signera session-ID-cookie
    resave: false, //Sessionen sparas ej tillbaka till session store
    saveUninitialized: false, //En ny, och ej modifierad, session sparas ej till store
    store: MongoStore.create({
      mongoUrl: "mongodb://localhost/blog", //Adress till Mongo-databasen där sessionsdata skall lagras
      collectionName: "sessions", //Samlingen i MongoDB där sessionsdata sparas
    }),
    cookie: { maxAge: 1000 * 60 * 60 }, //Anger livslängden på cookies (1h)
  })
);

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

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  signature: String,
  isAdmin: { type: Boolean, default: false }, //Fastslår om användaren är admin eller ej
});

const User = mongoose.model("User", userSchema);

//Kontrollerar om en användare har admin-behörighet
const isAdmin = async (req, res, next) => {
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
    //Kontrollerar om userID finns i användarens session
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

app.delete("/delete-post/:id", requireLogin, isAdmin, async (req, res) => {
  //isAdmin undersöker om användaren har admin-behörigheter
  try {
    await Post.findByIdAndDelete(req.params.id);
    res.redirect("/"); //Användaren omdirigeras till startsidan efter att inlägget raderats
  } catch (error) {
    console.error(error);
    res.status(500).send("Internt serverfel"); //Om ett fel uppstår loggas ett felmeddelande i konsollen
  }
});

//Startar servern genom att åkalla variabeln port
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
