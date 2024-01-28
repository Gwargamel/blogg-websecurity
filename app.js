//Importerar nödvändiga paket och moduler (de skall finnas angivna i package.json)
//som behövs för att bygga och köra webapplikationen d.v.s. själva bloggen
const express = require("express"); //Skapar webservern
const mongoose = require("mongoose"); //Behövs för arbetet med databasen MongoDB
const session = require("express-session"); //Hanterar sessioner
const bcrypt = require("bcrypt"); //Krypterar användarnas lösenord
const path = require("path");

const app = express(); // Skapar en instans av appen express som använder
//middleware-funktioner för att behandla förfrågningar via reg och res
const port = 3000; //Anger porten appen express ska lyssna på

//Ansluter till databasen (MongoDB) via Mongoose
mongoose.connect("mongodb://localhost:27017/blog", {
  useNewUrlParser: true, //Anslutningsparameter som används för att undvika äldre funktioner
  useUnifiedTopology: true, //Säkerställer en förbättrad kommunikation mellan mongoose och mongoDB
});
const db = mongoose.connection;

//Hanterar anslutningsproblem i MongoDB
db.on("error", console.error.bind(console, "MongoDB connection error:")); //Skriver ut felmeddelande i konsollen
db.once("open", () => console.log("Connected to MongoDB")); //Skriver ut meddelande som bekräftar lyckad anslutning i konsollen

app.use(express.urlencoded({ extended: true })); //Hanterar URL-kodning av formulärdata
app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true }) //Konfigurerar sessionen
  //som lagrar användarinformation mellan förfrågningar.
);

//Ange EJS som vy-motor och anger projektmappen "views" som sökväg till de olika vyerna
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

//Skapar en Mongoose-modell som definierar strukturen för användarobjekt i databasen.
const User = mongoose.model("User", {
  username: String,
  password: String,
});

//Expressrutten "/" renderar startsidan via en vy som heter index
app.get("/", (req, res) => {
  const user = req.session.user;
  res.render("index", { user });
});

// /login-rutten renderar en inloggningssida
app.get("/login", (req, res) => {
  res.render("login");
});

//Hanterar POST-förfrågningar när en användare vill logga in
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  //Bcrypt jämför det angivna lösenordet med det som ligger hashat i databasen
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.user = { username: user.username };
    res.redirect("/"); // Om användaren angivit korrekt information loggas de in till startsidan
  } else {
    res.send("Invalid username or password"); //Om användaren angivit felaktig information får de ett felmeddelande
  }
});

// /register-rutten renderar en vy där användaren kan skapa ett konto
// via ett formulär
app.get("/register", (req, res) => {
  res.render("register");
});

// Hanterar POST-förfrågningar för registrering av nya användare
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); //Bcrypt hashar det angivna lösenordet

  //De angivna uppgifterna sparas som en ny användare i databasen
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.redirect("/login"); //När registreringen lyckats blir användaren skickad till inloggningssidan
});

// /create-post-rutten renderar en vy där användaren kan skapa ett blogginlägg
//via ett formulär
app.get("/create-post", (req, res) => {
  const user = req.session.user;

  //Endast inloggade användare kan skapa nya bloginlägg.
  if (user) {
    res.render("create-post");
  } else {
    res.redirect("/login"); //Om användaren ej är inloggad skickas h*n till inloggningssidan
  }
});

//Hanterar POST-förfrågan om att skapa ett nytt blogginlägg
//När användaren klickar på knappen för att skapa inlägg skickas h*n till sin bloggsida
//där inlägget blivit publicerat
app.post("/create-post", (req, res) => {
  res.send("Post created successfully"); //Inlägget kan sparas i databasen
});

// /logout-rutten avslutar sessionen och användaren kan inte återgå till sin inloggade sida
//genom att t.ex. klicka på bakåtknappen
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/"); //Användaren skickas tillbaka till startsidan
});

//Startar servern genom att åkalla variabeln port
app.listen(port, () =>
  console.log(`Server is running on http://localhost:${port}`)
);
