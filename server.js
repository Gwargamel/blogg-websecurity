//Importerar nödvändiga paket och moduler (de skall finnas angivna i package.json) som behövs för att bygga och köra webapplikationen d.v.s. själva bloggen
const helmet = require("helmet"); //Ökar säkerheten med hjälp av HTTP-headers
const express = require("express"); //Ramverk för att skapa webbapplikationer med Node.js
const mongoose = require("mongoose"); //Behövs för att arbeta med databaser i MongoDB
const session = require("express-session"); //Middleware för sessionshantering i Express
const bcrypt = require("bcrypt"); //Krypterar användarnas lösenord genom att hasha dem
const methodOverride = require("method-override"); //Middleware för PUT och DELETE
const MongoStore = require("connect-mongo"); //Används för att lagra sessionsdata
const dotenv = require("dotenv"); //Hämtar information om säkerhetsnycklar etc
dotenv.config(); //Laddar över miljövariabler från.env till process.env

const app = express(); //Skapar en instans av appen express som använder middleware-funktioner
//för att behandla förfrågningar via reg och res
const port = 3000; //Anger porten som express ska lyssna på

//Ansluter till databasen (MongoDB) via Mongoose
mongoose.connect("mongodb://localhost/blog", {});

//Konfigurerar användningen av MongoStore för att spara sessionsdata
app.use(
	session({
		secret: "your-secret-key", //Använder en hemlig nyckel för att signera sessions-ID-cookien
		resave: false, //Sessionen sparas ej tillbaka till session store
		saveUninitialized: false, //En ny, och ej modifierad, session sparas ej till store
		store: MongoStore.create({
			mongoUrl: "mongodb://localhost/blog", //Adress till Mongo-databasen där sessionsdata skall lagras
			collectionName: "sessions", //Samlingen i MongoDB där sessionsdata sparas
		}),
		cookie: { maxAge: 1000 * 60 * 60 }, //Anger livslängden på cookies (1h)
	})
);

//Middleware för säkerhet och hantering av inkommande data
app.use(helmet()); //Använder HTTP-headers för att förhindra t.ex. XSS-attacker, klickjacking etc
app.use(express.urlencoded({ extended: true })); //Tolkar url-kodad data i POST-förfrågningar
app.use(methodOverride("_method")); //Tillåter användandet av HTTP-metoder som PUT och DELETE där det ej stöds av klient

//Anger EJS (Embedded javascript) som vy-motor för att rendera HTML-sidor
app.set("view engine", "ejs");
app.use(express.static("public")); //Express hämtar statiska filer (styles.css) från projektmappen public

//Definierar scheman för användare och blogginlägg
const userSchema = new mongoose.Schema({
	username: String,
	password: String,
	signature: String,
	isAdmin: { type: Boolean, default: false },
	//Standardvärdet för admin-behörighet är "har ej"
});
//Skapar en modell baserad på användarschemat
const User = mongoose.model("User", userSchema);

//Definierar blogginläggens struktur
const Post = mongoose.model("Post", {
	title: String,
	content: String, //Titel och innehåll anges i formen av strängar
	author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
	//Användarnamnet publiceras vid inlägget
	signature: String,
	createdAt: { type: Date, default: Date.now },
	//Publicerar datum för när blogginlägget skapades
});

//Middlewarefunktion för att kontrollera admin-behörighet
const isAdmin = async (req, res, next) => {
	if (!req.session.userId) {
		//Undersöker om sessionen har ett användar-ID
		return res.status(401).send("401: Du måste vara inloggad");
		//Om inte returneras en statuskod och ett felmeddelande
	}

	try {
		//Letar efter användarinformation i databasen
		const user = await User.findById(req.session.userId);
		if (user && user.isAdmin) {
			//Kontrollerar att användaren är admin samt har korrekta användaruppgifter
			return next(); //Om Ja = skickas vidare till nästa middleware
		} else {
			return res //Om användaren ej är admin returneras ett felmeddelande
				.status(403)
				.send("403: Endast administratörer har tillgång till denna funktion");
		}
	} catch (error) {
		//Om ett fel uppstår returneras ett felmeddelande
		console.error(error);
		return res.status(500).send("Internt serverfel");
	}
};

// Middleware för att kontrollera om användaren är inloggad
const requireLogin = (req, res, next) => {
	//Arrowfunktion som kontrollerar förfrågan (req) och svaret (res)
	if (!req.session.userId) {
		//Kontrollerar om userID finns i användarens session
		res.redirect("/login"); //Omdirigerar användaren till inloggningssidan
	} else {
		next(); //Callbackfunktion som skickar en inloggad användare vidare till nästa middleware i kedjan
	}
};

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

//Rutt till autentisering via GitHub
app.get("/auth/github", (_req, res) => {
	const authUrl =
		"https://github.com/login/oauth/authorize?client_id=169b8ab064c8f1386757";
	res.redirect(authUrl); //Skickar användaren vidare till GitHubs OAuth-autentiseringssida
});

//Rutt för att hantera GitHubs-inloggningscallback
app.get("/auth/github/callback", async (req, res) => {
	const code = req.query.code; //Hämtar kod från GitHub
	//Anropar GitHub's API för att byta koden mot en access token
	const response = await fetch(
		"https://github.com/login/oauth/access_token", // URL för utbyte av GitHub OAuth-token
		{
			method: "POST",
			body: new URLSearchParams({
				client_id: process.env.GITHUB_CLIENT_ID, //Klient-ID för projektet i GitHub
				client_secret: process.env.GITHUB_CLIENT_SECRET, //Nyckel till projektet i GitHub
				code: code, //Kod som tidigare hämtats från GitHub-inloggning
			}),
			headers: {
				Accept: "application/json", //Svar från GitHub
			},
		}
	);

	const jsonResponse = await response.json(); //Konverterar svaret till JSON-format

	if (jsonResponse.access_token) {
		//Kontrollerar att svaret innehåller en access-token
		const githubUser = await getUserInfoFromGitHub(jsonResponse.access_token); //Hämtar användarinformation från GitHub.

		let user = await User.findOne({ username: githubUser.login }); //Undersöker om användaren redan finns i databasen
		if (!user) {
			//Om användaren ej finns i databasen skapas en ny användare
			user = new User({ username: githubUser.login, password: "" });
			await user.save(); //Sparar användaren i databasen
		}

		req.session.userId = user._id; //Skapar (eller uppdaterar) ett sessions-ID för användaren
		res.redirect("/"); //Omdirigerar användaren till rot-URL
	} else {
		// Om GitHub ej returnerat ett åtkomsttoken visas ett felmeddelande.
		res.send("Fel vid inloggning med GitHub.");
	}
});

//Funktion för att hämta användarinfo från GitHub med hjälp av ett access token
const getUserInfoFromGitHub = async (access_token) => {
	const response = await fetch(
		"https://api.github.com/user", //Skickar en GET-request till GitHubs API för att hämta användarinformation
		{
			headers: {
				Authorization: `Bearer ${access_token}`, //Anger åtkomsttoken i Authorization-headern
			},
		}
	);
	return await response.json(); //Returnerar svaret från GitHub
};

//En Express-route som svarar på GET-förfrågningar till "/user".
app.get("/user", async (req, res) => {
	if (!req.session.access_token) {
		//Kontrollerar om det finns en access token i användarsessionen.
		res.status(403).send("403: Access Denied."); //Om det ej finns returneras ett felmeddelande till klienten
	}
	res.send(await response.json()); //Skickar svar till klienten
});

// Definiera routes för användarregistrering, inloggning, utloggning, och skapande av inlägg
app.get("/register", (req, res) => {
	res.render("register");
});

//En express-rutt som hanterar POST-förfrågningar för registrering av nya användare
app.post("/register", async (req, res) => {
	const { username, password } = req.body;
	const saltRounds = 10; //Antalet saltRounds som används för att salta lösenordet
	const hashedPassword = await bcrypt.hash(password, saltRounds); //Bcrypt hashar det saltade lösenordet

	const newUser = new User({ username, password: hashedPassword }); //Skapar en ny användare med angivet användarnamn och hashat lösenord
	await newUser.save();

	res.redirect("/"); //Sparar användarens uppgifter i databasen
});

//Rutt till inloggningssidan
app.get("/login", (req, res) => {
	res.render("login");
});

//Hanterar POST-förfrågningar när en användare vill logga in
app.post("/login", async (req, res) => {
	const { username, password } = req.body;

	try {
		const user = await User.findOne({ username });
		//Bcrypt jämför det angivna lösenordet med det som ligger hashat i databasen
		if (user && (await bcrypt.compare(password, user.password))) {
			req.session.userId = user._id;
			res.redirect("/"); //Om användaren angivit korrekt information omdirigeras de till sin sida
		} else {
			//Om användaren angivit felaktiga inloggningsuppgifter får de ett felmeddelande
			res.status(401).send("401: Åtkomst nekad (YOU SHALL NOT PASS!)");
		}
	} catch (error) {
		//Fångar upp eventuella fel
		console.error(error);
		res.status(500).send("500: Internt serverfel"); //Felmeddelande loggas i konsollen
	}
});

//Rutt som avslutar sessionen
app.get("/logout", (req, res) => {
	req.session.destroy(() => {
		res.redirect("/"); //Användaren skickas tillbaka till startsidan
	});
});

// /create-post-rutten renderar en vy där användaren kan skapa ett blogginlägg
app.get("/create-post", requireLogin, async (req, res) => {
	//Asyncron-funktion som hanterar inkommande GET-förfrågningar
	//requireLogin kontrollerar att användaren är inloggad vilket krävs för att skriva ett inlägg
	try {
		//Kontrollerar om det finns ett userId i den aktuella sessionen
		const user = req.session.userId //En ternär operator, ? och :, används istället för if-else
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
			throw new Error("User not found"); //Om användare ej hittas uppstår ett fel
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

// Middleware-funktion som kontrollerar om en användare får radera ett inlägg
const canDeletePost = async (req, res, next) => {
	//Undersöker om det finns en användar-ID i sessionen
	if (!req.session.userId) {
		//Om inget ID finns returneras ett felmeddelande
		return res.status(401).send("401: Åtkomst nekad. Du måste vara inloggad");
	}

	try {
		const post = await Post.findById(req.params.id).exec(); //Söker i databasen efter inlägg med det angivna ID't
		const user = await User.findById(req.session.userId); //Hämtar användaruppgifter från databasen

		if (!post) {
			//Om inget inlägg hittas returneras ett felmeddelande
			return res.status(404).send("404: Inlägget hittades inte");
		}

		//Kontrollerar behörighet för radering av inlägg
		if (user.isAdmin || post.author.equals(user._id)) {
			//Undersöker om användaren är admin eller författare till inlägget som skall raderas
			return next();
			//Om ja anropas middlewarefunktionen next
		} else {
			return res //Om nej returneras statuskod 403 och ett felmeddelande
				.status(403)
				.send(
					"403: Ej tillåtet. Du har inte behörighet att radera detta inlägg"
				);
		}
	} catch (error) {
		//Fångar upp eventuella fel
		console.error(error);
		return res.status(500).send("500: Internt serverfel");
	}
};

//Expressrutt för att radera ett inlägg
app.delete(
	"/delete-post/:id",
	requireLogin, //Middleware som kräver att användaren är inloggad
	canDeletePost, //Middleware som kontrollerar om användaren har behörighet att radera inlägget
	async (req, res) => {
		try {
			//Letar upp inlägget med det angivna ID't och raderar
			await Post.findByIdAndDelete(req.params.id);
			res.redirect("/"); //Omdirigerar användaren till rot-URL
		} catch (error) {
			//Fångar upp eventuella fel och loggar dem
			console.error(error);
			res.status(500).send("500: Internt serverfel"); //Returnerar en statuskod för felet
		}
	}
);

//Startar servern
app.listen(port, () => {
	console.log(`Server is running on http://localhost:${port}`);
});
