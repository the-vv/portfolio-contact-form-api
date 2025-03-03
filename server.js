import express from "express"
import sqlite3 from "sqlite3"
import { open } from "sqlite"
import nodemailer from "nodemailer"
import bodyParser from "body-parser"
import session from "express-session"
import bcrypt from "bcrypt"
import path from "path"
import { fileURLToPath } from "url"

process.loadEnvFile()

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const app = express()
const PORT = process.env.PORT || 3000

// Middleware
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, "public")))
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1 hour
  }),
)

// Set up view engine
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

// Database setup
let db
async function setupDatabase() {
  db = await open({
    filename: "./database.sqlite",
    driver: sqlite3.Database,
  })

  await db.exec(`
    CREATE TABLE IF NOT EXISTS submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `)

  // Check if admin user exists, if not create one
  const adminUser = await db.get("SELECT * FROM users WHERE username = ?", [process.env.ADMIN_USER])
  if (!adminUser) {
    const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, 10)
    await db.run("INSERT INTO users (username, password) VALUES (?, ?)", [process.env.ADMIN_USER, hashedPassword])
    console.log("Admin user created")
  }
}

// Email configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

console.log({
  service: process.env.EMAIL_SERVICE,
  port: 587,
  secure: false,
  debug: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.isAuthenticated) {
    return next()
  }
  res.redirect("/login")
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"))
})

// Contact form submission
app.post("/submit", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body

    // Validate input
    if (!name || !email || !message) {
      return res.status(400).json({ success: false, message: "Name, email, and message are required" })
    }

    // Store in database
    await db.run("INSERT INTO submissions (name, email, message) VALUES (?, ?, ?)", [
      name,
      email,
      message,
    ])

    // Send email notification
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_TO,
      subject: `New Contact Form Submission: ${subject || "No Subject"}`,
      text: `
        Name: ${name}
        Email: ${email}
        Message: ${message}
      `,
    }

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error)
      } else {
        console.log("Email sent:", info.response)
      }
    })

    res.status(200).json({ success: true, message: "Form submitted successfully" })
  } catch (error) {
    console.error("Error submitting form:", error)
    res.status(500).json({ success: false, message: "An error occurred while submitting the form" })
  }
})

// Login page
app.get("/login", (req, res) => {
  res.render("login", { error: null })
})

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body

    const user = await db.get("SELECT * FROM users WHERE username = ?", [username])

    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.isAuthenticated = true
      req.session.username = username
      return res.redirect("/dashboard")
    }

    res.render("login", { error: "Invalid username or password" })
  } catch (error) {
    console.error("Login error:", error)
    res.render("login", { error: "An error occurred during login" })
  }
})

app.get("/logout", (req, res) => {
  req.session.destroy()
  res.redirect("/login")
})

// Dashboard
app.get("/dashboard", isAuthenticated, async (req, res) => {
  try {
    const submissions = await db.all("SELECT * FROM submissions ORDER BY created_at DESC")
    res.render("dashboard", {
      submissions,
      username: req.session.username,
    })
  } catch (error) {
    console.error("Dashboard error:", error)
    res.status(500).send("An error occurred while loading the dashboard")
  }
})

// Delete submission
app.post("/delete/:id", isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params
    await db.run("DELETE FROM submissions WHERE id = ?", [id])
    res.redirect("/dashboard")
  } catch (error) {
    console.error("Delete error:", error)
    res.status(500).send("An error occurred while deleting the submission")
  }
})

// Start server
async function startServer() {
  await setupDatabase()
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`)
  })
}

startServer().catch(console.error)

