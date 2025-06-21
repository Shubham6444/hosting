require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const session = require("express-session")
const MongoStore = require("connect-mongo")
const multer = require("multer")
const path = require("path")
const fs = require("fs").promises
const fssync = require("fs")
const { exec } = require("child_process")
const util = require("util")

const app = express()
const execAsync = util.promisify(exec)

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

// Schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  domains: [
    {
      domain: String,
      sslEnabled: { type: Boolean, default: false },
      createdAt: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
})
const User = mongoose.model("User", userSchema)

// Middleware
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static("public"))
app.use("/uploads", express.static("uploads"))

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { maxAge: 86400000 }, // 24 hours
  })
)

// Multer upload
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const userDir = `uploads/${req.session.userId}`
    await fs.mkdir(userDir, { recursive: true })
    cb(null, userDir)
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname)
  },
})

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "text/html" || path.extname(file.originalname) === ".html") cb(null, true)
    else cb(new Error("Only HTML files allowed"), false)
  },
})

// Auth middleware
const requireAuth = (req, res, next) => {
  req.session.userId ? next() : res.redirect("/login")
}

// Nginx config generator
async function generateNginxConfig(user) {
  let config = ""
  for (const { domain, sslEnabled } of user.domains) {
    const userDir = path.join(__dirname, "uploads", user._id.toString())

    config += `
server {
    listen 80;
    server_name ${domain};

    location / {
        root ${userDir};
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    location ~ /\.ht {
        deny all;
    }
}
`

    if (sslEnabled) {
      config += `
server {
    listen 443 ssl;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    location / {
        root ${userDir};
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    location ~ /\.ht {
        deny all;
    }
}
`
    }
  }
  return config
}

// SSL certificate via Certbot
async function generateSSLCertificate(domain) {
  const email = process.env.CERTBOT_EMAIL
  const command = `sudo certbot certonly --nginx -d ${domain} --non-interactive --agree-tos --email ${email}`
  try {
    await execAsync(command)
    return true
  } catch (error) {
    console.error("❌ SSL generation error:", error.stderr || error)
    return false
  }
}

// Routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", req.session.userId ? "dashboard.html" : "index.html")))
app.get("/register", (_, res) => res.sendFile(path.join(__dirname, "public", "register.html")))
app.get("/login", (_, res) => res.sendFile(path.join(__dirname, "public", "login.html")))

app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body
    const exists = await User.findOne({ $or: [{ username }, { email }] })
    if (exists) return res.status(400).json({ error: "User already exists" })

    const user = await User.create({
      username,
      email,
      password: await bcrypt.hash(password, 10),
    })

    await fs.mkdir(`uploads/${user._id}`, { recursive: true })
    req.session.userId = user._id
    res.json({ success: true })
  } catch (e) {
    res.status(500).json({ error: "Registration failed" })
  }
})

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email })
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: "Invalid credentials" })
  }
  req.session.userId = user._id
  res.json({ success: true })
})

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }))
})

app.get("/api/user", requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId).select("-password")
  res.json(user)
})

app.post("/api/domains", requireAuth, async (req, res) => {
  const { domain } = req.body
  const user = await User.findById(req.session.userId)

  if (user.domains.length >= 2) return res.status(400).json({ error: "Max 2 domains allowed" })
  if (user.domains.some((d) => d.domain === domain)) return res.status(400).json({ error: "Domain already added" })

  user.domains.push({ domain })
  await user.save()

  const config = await generateNginxConfig(user)
  const configPath = `/etc/nginx/sites-available/${user._id}`
  await fs.writeFile(configPath, config)
  await execAsync(`ln -sf ${configPath} /etc/nginx/sites-enabled/${user._id}`)
  await execAsync("sudo nginx -t && sudo systemctl reload nginx")

  res.json({ success: true })
})

app.delete("/api/domains/:domain", requireAuth, async (req, res) => {
  const domain = req.params.domain
  const user = await User.findById(req.session.userId)
  user.domains = user.domains.filter((d) => d.domain !== domain)
  await user.save()

  const config = await generateNginxConfig(user)
  await fs.writeFile(`/etc/nginx/sites-available/${user._id}`, config)
  await execAsync("sudo nginx -t && sudo systemctl reload nginx")

  res.json({ success: true })
})

app.post("/api/ssl/:domain", requireAuth, async (req, res) => {
  const domain = req.params.domain
  const user = await User.findById(req.session.userId)
  const domainObj = user.domains.find((d) => d.domain === domain)
  if (!domainObj) return res.status(404).json({ error: "Domain not found" })

  if (await generateSSLCertificate(domain)) {
    domainObj.sslEnabled = true
    await user.save()
    const config = await generateNginxConfig(user)
    await fs.writeFile(`/etc/nginx/sites-available/${user._id}`, config)
    await execAsync("sudo nginx -t && sudo systemctl reload nginx")
    res.json({ success: true })
  } else {
    res.status(500).json({ error: "SSL generation failed" })
  }
})

app.post("/api/upload", requireAuth, upload.array("htmlFiles"), (req, res) => {
  res.json({
    success: true,
    files: req.files.map(({ filename, path }) => ({ filename, path })),
  })
})

app.get("/api/files", requireAuth, async (req, res) => {
  try {
    const dir = `uploads/${req.session.userId}`
    const files = await fs.readdir(dir)
    res.json(files.filter((f) => path.extname(f) === ".html"))
  } catch {
    res.json([])
  }
})

app.delete("/api/files/:filename", requireAuth, async (req, res) => {
  try {
    await fs.unlink(`uploads/${req.session.userId}/${req.params.filename}`)
    res.json({ success: true })
  } catch {
    res.status(500).json({ error: "Failed to delete file" })
  }
})

// Start server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`)
})
