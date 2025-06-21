const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const session = require("express-session")
const MongoStore = require("connect-mongo")
const multer = require("multer")
const path = require("path")
const fs = require("fs").promises
const { exec } = require("child_process")
const util = require("util")

const app = express()
const execAsync = util.promisify(exec)

// MongoDB connection
mongoose.connect("", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
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

// Session configuration
app.use(
  session({
    secret: "your-secret-key-here",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: "",
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 24 hours
  }),
)

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = `uploads/${req.session.userId}`
    fs.mkdir(userDir, { recursive: true }).then(() => {
      cb(null, userDir)
    })
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname)
  },
})

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "text/html" || path.extname(file.originalname) === ".html") {
      cb(null, true)
    } else {
      cb(new Error("Only HTML files are allowed!"), false)
    }
  },
})

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next()
  } else {
    res.redirect("/login")
  }
}

// Nginx configuration generator
async function generateNginxConfig(user) {
  let config = ""

  for (const domainObj of user.domains) {
    const domain = domainObj.domain
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

    if (domainObj.sslEnabled) {
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

// SSL certificate generation
async function generateSSLCertificate(domain) {
  try {
    const command = `certbot certonly --nginx -d ${domain} --non-interactive --agree-tos --email admin@${domain}`
    await execAsync(command)
    return true
  } catch (error) {
    console.error("SSL generation failed:", error)
    return false
  }
}

// Routes
app.get("/", (req, res) => {
  if (req.session.userId) {
    res.redirect("/dashboard")
  } else {
    res.sendFile(path.join(__dirname, "public", "index.html"))
  }
})

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"))
})

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"))
})

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId)
    res.sendFile(path.join(__dirname, "public", "dashboard.html"))
  } catch (error) {
    res.status(500).send("Server error")
  }
})

// API Routes
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    })

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({
      username,
      email,
      password: hashedPassword,
    })

    await user.save()

    // Create user directory
    await fs.mkdir(`uploads/${user._id}`, { recursive: true })

    req.session.userId = user._id
    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ error: "Registration failed" })
  }
})

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" })
    }

    req.session.userId = user._id
    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ error: "Login failed" })
  }
})

app.get("/api/user", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select("-password")
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch user data" })
  }
})

app.post("/api/domains", requireAuth, async (req, res) => {
  try {
    const { domain } = req.body
    const user = await User.findById(req.session.userId)

    if (user.domains.length >= 2) {
      return res.status(400).json({ error: "Maximum 2 domains allowed" })
    }

    if (user.domains.some((d) => d.domain === domain)) {
      return res.status(400).json({ error: "Domain already exists" })
    }

    user.domains.push({ domain })
    await user.save()

    // Generate Nginx configuration
    const nginxConfig = await generateNginxConfig(user)
    await fs.writeFile(`/etc/nginx/sites-available/${user._id}`, nginxConfig)

    // Enable site
    try {
      await execAsync(`ln -sf /etc/nginx/sites-available/${user._id} /etc/nginx/sites-enabled/`)
      await execAsync("nginx -t && systemctl reload nginx")
    } catch (error) {
      console.error("Nginx configuration failed:", error)
    }

    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ error: "Failed to add domain" })
  }
})

app.delete("/api/domains/:domain", requireAuth, async (req, res) => {
  try {
    const domain = req.params.domain
    const user = await User.findById(req.session.userId)

    user.domains = user.domains.filter((d) => d.domain !== domain)
    await user.save()

    // Regenerate Nginx configuration
    const nginxConfig = await generateNginxConfig(user)
    await fs.writeFile(`/etc/nginx/sites-available/${user._id}`, nginxConfig)
    await execAsync("nginx -t && systemctl reload nginx")

    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ error: "Failed to delete domain" })
  }
})

app.post("/api/ssl/:domain", requireAuth, async (req, res) => {
  try {
    const domain = req.params.domain
    const user = await User.findById(req.session.userId)

    const domainObj = user.domains.find((d) => d.domain === domain)
    if (!domainObj) {
      return res.status(404).json({ error: "Domain not found" })
    }

    const sslGenerated = await generateSSLCertificate(domain)
    if (sslGenerated) {
      domainObj.sslEnabled = true
      await user.save()

      // Regenerate Nginx configuration with SSL
      const nginxConfig = await generateNginxConfig(user)
      await fs.writeFile(`/etc/nginx/sites-available/${user._id}`, nginxConfig)
      await execAsync("nginx -t && systemctl reload nginx")

      res.json({ success: true })
    } else {
      res.status(500).json({ error: "SSL certificate generation failed" })
    }
  } catch (error) {
    res.status(500).json({ error: "SSL configuration failed" })
  }
})

app.post("/api/upload", requireAuth, upload.array("htmlFiles"), async (req, res) => {
  try {
    res.json({
      success: true,
      files: req.files.map((file) => ({
        filename: file.filename,
        path: file.path,
      })),
    })
  } catch (error) {
    res.status(500).json({ error: "File upload failed" })
  }
})

app.get("/api/files", requireAuth, async (req, res) => {
  try {
    const userDir = `uploads/${req.session.userId}`
    const files = await fs.readdir(userDir)
    const htmlFiles = files.filter((file) => path.extname(file) === ".html")
    res.json(htmlFiles)
  } catch (error) {
    res.json([])
  }
})

app.delete("/api/files/:filename", requireAuth, async (req, res) => {
  try {
    const filename = req.params.filename
    const filePath = `uploads/${req.session.userId}/${filename}`
    await fs.unlink(filePath)
    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ error: "Failed to delete file" })
  }
})

app.post("/api/logout", (req, res) => {
  req.session.destroy()
  res.json({ success: true })
})

const PORT = 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
