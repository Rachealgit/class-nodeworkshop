// PACKAGE
const express = require("express");
const app = express();
require("dotenv").config();
const fs = require("fs");
const databaseFile = "./database/db.json";
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// MIDDLEWARES
app.use(express.json());
app.post("/user/sign-up", postUser);
app.post("/user/sign-in", signUserIn);
app.get("/", (req, res) => {
  res.json({ message: "Welcome to MigraCode Auth application." });
});
app.get("/protected", (req, res) => {
  try {
    const token = req.header("x-auth-token");
    jwt.verify(token, process.env.jwtSecret);
  } catch (error) {
    return res.status(401).json({ message: "Access denied!" });
  }

  return res.status(200).json({ message: "You reached a protected endpoint!" });
});

// set port, listen for requests
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
//  console.log(`Server is running on port ${PORT}.`);
});
// FUNCTIONS
async function postUser(req, res) {
  const { name, email, password } = req.body;
  const dbUsers = readUsers();
  const userFromDatabase = dbUsers.find((u) => u.email === email);
  if (userFromDatabase) {
    return res
      .status(400)
      .json({ message: `User with email:${email} already exist!` });
  }

  const salt = await bcrypt.genSalt();
  const encryptedPassword = await bcrypt.hash(password, salt);

  const newDbUser = {
    id: dbUsers.length,
    name,
    email,
    password: encryptedPassword,
  };
  dbUsers.push(newDbUser);
  saveUsers(dbUsers);

  const token = generateJWT(newDbUser.id);

  return res.status(201).json({
    message: "User created successfully!",
    user: {
      id: newDbUser.id,
      name: newDbUser.name,
      email: newDbUser.email,
    },
    jwt: token,
  });
}

async function signUserIn(req, res) {
  const { email, password } = req.body;
  const dbUsers = readUsers();
  const userFromDatabase = dbUsers.find((u) => u.email === email);
  if (!userFromDatabase) {
    return res
      .status(400)
      .json({ message: `User with email:${email} does not exist!` });
  }

  const isValidPassword = await bcrypt.compare(
    password,
    userFromDatabase.password
  );

  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid Password!" });
  }

  const token = generateJWT(userFromDatabase.id);

  return res.status(201).json({
    message: "User logged in successfully!",
    user: {
      id: userFromDatabase.id,
      name: userFromDatabase.name,
      email: userFromDatabase.email,
    },
    jwt: token,
  });
}

function generateJWT(userId) {
  const payload = {
    user: {
      id: userId,
    },
  };

  return jwt.sign(payload, process.env.jwtSecret, { expiresIn: "1h" });
}

function readUsers() {
  const users = fs.readFileSync(databaseFile);
  return JSON.parse(users);
}

function saveUsers(users) {
  const usersAsText = JSON.stringify(users, null, 2);
  fs.writeFileSync(databaseFile, usersAsText);
}