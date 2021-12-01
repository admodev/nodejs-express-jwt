require("dotenv").config();
require("./config/database").connect();

const User = require("./model/user");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");

const app = express();

app.use(express.json());

app.get("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome! 🙌");
});

app.post("/register", async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    // Validate user input
    if (!(first_name && last_name && email && password)) {
      res.status(400).send("All inputs are required!");
    }

    // Check if user already exists in database
    const registeredUser = await User.findOne({ email });

    if (registeredUser) {
      return res.status(409).send("User already exits, please login...");
    }

    // Encrypt user password
    const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(), // Sanitize email to lowerCase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      {
        user_id: user._id,
        email,
      },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );

    // Save user token
    user.token = token;

    res.status(201).json(user);
  } catch (error) {
    console.error(error);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exists in database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
});

module.exports = app;
