import express from "express";
import path from "path";
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


import { registerUser, loginUser, profile, logout } from "../controllers/auth.js";
import { authenticateToken } from "../middlewares/auth.js";

const authRouter = express.Router()

authRouter.get('/register', (req, res) => {res.sendFile(path.join(__dirname, '../','public', 'register.html'))})

authRouter.post('/register', registerUser)

authRouter.get('/login', (req, res) => {res.sendFile(path.join(__dirname, '../','public', 'login.html'))})

authRouter.post('/login', loginUser)

authRouter.get('/profile', authenticateToken, (req, res) => {res.sendFile(path.join(__dirname, '../','public', 'profile.html'))})

authRouter.get('/profile/dati', authenticateToken, profile)

authRouter.post('/profile', authenticateToken, logout)


export default authRouter;