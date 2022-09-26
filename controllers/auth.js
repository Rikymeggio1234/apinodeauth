import mongoose from 'mongoose'
import { User } from '../models/user.js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { LocalStorage } from 'node-localstorage'

export const registerUser = async (req, res) => {
        const {nome, cognome, email, username, password} = req.body
        if(!nome){
            return res.json({status: 'error', message: 'nome non presente'})
        }else if(typeof nome != "string"){
            return res.json({status: 'error', message: 'nome non valido'})
        }
        if(!cognome || typeof cognome != 'string'){
            return res.json({status: 'error', message: 'cognome non presente o non valido'})
        }
        if(!email || typeof email != 'string'){
            return res.json({status: 'error', message: 'email non presente o non valido'})
        }
        if(!username || typeof username != 'string'){
            return res.json({status: 'error', message: 'username non valido'})        }     
        if(!password || typeof password != 'string'){
            return res.json({status: 'error', message: 'password non valida'})
        }     
        if(password.length <8){
            return res.json({status: 'error', message: 'password troppo corta'})
        }
        const ashedpassword = await bcrypt.hash(password, 10) 
        const user = new User({nome: nome, cognome: cognome, email: email, username: username, password: ashedpassword})
        try{
            await user.save()
            res.status(201).json(user)
        }catch(error){
            res.status(409).json({message: error.message})
        }
}

export const loginUser = async (req, res) => {
    const {username, password} = req.body
    const user = await User.findOne({username})
    if(!user) return res.status(404).json({status: "error", message: "username o password errata"})
    if(await bcrypt.compare(password, user.password)){
        const token = jwt.sign({
            id: user._id,
            username: user.username
        }, process.env.JWT_SECRET)
        let localStorage = new LocalStorage('./scratch'); 
        localStorage.setItem('authToken', `Bearer ${token}`)
        return res.status(200).json({status: "success", message: "loggin avvenuto con successo"})
    }
    res.status(401).json({status: "error", message: "username o password errata"})
}

export const profile = async (req, res) => {
    let localStorage = new LocalStorage('./scratch');
    const authHeader = localStorage.getItem('authToken')
    const token = authHeader && authHeader.split(' ')[1]
    if(token == null) return res.sendStatus(401)
    jwt.verify(token, process.env.JWT_SECRET, (error, user)=>{
        console.log(error)
        if(error) return res.sendStatus(403)
        req.user = user
    })
    let profile = req.user
    const profileTrovato = await User.findOne(profile)
    res.status(200).json(profileTrovato)
}

export const logout = async (req, res) => {
    let localStorage = new LocalStorage('./scratch');
    localStorage.setItem('authToken', 'fuhvuhvuf')
    return res.status(403).json({status: "logout avvenuto", message: "non più autorizzato"})
}