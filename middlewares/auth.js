import jwt from 'jsonwebtoken'
import { LocalStorage } from 'node-localstorage'

export const authenticateToken = (req, res, next) => {
    let localStorage = new LocalStorage('./scratch');
    const authHeader = localStorage.getItem('authToken')
    const token = authHeader && authHeader.split(' ')[1]
    if(token == null) return res.sendStatus(401)
    jwt.verify(token, process.env.JWT_SECRET, (error, user)=>{
        console.log(error)
        if(error) return res.sendStatus(403)
        req.user = user
        next()
    })
}