import jwt from 'jsonwebtoken'
import localStorage from 'localStorage'

export const authenticateToken = (req, res, next) => {
    const authHeader = localStorage.getItem('authToken')
    if(authHeader == ''){
        return res.status(401).json({status: "error", message: "non autorizzato"})
    } else {
        const token = authHeader && authHeader.split(' ')[1]
        if(token == null) return res.status(401).json({status: "error", message: "non autorizzato"})
        jwt.verify(token, process.env.JWT_SECRET, (error, user)=>{
            console.log(error)
            if(error) return res.status(403).json({status: "error", message: "non autorizzato"})
            req.user = user
            next()
        })
    }
}