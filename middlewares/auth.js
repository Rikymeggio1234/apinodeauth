import jwt from 'jsonwebtoken'
import localStorage from 'localStorage'

export const authenticateToken = (req, res, next) => {
    const authHeader = localStorage.getItem('authToken')
    if(authHeader == ''){
        return res.status(403).json({message: "non autorizzato"})
    } else {
        const token = authHeader && authHeader.split(' ')[1]
        if(token == null) return res.sendStatus(401)
        jwt.verify(token, process.env.JWT_SECRET, (error, user)=>{
            console.log(error)
            if(error) return res.sendStatus(403)
            req.user = user
            next()
        })
    }
}