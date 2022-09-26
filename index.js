import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import dotenv from 'dotenv'

import authRouter from './routes/auth.js'

const app = express()
dotenv.config()

const PORT = process.env.PORT || 3000

app.use(express.json())//per gestire i file json che arrivano dall'esterno
app.use(express.urlencoded({extended: false}))//per gestire i dati ricevuti da form html
app.use(cors())//per collegare il backand al frontand

//gestire le routes
app.get('/', (req, res) => { res.send("<h1>HOMEPAGE</h1>")})
app.use('/', authRouter)

mongoose.connect(process.env.CONNECTION_URL)
    .then(()=>{
        app.listen(PORT, () => {
            console.log(`server running on port: ${PORT}`)
        })    
    })
    .catch(error=>console.error(error))


