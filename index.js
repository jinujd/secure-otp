const otpGenerator = require('otp-generator') 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); 
const SHA256 = require("crypto-js/sha256");
const generateUniqueString = (length=6, digits = true, upperCaseAlphabets = false, lowerCaseAlphabets = false, specialChars = false) =>  otpGenerator.generate(length, { digits, upperCaseAlphabets, lowerCaseAlphabets, specialChars }); 
const promise = (cb) => new Promise(cb)  
const generateOtp = (identifier, length = 6, expiresAtSeconds = 60*5, digits = true, upperCaseAlphabets = false, lowerCaseAlphabets = false, specialChars = false) => promise((resolve, reject) => {
    try {
        const separator = "--"
        const otp = generateUniqueString(length, digits, upperCaseAlphabets, lowerCaseAlphabets, specialChars)
        const secret = SHA256(`${generateUniqueString()}${separator}${identifier}${separator}${otp}`).toString()
        const token = jwt.sign({ exp: Math.floor(Date.now() / 1000) + expiresAtSeconds, data: {identifier, otp} }, secret)
        const saltRounds = 10
        bcrypt.hash(secret, saltRounds, (err, hash) => {
            if(err) return reject(err)
            resolve({  identifier, otp, secret, hash, token })
        }) 
    } catch(err) {
        reject(err)
    }
})

const verifyOtp = (identifier, otp, secret, hash, token) => promise((resolve, reject) => {
    try {
        bcrypt.compare(secret, hash, (err, result) => { 
            if(err || !result) return resolve(false)  
            jwt.verify(token, secret,(err, decodedValue) => { 
                if(err || !decodedValue) return resolve(false)
                const {data:{identifier: originalidentifier, otp: originalOtp}} = decodedValue
                resolve((identifier == originalidentifier) && (otp == originalOtp))  
            }) 
        }) 
    } catch( err ) {
        reject(err)
    }
})  
module.exports = {  generateOtp, verifyOtp }