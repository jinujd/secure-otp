const otpGenerator = require('otp-generator') 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); 
const SHA256 = require("crypto-js/sha256");
const generateUniqueString = (length=6, digits = true, upperCaseAlphabets = false, lowerCaseAlphabets = false, specialChars = false) =>  otpGenerator.generate(length, { digits, upperCaseAlphabets, lowerCaseAlphabets, specialChars }); 
const promise = (cb) => new Promise(cb)  
const generateOtp = (phone, length = 6, expiresAtSeconds = 60*5, digits = true, upperCaseAlphabets = false, lowerCaseAlphabets = false, specialChars = false) => promise((resolve, reject) => {
    try {
        const separator = "--"
        const otp = generateUniqueString(length, digits, upperCaseAlphabets, lowerCaseAlphabets, specialChars)
        const secret = SHA256(`${generateUniqueString()}${separator}${phone}${separator}${otp}`).toString()
        const token = jwt.sign({ exp: Math.floor(Date.now() / 1000) + expiresAtSeconds, data: {phone, otp} }, secret)
        const saltRounds = 10
        bcrypt.hash(secret, saltRounds, function(err, hash) {
            if(err) return reject(err)
            resolve({  phone, otp, secret, hash, token })
        }) 
    } catch(err) {
        reject(err)
    }
})

const verifyOtp = (phone, otp, secret, hash, token) => promise((resolve, reject) => {
    try {
        bcrypt.compare(secret, hash, function(err, result) { 
            if(err || !result) return resolve(false)  
            jwt.verify(token, secret,(err, decodedValue) => { 
                if(err || !decodedValue) return resolve(false)
                const {data:{phone: originalPhone, otp: originalOtp}} = decodedValue
                resolve((phone == originalPhone) && (otp == originalOtp))  
            }) 
        }); 
    } catch( err ) {
        reject(err)
    }
})  
module.exports = {  generateOtp, verifyOtp }