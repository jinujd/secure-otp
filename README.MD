#Secure OTP#
Storing OTPs as plain text in database is not a secure way, as OTPs are widely used for authenticating users nowadays.
secure-otp provides a better OTP generation methodology which makes OTP theft and OTP manipulation difficult.
##Usage##
secure-otp provides two functions, one for generating the OTP and other for verifying the OTP.
The method generateOtp accepts an identifier as argument and generates an OTP against that identifier. This identifier can be a phone or email or a specific information that is used to identify an entity.

The result of generateOtp is a an object with the following fields.
1. otp - This can be sent to user, via SMS or email or whatever way the application wants to sent
2. hash - This has should be stored in the database
3. secret - This secret should be sent to the client
4. token - This token should be saved in the database.

OTP table in the database shall contain the following fields
1. identifier (Phone, Email etc.)
2. hash - The encrypted value of the hash generated using generateOtp. Suggest to use AES encryption
3. token - The encrypted value of the token generated using generateOtp. Suggest to use AES encryption
4. isVerified - A flag indicating whether OTP is already verified

To verify the OTP, client has to sent the following to the app
1. otp
2. secret
3. identifier

When receiving the info, fetch the record from table matching the specified identifier. 
Then decrypt the token and hash so that we gets the actual value of the token and hash.

Now pass the hash, otp, identifier and secret to verify otp function.
If otp is valid it will return true. Otherwise it will return false.

Advantages of this method are
1. OTP is not stored as plain text in DB
2. OTP expiry is not stored in the database as plain text

##Code for generating OTP##
###Without await###
```javascript
    const {generateOtp} = require(`secure-otp`)
    generateOtp("8594011122", 4).then((otpInfo) => {
        const {identifier, otp, secret, hash, token} = otpInfo 
    }) 
```

###With await###
```javascript
    const {generateOtp} = require(`secure-otp`)
    const otpInfo = await generateOtp("8594011122", 4)
    const {identifier, otp, secret, hash, token} = otpInfo  
```

##Code for verifying OTP## 
###Without await###
```javascript
    const {verifyOtp} = require(`secure-otp`)
    
    verifyOtp(identifier, otp, secret, hash, token).then((isVerified) => {
        console.log(isVerified) //true / false
    }) 
```
###With await###
```javascript
    const {generateOtp} = require(`secure-otp`)
    const isVerified = verifyOtp(identifier, otp, secret, hash, token)
    console.log(isVerified) //true / false   
```
Note: Readme is being updated with better usage documentation..

