const jwt = require('jsonwebtoken');
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = require('../config/index');
const RefeshToken = require('../models/token');

class JWTService {

    static signAccessToken(payLoad, expiryTime) {
        return jwt.sign(payLoad, ACCESS_TOKEN_SECRET, { expiresIn: expiryTime })
    }
    static signRefreshToken(payLoad, expiryTime) {
        return jwt.sign(payLoad, REFRESH_TOKEN_SECRET, { expiresIn: expiryTime })
    }
    static verifyAccessToken(token) {
        return jwt.verify(token, ACCESS_TOKEN_SECRET);
    }
    static verifyRefreshToken(token) {
        return jwt.verify(token, REFRESH_TOKEN_SECRET);
    }
    static async storeRefreshToken(token, userId) {
        try {
            const newToken = new RefeshToken({
                token: token,
                userId: userId
            });

            await newToken.save();

        } catch (error) {
            console.log(error);
        }

    }
}
module.exports = JWTService