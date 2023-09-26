const Joi = require('joi');
const User = require('../models/users');
const bcrypt = require('bcrypt');
const UserDTO = require('../dto/user');
const JWTService = require('../services/JWTService');
const RefreshToken = require('../models/token');
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;
const authController = {
    async register(req, res, next) {
        const userRegisterSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            name: Joi.string().max(30).required(),
            // email: Joi.string().email().required(),
            password: Joi.string().pattern(passwordPattern).required(),
            confirmPassword: Joi.ref("password")
        });
        const { error } = userRegisterSchema.validate(req.body);
        if (error) {
            return next(error)
        }
        const { username, name, password } = req.body;
        try {
            // const emailInUse = await User.exists({ email });//

            const usernameInUse = await User.exists({ username });

            // if (emailInUse) {
            //     const error = {
            //         status: 409,
            //         message: "Email already registered, use another email!",
            //     };

            //     return next(error);
            // }

            if (usernameInUse) {
                const error = {
                    status: 409,
                    message: "Username not available, choose another username!",
                };

                return next(error);
            }
        } catch (error) {

            return next(error);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        let accessToken;
        let refreshToken;
        let user;

        try {
            const userToRegister = new User({
                username,
                name,
                password: hashedPassword,
            });

            user = await userToRegister.save();

            // token generation
            accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");

            refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");
        } catch (error) {
            return next(error);
        }

        // store refresh token in db
        await JWTService.storeRefreshToken(refreshToken, user._id);

        // // send tokens in cookie
        res.cookie("accessToken", accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        });

        res.cookie("refreshToken", refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        });

        // 6. response send

        const userDto = new UserDTO(user);

        return res.status(201).json({ user: userDto, auth: true });

    },

    async login(req, res, next) {
        const userLoginSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            password: Joi.string().pattern(passwordPattern).required()
        })
        const { error } = userLoginSchema.validate(req.body)
        if (error) {
            return next(error)
        }
        const { username, password } = req.body;
        let accessToken;
        let refreshToken;
        let user;
        try {
            user = await User.findOne({ username: username })
            if (!user) {
                const error = {
                    status: 401,
                    message: "Invilade User!",
                };
                return next(error);
            }
            const match = await bcrypt.compare(password, user.password)
            if (!match) {
                const error = {
                    status: 401,
                    message: "Password Invilade!",
                };

                return next(error);
            }

        } catch (error) {
            return next(error);
        }

        // token generation
        accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");

        refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");

        // updateToken in db

        try {
            await RefreshToken.updateOne({
                _id: user._id
            }, {
                token: refreshToken
            }, {
                upsert: true
            })

        } catch (error) {
            return next(error)
        }


        // // send tokens in cookie
        res.cookie("accessToken", accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        });

        res.cookie("refreshToken", refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        });
        const userDto = new UserDTO(user);

        return res.status(201).json({ user: userDto, auth: true });

    },
    async logout(req, res, next) {
        const { refreshToken } = req.cookies
        try {
            await RefreshToken.deleteOne({ token: refreshToken });
        } catch (error) {
            return next(error)
        }
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        res.status(200).json({ user: null, auth: false });
    },

    async refresh(req,res,next){
            const orignalRefreshToken=req.cookies.refreshToken;
            let id;
            try {
                id=JWTService.verifyRefreshToken(orignalRefreshToken)._id;
            } catch (error) {
                 error={
                    status:401,
                    message:'unAuth',
                }
                return next(error)
            }

            try {
               const match= await RefreshToken.findOne({_id:id,},{token:orignalRefreshToken});
               if(!match){
                const error={
                    status:401,
                    message:'unAuth',
                }
                return next(error);

               }
            } catch (error) {
                return next(error);
            }
            try {
                const accessToken=JWTService.signAccessToken({_id:id},'30m');
                const refreshToken=JWTService.signRefreshToken({_id:id},'60m');
                await RefreshToken.updateOne({_id:id},{token:refreshToken});
                res.cookie('accessToken',accessToken,{
                    maxAge: 1000 * 60 * 60 * 24,
                    httpOnly: true,
                });
                res.cookie('refreshToken',refreshToken,{
                    maxAge: 1000 * 60 * 60 * 24,
                    httpOnly: true,
                });
            } catch (error) {
                return next(error);
            }
            const user=await User.findOne({_id:id});
            const userDto = new UserDTO(user);
            console.log(userDto);
            return res.status(200).json({user:userDto,auth:true});
    }

}
module.exports = authController
