const express = require('express');
const router = express.Router();
const auth = require('../middlewares/auth');
const authController = require('../controller/authController');
const blogController=require('../controller/blogController');
const commentController=require('../controller/commentController');

//test case
router.get('/test', (req, res) => {
    res.send('Hello World!testing');
})

// user routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', auth, authController.logout);
router.get('/refresh',authController.refresh);

// blog routes
router.post('/blog',auth,blogController.create);
router.get('/blog/all',auth,blogController.getAll);
router.get('/blog/:id',auth,blogController.getById);
router.put('/blog',auth,blogController.update);
router.delete('/blog/:id',auth,blogController.delete);

//comments routes
router.post('/comment',auth,commentController.create);
router.get('/comment/:id',auth,commentController.getById);

module.exports = router