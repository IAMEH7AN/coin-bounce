const Joi = require('joi');
const fs = require('fs');
const Blog = require('../models/blog');
const Comment=require('../models/comment');
const { BACKEND_SERVER_PATH } = require('../config/index');
const BlogDTO = require('../dto/blog');
const BlogDetailsDTO = require('../dto/blog-details');
const mongodbIdPattern = /^[0-9a-fA-F]{24}$/;

const blogController = {

    async create(req, res, next) {
        const blogCreateSchema = Joi.object({
            title: Joi.string().required(),
            author: Joi.string().regex(mongodbIdPattern).required(),
            content: Joi.string().required(),
            photo: Joi.string().required(),
        });

        const { error } = blogCreateSchema.validate(req.body);
        if (error) {
            return next(error);
        }
        const { title, author, content, photo } = req.body

        const buffer = Buffer.from(photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ''), 'base64');

        const imagePath = `${Date.now()}-${author}.png`;


        try {
            fs.writeFileSync(`storage/${imagePath}`, buffer);
        } catch (error) {

            return next(error);
        }
        let newBlog;
        try {
            newBlog = new Blog({
                title,
                content,
                photopath: `${BACKEND_SERVER_PATH}/storage/${imagePath}`,
                author,
            });
            await newBlog.save();
        } catch (error) {

            return next(error);
        }
        const blogDto = new BlogDTO(newBlog);

        return res.status(201).json({ blog: blogDto });
    },

    async getAll(req, res, next) {
        try {
            const blogs = await Blog.find({});

            const blogsDto = [];

            for (let i = 0; i < blogs.length; i++) {
                const dto = new BlogDTO(blogs[i]);
                blogsDto.push(dto);
            }

            return res.status(200).json({ blogs: blogsDto });
        } catch (error) {
            return next(error);
        }
    },

    async getById(req, res, next) {

        const getByIdSchema = Joi.object({
            id: Joi.string().regex(mongodbIdPattern).required(),
        });
        const { error } = getByIdSchema.validate(req.params)
        if (error) {
            return next(error)
        }
        const { id } = req.params
        let blog;
        try {
            blog = await Blog.findOne({ _id: id }).populate('author');

        } catch (error) {
            return next(error)
        }
        const blogDto = new BlogDetailsDTO(blog)
        return res.status(201).json({ blog: blogDto })

    },

    async update(req, res, next) {
        const blogUpdateSchema = Joi.object({
            blogid: Joi.string().regex(mongodbIdPattern).required(),
            author: Joi.string().regex(mongodbIdPattern).required(),
            title: Joi.string(),
            content: Joi.string(),
            photo: Joi.string(),
        });
        const { error } = blogUpdateSchema.validate(req.body);
        if (error) {
            return next(error);
        }

        const { blogid, author, title, content, photo } = req.body
        let blog
        try {
            blog = await Blog.findOne({ _id: blogid });
        } catch (error) {
            return next(error);
        }
        if (photo) {
            let previousPhoto = blog.photopath;

            previousPhoto = previousPhoto.split("/").at(-1);

            // delete photo
            fs.unlinkSync(`storage/${previousPhoto}`);

            // read as buffer
            const buffer = Buffer.from(photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ''), 'base64');

            // allot a random name
            const imagePath = `${Date.now()}-${author}.png`;

            // save locally

            try {

                fs.writeFileSync(`storage/${imagePath}`, buffer);
            } catch (error) {
                return next(error);
            }

            await Blog.updateOne(
                { _id: blogid },
                {
                    title,
                    content,
                    photopath: `${BACKEND_SERVER_PATH}/storage/${imagePath}`,
                }
            );
        } else {
            await Blog.updateOne({ _id: blogid }, { title, content });
        }
        return res.status(200).json({ message: "blog updated!" });

    },

    async delete(req, res, next) { 
        const deleteBlogSchema = Joi.object({
            id: Joi.string().regex(mongodbIdPattern).required(),
          });
      
          const { error } = deleteBlogSchema.validate(req.params);
          if(error){
            return next(error);
          }
      
          const { id } = req.params;
      
          // delete blog
          // delete comments
          try {
            await Blog.deleteOne({ _id: id });
      
            await Comment.deleteMany({ blog: id });
          } catch (error) {
            return next(error);
          }
      
          return res.status(200).json({ message: "blog deleted" });
    },

}
module.exports = blogController;