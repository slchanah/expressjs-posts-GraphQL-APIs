const bcrypt = require('bcryptjs')
const validator = require('validator')
const jwt = require('jsonwebtoken')

const User = require('../models/user')
const Post = require('../models/posts')
const { clearImage } = require('../utils/file')
const user = require('../models/user')

module.exports = {
    createUser: async function ({ userInput }, req) {
        const errors = []
        if (!validator.isEmail(userInput.email)) {
            errors.push({ message: 'E-mail is invalid' })
        }

        if (!validator.isLength(userInput.password.trim(), { min: 5 })) {
            errors.push({ message: 'Password too short' })
        }

        if (errors.length > 0) {
            const error = new Error('Invalid Input')
            error.data = errors
            error.code = 422
            throw error
        }

        const existingUser = await User.findOne({ email: userInput.email })
        if (existingUser) {
            const error = new Error('User already exists')
            throw error
        }

        const hashedPw = await bcrypt.hash(userInput.password, 12)
        const user = new User({
            email: userInput.email,
            password: hashedPw,
            name: userInput.name
        })

        const createdUser = await user.save()
        return { ...createdUser._doc, _id: createdUser._id.toString() }
    },
    async login({ email, password }, req) {
        const user = await User.findOne({ email })
        if (!user) {
            const error = new Error('User not found')
            error.code = 401
            throw error
        }

        const isEqual = await bcrypt.compare(password, user.password)
        if (!isEqual) {
            const error = new Error('Password is incorrect')
            error.code = 401
            throw error
        }

        const token = jwt.sign({
            userId: user._id.toString(),
            email: user.email
        },
            'supersecretcode',
            { expiresIn: '1h' })

        return { token, userId: user._id.toString() }
    },
    async createPost({ postInput }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const errors = []
        if (!validator.isLength(postInput.title.trim(), { min: 5 })) {
            errors.push({ message: 'Invalid title' })
        }
        if (!validator.isLength(postInput.content.trim(), { min: 5 })) {
            errors.push({ message: 'Invalid Content' })
        }
        if (errors.length > 0) {
            const error = new Error('Invalid Input')
            error.data = errors
            error.code = 422
            throw error
        }

        const user = await User.findById(req.userId)
        if (!user) {
            const error = new Error('Invalid user')
            error.code = 401
            throw error
        }

        const post = new Post({
            title: postInput.title,
            content: postInput.content,
            imageUrl: postInput.imageUrl,
            creator: user
        })
        const createdPost = await post.save()
        user.posts.push(createdPost)
        await user.save()

        return {
            ...createdPost._doc,
            _id: post._id.toString(),
            createdAt: createdPost.createdAt.toISOString(),
            updatedAt: createdPost.updatedAt.toISOString()
        }
    },
    async posts({ page }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        if (!page) {
            page = 1
        }

        const perPage = 2
        const totalPosts = await Post.find().countDocuments()
        const posts = await Post.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * perPage)
            .limit(perPage)
            .populate('creator')

        return {
            posts: posts.map(p => {
                return {
                    ...p._doc,
                    _id: p._id.toString(),
                    createdAt: p.createdAt.toISOString(),
                    updatedAt: p.updatedAt.toISOString()
                }
            }),
            totalPosts
        }
    },
    async post({ id }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const post = await Post.findById(id).populate('creator')
        if (!post) {
            const error = new Error('Post not found')
            error.code = 404
            throw error
        }

        return {
            ...post._doc,
            _id: post._id.toString(),
            createdAt: post.createdAt.toISOString(),
            updatedAt: post.updatedAt.toISOString()
        }
    },
    async updatePost({ id, postInput }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const post = await Post.findById(id).populate('creator')
        if (!post) {
            const error = new Error('Post not found')
            error.code = 404
            throw error
        }

        if (post.creator._id.toString() !== req.userId) {
            const error = new Error('Not authorized')
            error.code = 403
            throw error
        }

        const errors = []
        if (!validator.isLength(postInput.title.trim(), { min: 5 })) {
            errors.push({ message: 'Invalid title' })
        }
        if (!validator.isLength(postInput.content.trim(), { min: 5 })) {
            errors.push({ message: 'Invalid Content' })
        }
        if (errors.length > 0) {
            const error = new Error('Invalid Input')
            error.data = errors
            error.code = 422
            throw error
        }

        post.title = postInput.title
        post.content = postInput.content
        if (postInput.imageUrl !== 'undefined') {
            post.imageUrl = postInput.imageUrl
        }

        const updatedPost = await post.save()

        return {
            ...updatedPost._doc,
            _id: updatedPost._id.toString(),
            createdAt: updatedPost.createdAt.toISOString(),
            updatedAt: updatedPost.updatedAt.toISOString()
        }
    },
    async deletePost({ id }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const post = await Post.findById(id)
        if (!post) {
            const error = new Error('Post not found')
            error.code = 404
            throw error
        }

        if (post.creator.toString() !== req.userId) {
            const error = new Error('Not authorized')
            error.code = 403
            throw error
        }

        clearImage(post.imageUrl)
        await Post.findByIdAndDelete(id)

        const user = await User.findById(req.userId)
        user.posts.pull(id)
        await user.save()

        return true
    },
    async user(_, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const user = await User.findById(req.userId)
        if (!user) {
            const error = new Error('User not found')
            error.code = 404
            throw error
        }

        return {
            ...user._doc,
            _id: user._id.toString()
        }
    },
    async updateStatus({ status }, req) {
        if (!req.isAuth) {
            const error = new Error('Not Authenticated')
            error.code = 401
            throw error
        }

        const user = await User.findById(req.userId)
        if (!user) {
            const error = new Error('User not found')
            error.code = 404
            throw error
        }

        user.status = status
        await user.save()

        return {
            ...user._doc,
            _id: user._id.toString()
        }
    }
}