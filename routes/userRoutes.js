const express = require('express');
const userController = require('../controllers/userController');
const { protect, restrictTo } = require('../middleware/authMiddleware');
const validator = require('../middleware/validator');
const { updateUserValidator } = require('../utils/validators');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting middleware (e.g., max 100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

router.use(limiter);

// Protected routes - all routes require authentication
router.use(protect);

// Routes for logged-in users to manage their own account
router.patch('/me', updateUserValidator, validator, userController.updateMe);
router.delete('/me', userController.deleteMe);

// Admin only routes
router.use(restrictTo('admin'));

// CRUD operations for users (admin only)
router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUser);
router.patch('/:id', updateUserValidator, validator, userController.updateUser);
router.delete('/:id', userController.deleteUser);

module.exports = router;