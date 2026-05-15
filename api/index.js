import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { body, param, query, validationResult } from 'express-validator';

// ─── DB ───────────────────────────────────────────────────────────────────────

let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGO_URI, { dbName: 'task_manager_app' });
  isConnected = true;
  console.log('✅ MongoDB connected');
};

// ─── MODELS ───────────────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema(
  {
    name:     { type: String, required: true, trim: true, minlength: 2, maxlength: 50 },
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 8 },
  },
  { timestamps: true }
);

const User = mongoose.models.User || mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema(
  {
    user:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title:       { type: String, required: true, trim: true, maxlength: 140 },
    description: { type: String, default: '', trim: true, maxlength: 2000 },
    status:      { type: String, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending', index: true },
    priority:    { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium', index: true },
    dueDate:     { type: Date },
  },
  { timestamps: true }
);

taskSchema.index({ title: 'text', description: 'text' });

const Task = mongoose.models.Task || mongoose.model('Task', taskSchema);

// ─── UTILS ────────────────────────────────────────────────────────────────────

const generateToken = (userId, expiresIn = '7d') =>
  jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn });

const sanitizeUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  createdAt: user.createdAt,
});

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: 'Validation failed',
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
};

const protect = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Not authorized. Missing token.' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(401).json({ message: 'Not authorized. User not found.' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ message: 'Not authorized. Invalid token.' });
  }
};

const notFound = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
};

const errorHandler = (err, req, res, _next) => {
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode).json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
  });
};

// ─── APP ──────────────────────────────────────────────────────────────────────

const app = express();

app.use(
  cors({
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.options('*', cors());
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

// Connect DB before every request (cached after first call)
app.use(async (_req, _res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    next(err);
  }
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => res.status(200).json({ message: 'Server is running' }));

app.post(
  '/api/auth/signup',
  [
    body('name').trim().notEmpty().withMessage('Name is required').isLength({ min: 2 }),
    body('email').isEmail().withMessage('Valid email is required').toLowerCase(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  ],
  validate,
  async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Email already in use.' });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hashed });
    const token = generateToken(user._id, process.env.JWT_EXPIRES_IN);
    res.status(201).json({ message: 'Signup successful', token, user: sanitizeUser(user) });
  }
);

app.post(
  '/api/auth/login',
  [
    body('email').isEmail().withMessage('Valid email is required').toLowerCase(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password.' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password.' });
    const token = generateToken(user._id, process.env.JWT_EXPIRES_IN);
    res.status(200).json({ message: 'Login successful', token, user: sanitizeUser(user) });
  }
);

app.get('/api/auth/me', protect, (req, res) => {
  res.status(200).json({ user: req.user });
});

// ─── TASK ROUTES ──────────────────────────────────────────────────────────────

const taskValidation = [
  body('title').optional().trim().notEmpty().withMessage('Title cannot be empty').isLength({ max: 140 }),
  body('description').optional().trim().isLength({ max: 2000 }),
  body('status').optional().isIn(['Pending', 'In Progress', 'Completed']),
  body('priority').optional().isIn(['Low', 'Medium', 'High']),
  body('dueDate').optional().isISO8601().withMessage('Invalid due date'),
];

app.get(
  '/api/tasks',
  protect,
  [
    query('status').optional().isIn(['Pending', 'In Progress', 'Completed']),
    query('priority').optional().isIn(['Low', 'Medium', 'High']),
  ],
  validate,
  async (req, res) => {
    const { status, priority, search = '', sort = '-createdAt' } = req.query;
    const filter = { user: req.user._id };
    if (status) filter.status = status;
    if (priority) filter.priority = priority;
    if (search) filter.$or = [
      { title: { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } },
    ];
    const tasks = await Task.find(filter).sort(sort);
    const stats = {
      total: tasks.length,
      completed: tasks.filter((t) => t.status === 'Completed').length,
      pending: tasks.filter((t) => t.status === 'Pending').length,
      inProgress: tasks.filter((t) => t.status === 'In Progress').length,
    };
    res.status(200).json({ tasks, stats });
  }
);

app.post(
  '/api/tasks',
  protect,
  [body('title').trim().notEmpty().withMessage('Title is required'), ...taskValidation],
  validate,
  async (req, res) => {
    const task = await Task.create({ ...req.body, user: req.user._id });
    res.status(201).json({ message: 'Task created', task });
  }
);

app.get(
  '/api/tasks/:id',
  protect,
  [param('id').isMongoId().withMessage('Invalid task id')],
  validate,
  async (req, res) => {
    const task = await Task.findOne({ _id: req.params.id, user: req.user._id });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    res.status(200).json({ task });
  }
);

app.put(
  '/api/tasks/:id',
  protect,
  [param('id').isMongoId().withMessage('Invalid task id'), ...taskValidation],
  validate,
  async (req, res) => {
    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!task) return res.status(404).json({ message: 'Task not found' });
    res.status(200).json({ message: 'Task updated', task });
  }
);

app.delete(
  '/api/tasks/:id',
  protect,
  [param('id').isMongoId().withMessage('Invalid task id')],
  validate,
  async (req, res) => {
    const task = await Task.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    res.status(200).json({ message: 'Task deleted' });
  }
);

app.use(notFound);
app.use(errorHandler);

export default app;
