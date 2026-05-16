import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { body, param, query, validationResult } from 'express-validator';

// ─────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────

const MONGO_URI =
  'mongodb+srv://akashkumarhzb121_db_user:akash123@kanbanbackend.uueuwje.mongodb.net/?appName=kanbanbackend';

const JWT_SECRET = 'akash123';

const PORT = 5000;

// ─────────────────────────────────────────────────────────────
// DB CONNECTION
// ─────────────────────────────────────────────────────────────

const connectDB = async () => {
  try {
    if (mongoose.connections[0].readyState) {
      console.log('MongoDB already connected');
      return;
    }
    await mongoose.connect(MONGO_URI, { dbName: 'task_manager_app' });
    console.log('MongoDB Connected');
  } catch (error) {
    console.error('MongoDB Connection Error:', error);
    process.exit(1);
  }
};

// ─────────────────────────────────────────────────────────────
// MODELS
// ─────────────────────────────────────────────────────────────

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
    user:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title:       { type: String, required: true, trim: true, maxlength: 140 },
    description: { type: String, default: '', trim: true, maxlength: 2000 },
    status:      { type: String, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending' },
    priority:    { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium' },
    dueDate:     { type: Date },
  },
  { timestamps: true }
);

taskSchema.index({ title: 'text', description: 'text' });

const Task = mongoose.models.Task || mongoose.model('Task', taskSchema);

// ─────────────────────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────────────────────

const generateToken = (userId) =>
  jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

const sanitizeUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  createdAt: user.createdAt,
});

// ─────────────────────────────────────────────────────────────
// VALIDATION MIDDLEWARE
// ─────────────────────────────────────────────────────────────

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  next();
};

// ─────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────

const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Unauthorized. No token.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// ─────────────────────────────────────────────────────────────
// SHARED TASK FIELD VALIDATORS  (optional — used in PUT)
// ─────────────────────────────────────────────────────────────

const optionalTaskValidation = [
  body('title')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Title cannot be blank'),

  body('status')
    .optional()
    .isIn(['Pending', 'In Progress', 'Completed'])
    .withMessage('Invalid status value'),

  body('priority')
    .optional()
    .isIn(['Low', 'Medium', 'High'])
    .withMessage('Invalid priority value'),
];

// ─────────────────────────────────────────────────────────────
// APP SETUP
// ─────────────────────────────────────────────────────────────

const app = express();

connectDB();

app.use(
  cors({
    origin: ['http://localhost:5173', 'http://localhost:3000','https://kanbann-sandy.vercel.app/'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  })
);

app.options('/{*path}', cors());
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

// ─────────────────────────────────────────────────────────────
// ROOT & HEALTH
// ─────────────────────────────────────────────────────────────

app.get('/', (_req, res) =>
  res.status(200).json({ success: true, message: 'Kanban Backend Running Successfully' })
);

app.get('/api/health', (_req, res) =>
  res.status(200).json({ success: true, message: 'Server is healthy' })
);

// ─────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────

// SIGNUP
app.post(
  '/api/auth/signup',
  [
    body('name').trim().notEmpty().withMessage('Name required'),
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 chars'),
  ],
  validate,
  async (req, res) => {
    try {
      const { name, email, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ success: false, message: 'Email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = await User.create({ name, email, password: hashedPassword });
      const token = generateToken(user._id);

      res.status(201).json({
        success: true,
        message: 'Signup successful',
        token,
        user: sanitizeUser(user),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// LOGIN
app.post(
  '/api/auth/login',
  [
    body('email').isEmail().withMessage('Valid email required'),
    body('password').notEmpty().withMessage('Password required'),
  ],
  validate,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = generateToken(user._id);

      res.status(200).json({
        success: true,
        message: 'Login successful',
        token,
        user: sanitizeUser(user),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// GET CURRENT USER
app.get('/api/auth/me', protect, (req, res) =>
  res.status(200).json({ success: true, user: req.user })
);

// ─────────────────────────────────────────────────────────────
// TASK ROUTES
// ─────────────────────────────────────────────────────────────

// GET ALL TASKS
app.get(
  '/api/tasks',
  protect,
  [
    query('status').optional().isIn(['Pending', 'In Progress', 'Completed']),
    query('priority').optional().isIn(['Low', 'Medium', 'High']),
  ],
  validate,
  async (req, res) => {
    try {
      const { status, priority, search = '' } = req.query;

      const filter = { user: req.user._id };
      if (status)   filter.status   = status;
      if (priority) filter.priority = priority;
      if (search) {
        filter.$or = [
          { title:       { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
        ];
      }

      const tasks = await Task.find(filter).sort({ createdAt: -1 });
      res.status(200).json({ success: true, tasks });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// CREATE TASK
app.post(
  '/api/tasks',
  protect,
  [
    body('title').trim().notEmpty().withMessage('Title required'),
    ...optionalTaskValidation,
  ],
  validate,
  async (req, res) => {
    try {
      const task = await Task.create({ ...req.body, user: req.user._id });
      res.status(201).json({ success: true, message: 'Task created', task });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// UPDATE TASK
app.put(
  '/api/tasks/:id',
  protect,
  [
    param('id').isMongoId().withMessage('Invalid task ID'),
    ...optionalTaskValidation,
  ],
  validate,
  async (req, res) => {
    try {
      const task = await Task.findOneAndUpdate(
        { _id: req.params.id, user: req.user._id },
        req.body,
        { new: true, runValidators: true }
      );

      if (!task) {
        return res.status(404).json({ success: false, message: 'Task not found' });
      }

      res.status(200).json({ success: true, message: 'Task updated', task });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// DELETE TASK
app.delete(
  '/api/tasks/:id',
  protect,
  [param('id').isMongoId().withMessage('Invalid task ID')],
  validate,
  async (req, res) => {
    try {
      const task = await Task.findOneAndDelete({
        _id: req.params.id,
        user: req.user._id,
      });

      if (!task) {
        return res.status(404).json({ success: false, message: 'Task not found' });
      }

      res.status(200).json({ success: true, message: 'Task deleted' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// ─────────────────────────────────────────────────────────────
// 404 HANDLER
// ─────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.originalUrl} not found` });
});

// ─────────────────────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err);
  res.status(500).json({ success: false, message: err.message });
});

// ─────────────────────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

export default app;
