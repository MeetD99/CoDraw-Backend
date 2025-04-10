import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import http from "http"; 
import { Server } from "socket.io";

dotenv.config();

const app = express();
app.use(cors({
  origin: "https://co-draw-frontend.vercel.app",
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
const server = http.createServer(app); 
const PORT = process.env.PORT || 5000;
const boardMap = {};
const voiceRooms = {};

const io = new Server(server, {
  cors: {
    origin: 'https://co-draw-frontend.vercel.app',
    credentials: true
  }
});

// Middleware


// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// User Schema & Model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

// Whiteboard Schema & Model
const whiteboardSchema = new mongoose.Schema({
  _id: {
    type: String, 
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  data: {
    type: Object,
    required: true
  },
  previewImage: {
    type: String, 
    default: ''
  },
  createdAt: { type: Date, default: Date.now },
});

const Whiteboard = mongoose.model("Whiteboard", whiteboardSchema);

// JWT Authentication Middleware
const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Authentication Routes
const authRouter = express.Router();

// Signup Route
authRouter.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User created" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login Route
authRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
  });

  res.json({ message: "Login successful", user: { id: user._id, name: user.name } });
});

// Logout Route
authRouter.post("/logout", (req, res) => {
  res.cookie("token", "", { expires: new Date(0), httpOnly: true });
  res.status(200).json({ message: "Logout successful" });
});

// Get Authenticated User Route
authRouter.get("/me", authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// Whiteboard Routes
const whiteboardRouter = express.Router();

// Save Whiteboard
whiteboardRouter.post('/save', authenticateUser, async (req, res) => {
  const { boardId, data, previewImage } = req.body;
  const userId = req.userId;

  if (!boardId || !data) {
    return res.status(400).json({ error: 'Board ID and data are required' });
  }

  try {
      let whiteboard = await Whiteboard.findOne({ _id: boardId, userId });

      if (whiteboard) {
          whiteboard.data = data;
          if (previewImage) whiteboard.previewImage = previewImage;
          await whiteboard.save();
      } else {
          whiteboard = new Whiteboard({ _id: boardId, userId, data, previewImage });
          await whiteboard.save();
      }

      res.status(201).json({ message: 'Whiteboard saved' });
  } catch (error) {
      res.status(400).json({ error: error.message });
  }
});


// Get Whiteboards for Logged-in User
whiteboardRouter.get("/", authenticateUser, async (req, res) => {
  try {
    const whiteboards = await Whiteboard.find({ userId: req.userId });
    res.json(whiteboards);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

whiteboardRouter.delete("/:id", authenticateUser, async (req, res) => {
  try {
    const whiteboard = await Whiteboard.findById(req.params.id);

    if (!whiteboard) {
      return res.status(404).json({ error: "Whiteboard not found" });
    }

    // Ensure the whiteboard belongs to the authenticated user
    if (whiteboard.userId.toString() !== req.userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    await whiteboard.deleteOne();
    res.status(200).json({ message: "Whiteboard deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete whiteboard" });
  }
});

whiteboardRouter.get("/:id", authenticateUser, async (req, res) => {
  try {
    const whiteboard = await Whiteboard.findById(req.params.id);
    if (!whiteboard) {
      return res.status(404).json({ error: "Whiteboard not found" });
    }

    // Check if the whiteboard belongs to the authenticated user
    if (whiteboard.userId.toString() !== req.userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    res.json(whiteboard);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});


io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('join-board', async ({boardId, data, role}) => {
    if(boardId.length == 6){
      const regex = new RegExp(boardId + '$');
      const whiteboard = await Whiteboard.findOne({_id: { $regex: regex }});
      if(whiteboard){
        boardId = whiteboard._id;
      }
    }
    if(role == 'host'){
      boardMap[boardId] = data;
    }
    socket.join(boardId);
    if(role == 'viewer'){
      socket.emit('send-current-data', { data: boardMap[boardId], boardId: boardId });
    }
    console.log(`Socket ${socket.id} joined board ${boardId}`);
  });

  socket.on('canvas-data', ({ boardId, data }) => {
    socket.to(boardId).emit('canvas-data', { boardId, data });
  });

  socket.on('join-voice', ({ boardId, peerId }) => {
    if (!voiceRooms[boardId]) voiceRooms[boardId] = {};

    voiceRooms[boardId][socket.id] = peerId;
    socket.join(`voice-${boardId}`);

    console.log(`${peerId} joined voice in ${boardId}`);

    // Notify all others
    socket.to(`voice-${boardId}`).emit('user-joined-voice', {
      socketId: socket.id,
      peerId
    });

    // Send existing users to the new user
    const existingPeers = Object.entries(voiceRooms[boardId])
      .filter(([id]) => id !== socket.id)
      .map(([id, peerId]) => ({ socketId: id, peerId }));

    socket.emit('all-peers', existingPeers.map(user => user.peerId));
  });

  socket.on('leave-voice', ({ boardId }) => {
    if (voiceRooms[boardId]) {
      const peerId = voiceRooms[boardId][socket.id];
      delete voiceRooms[boardId][socket.id];
      socket.leave(`voice-${boardId}`);
      socket.to(`voice-${boardId}`).emit('user-left-voice', {
        socketId: socket.id,
        peerId,
      });
      console.log(`${peerId} left voice in ${boardId}`);
    }
  });


  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    for (const boardId in voiceRooms) {
      if (voiceRooms[boardId][socket.id]) {
        const peerId = voiceRooms[boardId][socket.id];
        delete voiceRooms[boardId][socket.id];
        socket.to(`voice-${boardId}`).emit('user-left-voice', {
          socketId: socket.id,
          peerId,
        });
      }
    }
  });
});

// Mount Routes
app.use("/api/auth", authRouter);
app.use("/api/whiteboards", whiteboardRouter);


server.listen(PORT, () => console.log(`Server with socket running on port ${PORT}`));
