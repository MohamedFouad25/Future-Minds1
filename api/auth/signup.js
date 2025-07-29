import dbConnect from '../../utils/db.js';
import User from '../../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ message: 'Method Not Allowed' });

  await dbConnect();

  const { fullName, email, governorate, password, confirmPassword, role, adminCode } = req.body;

  if (!fullName || !email || !governorate || !password || !confirmPassword || !role) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  if (role === 'admin' && adminCode !== process.env.ADMIN_CODE) {
    return res.status(403).json({ message: 'Invalid admin code' });
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(409).json({ message: 'Email already registered' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = await User.create({
    fullName,
    email,
    governorate,
    password: hashedPassword,
    role
  });

  const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({
    message: 'Signup successful',
    token,
    user: {
      id: newUser._id,
      fullName: newUser.fullName,
      email: newUser.email,
      role: newUser.role
    }
  });
}
