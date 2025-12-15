
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'admin'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Enquiry Schema (same as before)
const enquirySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  company: {
    type: String,
    trim: true
  },
  enquiry: {
    type: String,
    required: true,
    trim: true
  },
  source: {
    type: String,
    default: 'Website Form'
  },
  status: {
    type: String,
    enum: ['pending', 'contacted', 'resolved'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Enquiry = mongoose.model('Enquiry', enquirySchema);

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || "Axora@21";

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1] || req.cookies?.auth_token;

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};




// Initialize Admin User
const initializeAdmin = async () => {
  try {
    const adminExists = await User.findOne({ username: 'Pranil' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('pass@123', 10);
      await User.create({
        username: 'Pranil',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('✅ Admin user created: Pranil / pass@123');
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

// Admin Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Set cookie with token
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during login'
    });
  }
});

// Get Current User
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Server error'
    });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// ============= PROTECTED ENQUIRY ROUTES =============

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Axora Backend is running',
    timestamp: new Date().toISOString()
  });
});

// 1. Create New Enquiry (Public)
app.post('/api/enquiries', async (req, res) => {
  try {
    const { name, email, phone, company, enquiry } = req.body;
    
    if (!name || !email || !phone || !enquiry) {
      return res.status(400).json({
        success: false,
        error: 'Please provide all required fields'
      });
    }
    
    const newEnquiry = new Enquiry({
      name,
      email,
      phone,
      company: company || '',
      enquiry,
      source: 'CTA Section'
    });
    
    await newEnquiry.save();
    
    res.status(201).json({
      success: true,
      message: 'Enquiry submitted successfully!',
      data: newEnquiry
    });
    
  } catch (error) {
    console.error('Error saving enquiry:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to save enquiry'
    });
  }
});

// 2. Get All Enquiries (Protected - Admin Only)
app.get('/api/enquiries', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const { 
      status, 
      search,
      sort = '-createdAt',
      page = 1,
      limit = 50
    } = req.query;
    
    let query = {};
    
    if (status && status !== 'all') {
      query.status = status;
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { company: { $regex: search, $options: 'i' } },
        { enquiry: { $regex: search, $options: 'i' } }
      ];
    }
    
    const enquiries = await Enquiry.find(query)
      .sort(sort)
      .limit(parseInt(limit));
    
    const total = await Enquiry.countDocuments();
    const pending = await Enquiry.countDocuments({ status: 'pending' });
    const contacted = await Enquiry.countDocuments({ status: 'contacted' });
    const resolved = await Enquiry.countDocuments({ status: 'resolved' });
    
    res.json({
      success: true,
      count: enquiries.length,
      total,
      stats: {
        pending,
        contacted,
        resolved,
        total
      },
      data: enquiries
    });
    
  } catch (error) {
    console.error('Error fetching enquiries:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch enquiries'
    });
  }
});

// 3. Get Single Enquiry (Protected)
app.get('/api/enquiries/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const enquiry = await Enquiry.findById(req.params.id);
    
    if (!enquiry) {
      return res.status(404).json({
        success: false,
        error: 'Enquiry not found'
      });
    }
    
    res.json({
      success: true,
      data: enquiry
    });
    
  } catch (error) {
    console.error('Error fetching enquiry:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch enquiry'
    });
  }
});

// 4. Update Enquiry Status (Protected)
app.patch('/api/enquiries/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const { status } = req.body;
    
    if (!['pending', 'contacted', 'resolved'].includes(status)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid status'
      });
    }
    
    const enquiry = await Enquiry.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!enquiry) {
      return res.status(404).json({
        success: false,
        error: 'Enquiry not found'
      });
    }
    
    res.json({
      success: true,
      message: `Enquiry status updated to ${status}`,
      data: enquiry
    });
    
  } catch (error) {
    console.error('Error updating enquiry:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update enquiry'
    });
  }
});

// 5. Delete Enquiry (Protected)
app.delete('/api/enquiries/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const enquiry = await Enquiry.findByIdAndDelete(req.params.id);
    
    if (!enquiry) {
      return res.status(404).json({
        success: false,
        error: 'Enquiry not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Enquiry deleted successfully'
    });
    
  } catch (error) {
    console.error('Error deleting enquiry:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete enquiry'
    });
  }
});

// 6. Export Enquiries as CSV (Protected)
app.get('/api/enquiries/export/csv', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const enquiries = await Enquiry.find().sort('-createdAt');
    
    if (enquiries.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No enquiries to export'
      });
    }
    
    const headers = ['Name', 'Email', 'Phone', 'Company', 'Enquiry', 'Status', 'Date'];
    const csvRows = [];
    
    csvRows.push(headers.join(','));
    
    enquiries.forEach(enquiry => {
      const row = [
        `"${enquiry.name}"`,
        `"${enquiry.email}"`,
        `"${enquiry.phone}"`,
        `"${enquiry.company || ''}"`,
        `"${enquiry.enquiry.replace(/"/g, '""')}"`,
        `"${enquiry.status}"`,
        `"${new Date(enquiry.createdAt).toLocaleDateString()}"`
      ];
      csvRows.push(row.join(','));
    });
    
    const csvString = csvRows.join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="axora_enquiries_${new Date().toISOString().split('T')[0]}.csv"`);
    
    res.send(csvString);
    
  } catch (error) {
    console.error('Error exporting enquiries:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to export enquiries'
    });
  }
});

// Initialize and Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  await initializeAdmin();
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 JWT Authentication Enabled`);
  console.log(`👤 Default Admin: Pranil / pass@123`);
});
