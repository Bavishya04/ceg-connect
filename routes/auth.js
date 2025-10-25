const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const admin = require('firebase-admin');
const router = express.Router();

// Initialize Firebase Admin (if not already initialized)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  }
});

// In-memory storage for OTPs (in production, use Redis or database)
const otpStorage = new Map();

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP email
router.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ 
        message: 'Please use a valid email address' 
      });
    }

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Store OTP
    otpStorage.set(email, {
      otp,
      expiresAt,
      attempts: 0
    });

    // Email content
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'CEG Connect - Your OTP Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #36B3A1 0%, #6B5A5A 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">CEG Connect</h1>
            <p style="color: white; margin: 5px 0 0 0;">Your College Community</p>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #333; margin-bottom: 20px;">Your Verification Code</h2>
            <p style="color: #666; margin-bottom: 30px;">
              Use the following code to verify your email address:
            </p>
            
            <div style="background: white; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #36B3A1;">
              <h1 style="color: #36B3A1; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
            </div>
            
            <p style="color: #666; margin-top: 20px; font-size: 14px;">
              This code will expire in 5 minutes. If you didn't request this code, please ignore this email.
            </p>
          </div>
          
          <div style="background: #333; color: white; padding: 20px; text-align: center; font-size: 12px;">
            <p style="margin: 0;">© 2024 CEG Connect. College of Engineering, Guindy.</p>
          </div>
        </div>
      `
    };

    // Send email
    await transporter.sendMail(mailOptions);

    res.json({ 
      message: 'OTP sent successfully',
      expiresIn: 300 // 5 minutes in seconds
    });

  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ 
      message: 'Failed to send OTP. Please try again.' 
    });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Validate input
    if (!email || !otp) {
      return res.status(400).json({ 
        message: 'Email and OTP are required' 
      });
    }

    // Check if OTP exists
    const storedData = otpStorage.get(email);
    if (!storedData) {
      return res.status(400).json({ 
        message: 'OTP not found or expired' 
      });
    }

    // Check if OTP is expired
    if (new Date() > storedData.expiresAt) {
      otpStorage.delete(email);
      return res.status(400).json({ 
        message: 'OTP has expired' 
      });
    }

    // Check attempts
    if (storedData.attempts >= 3) {
      otpStorage.delete(email);
      return res.status(400).json({ 
        message: 'Too many failed attempts. Please request a new OTP.' 
      });
    }

    // Verify OTP
    if (storedData.otp !== otp) {
      storedData.attempts++;
      otpStorage.set(email, storedData);
      return res.status(400).json({ 
        message: 'Invalid OTP' 
      });
    }

    // OTP is valid, get or create user
    try {
      let userRecord;
      
      try {
        // Try to get existing user by email
        userRecord = await admin.auth().getUserByEmail(email);
      } catch (error) {
        // User doesn't exist, create new user
        userRecord = await admin.auth().createUser({
          email: email,
          emailVerified: true
        });
      }

      // Create custom token for the user
      const customToken = await admin.auth().createCustomToken(userRecord.uid, {
        email: email,
        verified: true
      });

      // Clean up OTP
      otpStorage.delete(email);

      res.json({ 
        message: 'OTP verified successfully',
        token: customToken
      });

    } catch (firebaseError) {
      console.error('Error creating custom token:', firebaseError);
      res.status(500).json({ 
        message: 'Failed to create authentication token' 
      });
    }

  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ 
      message: 'Failed to verify OTP. Please try again.' 
    });
  }
});

// Clean up expired OTPs (run every 5 minutes)
setInterval(() => {
  const now = new Date();
  for (const [email, data] of otpStorage.entries()) {
    if (now > data.expiresAt) {
      otpStorage.delete(email);
    }
  }
}, 5 * 60 * 1000);

module.exports = router;

