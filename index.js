const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Initialize Firebase Admin
admin.initializeApp();

const app = express();

// Middleware
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Email transporter setup
const transporter = nodemailer.createTransporter({
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

// Middleware to verify Firebase token
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split('Bearer ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// ==================== HEALTH & BASIC ENDPOINTS ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'CEG Connect Backend is running!',
    timestamp: new Date().toISOString() 
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend is working perfectly!',
    timestamp: new Date().toISOString() 
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'CEG Connect Backend API',
    status: 'running',
    timestamp: new Date().toISOString() 
  });
});

// ==================== AUTH ENDPOINTS ====================

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
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

    // For demo purposes, return success without sending email
    // In production, uncomment the email sending code below
    res.json({ 
      success: true,
      message: 'OTP sent successfully',
      email: email,
      otp: otp, // Demo OTP - remove in production
      expiresIn: 300 // 5 minutes in seconds
    });

    /* Email sending code (uncomment for production):
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

    await transporter.sendMail(mailOptions);
    */

  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ 
      message: 'Failed to send OTP. Please try again.' 
    });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
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
        success: true,
        message: 'OTP verified successfully',
        token: customToken,
        user: {
          id: userRecord.uid,
          email: email,
          name: email.split('@')[0]
        }
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

// ==================== COMMUNITIES ENDPOINTS ====================

// Get all communities
app.get('/api/communities', verifyToken, async (req, res) => {
  try {
    const { limit = 20, offset = 0, category } = req.query;

    let communitiesQuery = admin.firestore()
      .collection('communities')
      .orderBy('createdAt', 'desc');

    if (category && category !== 'All') {
      communitiesQuery = communitiesQuery.where('category', '==', category);
    }

    communitiesQuery = communitiesQuery
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await communitiesQuery.get();
    const communities = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      isFollowing: doc.data().followers?.includes(req.user.uid) || false
    }));

    res.json(communities);
  } catch (error) {
    console.error('Error fetching communities:', error);
    res.status(500).json({ message: 'Failed to fetch communities' });
  }
});

// Get single community
app.get('/api/communities/:communityId', verifyToken, async (req, res) => {
  try {
    const { communityId } = req.params;

    const communityDoc = await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .get();

    if (!communityDoc.exists) {
      return res.status(404).json({ message: 'Community not found' });
    }

    const communityData = communityDoc.data();
    res.json({
      id: communityDoc.id,
      ...communityData,
      isFollowing: communityData.followers?.includes(req.user.uid) || false
    });
  } catch (error) {
    console.error('Error fetching community:', error);
    res.status(500).json({ message: 'Failed to fetch community' });
  }
});

// Create new community
app.post('/api/communities', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { name, description, category } = req.body;

    if (!name || !description || !category) {
      return res.status(400).json({ message: 'Name, description, and category are required' });
    }

    const communityData = {
      name,
      description,
      category,
      followers: [uid],
      admin: uid,
      adminName: req.user.name || req.user.email?.split('@')[0] || 'Anonymous',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      postCount: 0
    };

    const communityRef = await admin.firestore()
      .collection('communities')
      .add(communityData);

    res.json({
      id: communityRef.id,
      message: 'Community created successfully'
    });
  } catch (error) {
    console.error('Error creating community:', error);
    res.status(500).json({ message: 'Failed to create community' });
  }
});

// Follow/Unfollow community
app.post('/api/communities/:communityId/follow', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { communityId } = req.params;

    const communityRef = admin.firestore().collection('communities').doc(communityId);
    const communityDoc = await communityRef.get();

    if (!communityDoc.exists) {
      return res.status(404).json({ message: 'Community not found' });
    }

    const communityData = communityDoc.data();
    const isFollowing = communityData.followers?.includes(uid) || false;

    if (isFollowing) {
      await communityRef.update({
        followers: admin.firestore.FieldValue.arrayRemove(uid),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      res.json({ message: 'Unfollowed community', isFollowing: false });
    } else {
      await communityRef.update({
        followers: admin.firestore.FieldValue.arrayUnion(uid),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      res.json({ message: 'Following community', isFollowing: true });
    }
  } catch (error) {
    console.error('Error toggling follow:', error);
    res.status(500).json({ message: 'Failed to update follow status' });
  }
});

// Get community posts
app.get('/api/communities/:communityId/posts', verifyToken, async (req, res) => {
  try {
    const { communityId } = req.params;
    const { limit = 20, offset = 0 } = req.query;

    const postsQuery = admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await postsQuery.get();
    const posts = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      isLiked: doc.data().likes?.includes(req.user.uid) || false
    }));

    res.json(posts);
  } catch (error) {
    console.error('Error fetching community posts:', error);
    res.status(500).json({ message: 'Failed to fetch posts' });
  }
});

// Create post in community
app.post('/api/communities/:communityId/posts', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { communityId } = req.params;
    const { text, images = [] } = req.body;

    if (!text && images.length === 0) {
      return res.status(400).json({ message: 'Post content is required' });
    }

    // Check if user is following the community
    const communityDoc = await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .get();

    if (!communityDoc.exists) {
      return res.status(404).json({ message: 'Community not found' });
    }

    const communityData = communityDoc.data();
    if (!communityData.followers?.includes(uid)) {
      return res.status(403).json({ message: 'Must follow community to post' });
    }

    const postData = {
      text,
      images,
      author: uid,
      authorName: req.user.name || req.user.email?.split('@')[0] || 'Anonymous',
      authorPhoto: req.user.picture,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      likes: [],
      comments: 0
    };

    const postRef = await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .add(postData);

    // Update community post count
    await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .update({
        postCount: admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({
      id: postRef.id,
      message: 'Post created successfully'
    });
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ message: 'Failed to create post' });
  }
});

// Like/Unlike post
app.post('/api/communities/:communityId/posts/:postId/like', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { communityId, postId } = req.params;

    const postRef = admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .doc(postId);

    const postDoc = await postRef.get();
    if (!postDoc.exists) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const postData = postDoc.data();
    const isLiked = postData.likes?.includes(uid) || false;

    if (isLiked) {
      await postRef.update({
        likes: admin.firestore.FieldValue.arrayRemove(uid)
      });
      res.json({ message: 'Post unliked', isLiked: false });
    } else {
      await postRef.update({
        likes: admin.firestore.FieldValue.arrayUnion(uid)
      });
      res.json({ message: 'Post liked', isLiked: true });
    }
  } catch (error) {
    console.error('Error toggling like:', error);
    res.status(500).json({ message: 'Failed to update like status' });
  }
});

// ==================== GROUPS ENDPOINTS ====================

// Get all groups
app.get('/api/groups', verifyToken, async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;

    const groupsQuery = admin.firestore()
      .collection('groups')
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await groupsQuery.get();
    const groups = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(groups);
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ message: 'Failed to fetch groups' });
  }
});

// Get single group
app.get('/api/groups/:groupId', verifyToken, async (req, res) => {
  try {
    const { groupId } = req.params;

    const groupDoc = await admin.firestore()
      .collection('groups')
      .doc(groupId)
      .get();

    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Group not found' });
    }

    res.json({
      id: groupDoc.id,
      ...groupDoc.data()
    });
  } catch (error) {
    console.error('Error fetching group:', error);
    res.status(500).json({ message: 'Failed to fetch group' });
  }
});

// Create new group
app.post('/api/groups', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { name, description, isPrivate = false } = req.body;

    if (!name || !description) {
      return res.status(400).json({ message: 'Name and description are required' });
    }

    const groupData = {
      name,
      description,
      isPrivate,
      members: [uid],
      admin: uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const groupRef = await admin.firestore()
      .collection('groups')
      .add(groupData);

    res.json({
      id: groupRef.id,
      message: 'Group created successfully'
    });
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ message: 'Failed to create group' });
  }
});

// Join group
app.post('/api/groups/:groupId/join', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { groupId } = req.params;

    const groupRef = admin.firestore().collection('groups').doc(groupId);
    const groupDoc = await groupRef.get();

    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Group not found' });
    }

    const groupData = groupDoc.data();
    
    if (groupData.members.includes(uid)) {
      return res.status(400).json({ message: 'Already a member of this group' });
    }

    await groupRef.update({
      members: admin.firestore.FieldValue.arrayUnion(uid),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'Successfully joined group' });
  } catch (error) {
    console.error('Error joining group:', error);
    res.status(500).json({ message: 'Failed to join group' });
  }
});

// Leave group
app.post('/api/groups/:groupId/leave', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { groupId } = req.params;

    const groupRef = admin.firestore().collection('groups').doc(groupId);
    const groupDoc = await groupRef.get();

    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Group not found' });
    }

    const groupData = groupDoc.data();
    
    if (!groupData.members.includes(uid)) {
      return res.status(400).json({ message: 'Not a member of this group' });
    }

    if (groupData.admin === uid) {
      return res.status(400).json({ message: 'Admin cannot leave the group' });
    }

    await groupRef.update({
      members: admin.firestore.FieldValue.arrayRemove(uid),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'Successfully left group' });
  } catch (error) {
    console.error('Error leaving group:', error);
    res.status(500).json({ message: 'Failed to leave group' });
  }
});

// Get group messages
app.get('/api/groups/:groupId/messages', verifyToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { limit = 50, offset = 0 } = req.query;

    // Check if user is a member of the group
    const groupDoc = await admin.firestore()
      .collection('groups')
      .doc(groupId)
      .get();

    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Group not found' });
    }

    const groupData = groupDoc.data();
    if (!groupData.members.includes(req.user.uid)) {
      return res.status(403).json({ message: 'Not a member of this group' });
    }

    const messagesQuery = admin.firestore()
      .collection('groups')
      .doc(groupId)
      .collection('messages')
      .orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await messagesQuery.get();
    const messages = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(messages);
  } catch (error) {
    console.error('Error fetching group messages:', error);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

// Send message to group
app.post('/api/groups/:groupId/messages', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { groupId } = req.params;
    const { text, type = 'text', fileUrl, fileName } = req.body;

    if (!text && !fileUrl) {
      return res.status(400).json({ message: 'Message content is required' });
    }

    // Check if user is a member of the group
    const groupDoc = await admin.firestore()
      .collection('groups')
      .doc(groupId)
      .get();

    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Group not found' });
    }

    const groupData = groupDoc.data();
    if (!groupData.members.includes(uid)) {
      return res.status(403).json({ message: 'Not a member of this group' });
    }

    const messageData = {
      text: text || `Shared a file: ${fileName}`,
      author: uid,
      type,
      fileUrl,
      fileName,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    };

    const messageRef = await admin.firestore()
      .collection('groups')
      .doc(groupId)
      .collection('messages')
      .add(messageData);

    // Update group's last message
    await admin.firestore()
      .collection('groups')
      .doc(groupId)
      .update({
        lastMessage: {
          text: messageData.text,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          author: uid
        },
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({
      id: messageRef.id,
      message: 'Message sent successfully'
    });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

// ==================== USERS ENDPOINTS ====================

// Get user profile
app.get('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    
    const userDoc = await admin.firestore()
      .collection('users')
      .doc(uid)
      .get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User profile not found' });
    }

    res.json(userDoc.data());
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: 'Failed to fetch user profile' });
  }
});

// Update user profile
app.put('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { name, regNo, department, year, photoURL } = req.body;

    const updateData = {
      name,
      regNo,
      department,
      year,
      photoURL,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await admin.firestore()
      .collection('users')
      .doc(uid)
      .update(updateData);

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

// Get user's notifications
app.get('/api/users/notifications', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { limit = 50, offset = 0 } = req.query;

    const notificationsQuery = admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('notifications')
      .orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await notificationsQuery.get();
    const notifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(notifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

// Mark notification as read
app.put('/api/users/notifications/:notificationId/read', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { notificationId } = req.params;

    await admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('notifications')
      .doc(notificationId)
      .update({
        read: true,
        readAt: admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ message: 'Failed to mark notification as read' });
  }
});

// Mark all notifications as read
app.put('/api/users/notifications/read-all', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;

    const notificationsQuery = admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('notifications')
      .where('read', '==', false);

    const snapshot = await notificationsQuery.get();
    const batch = admin.firestore().batch();

    snapshot.docs.forEach(doc => {
      batch.update(doc.ref, {
        read: true,
        readAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    await batch.commit();

    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ message: 'Failed to mark all notifications as read' });
  }
});

// Get user's bookmarks
app.get('/api/users/bookmarks', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { limit = 50, offset = 0 } = req.query;

    const bookmarksQuery = admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('bookmarks')
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await bookmarksQuery.get();
    const bookmarks = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(bookmarks);
  } catch (error) {
    console.error('Error fetching bookmarks:', error);
    res.status(500).json({ message: 'Failed to fetch bookmarks' });
  }
});

// Add bookmark
app.post('/api/users/bookmarks', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { postId, communityId, postType } = req.body;

    const bookmarkData = {
      postId,
      communityId,
      postType,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('bookmarks')
      .add(bookmarkData);

    res.json({ message: 'Bookmark added successfully' });
  } catch (error) {
    console.error('Error adding bookmark:', error);
    res.status(500).json({ message: 'Failed to add bookmark' });
  }
});

// Remove bookmark
app.delete('/api/users/bookmarks/:bookmarkId', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { bookmarkId } = req.params;

    await admin.firestore()
      .collection('users')
      .doc(uid)
      .collection('bookmarks')
      .doc(bookmarkId)
      .delete();

    res.json({ message: 'Bookmark removed successfully' });
  } catch (error) {
    console.error('Error removing bookmark:', error);
    res.status(500).json({ message: 'Failed to remove bookmark' });
  }
});

// ==================== CLEANUP TASKS ====================

// Clean up expired OTPs (run every 5 minutes)
setInterval(() => {
  const now = new Date();
  for (const [email, data] of otpStorage.entries()) {
    if (now > data.expiresAt) {
      otpStorage.delete(email);
    }
  }
}, 5 * 60 * 1000);

// ==================== START SERVER ====================

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 CEG Connect Backend Server is running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
  console.log(`✅ All endpoints are ready!`);
});