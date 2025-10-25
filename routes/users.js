const express = require('express');
const admin = require('firebase-admin');
const router = express.Router();

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

// Get user profile
router.get('/profile', verifyToken, async (req, res) => {
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
router.put('/profile', verifyToken, async (req, res) => {
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
router.get('/notifications', verifyToken, async (req, res) => {
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
router.put('/notifications/:notificationId/read', verifyToken, async (req, res) => {
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
router.put('/notifications/read-all', verifyToken, async (req, res) => {
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
router.get('/bookmarks', verifyToken, async (req, res) => {
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
router.post('/bookmarks', verifyToken, async (req, res) => {
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
router.delete('/bookmarks/:bookmarkId', verifyToken, async (req, res) => {
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

module.exports = router;

