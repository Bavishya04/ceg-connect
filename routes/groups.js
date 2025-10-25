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

// Get all groups
router.get('/', verifyToken, async (req, res) => {
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
router.get('/:groupId', verifyToken, async (req, res) => {
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
router.post('/', verifyToken, async (req, res) => {
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
router.post('/:groupId/join', verifyToken, async (req, res) => {
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
router.post('/:groupId/leave', verifyToken, async (req, res) => {
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
router.get('/:groupId/messages', verifyToken, async (req, res) => {
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
router.post('/:groupId/messages', verifyToken, async (req, res) => {
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

module.exports = router;

