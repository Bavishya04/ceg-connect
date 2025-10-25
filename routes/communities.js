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

// Get all communities
router.get('/', verifyToken, async (req, res) => {
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
router.get('/:communityId', verifyToken, async (req, res) => {
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
router.post('/', verifyToken, async (req, res) => {
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
router.post('/:communityId/follow', verifyToken, async (req, res) => {
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
router.get('/:communityId/posts', verifyToken, async (req, res) => {
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
router.post('/:communityId/posts', verifyToken, async (req, res) => {
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
router.post('/:communityId/posts/:postId/like', verifyToken, async (req, res) => {
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

module.exports = router;

