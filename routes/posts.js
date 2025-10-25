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

// Get feed posts
router.get('/feed', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { limit = 20, offset = 0, filter = 'all' } = req.query;

    // Get user's followed communities
    const communitiesQuery = admin.firestore()
      .collection('communities')
      .where('followers', 'array-contains', uid);

    const communitiesSnapshot = await communitiesQuery.get();
    const followedCommunityIds = communitiesSnapshot.docs.map(doc => doc.id);

    if (followedCommunityIds.length === 0) {
      return res.json([]);
    }

    // Get posts from followed communities
    const allPosts = [];
    
    for (const communityId of followedCommunityIds) {
      let postsQuery = admin.firestore()
        .collection('communities')
        .doc(communityId)
        .collection('posts')
        .orderBy('timestamp', 'desc');

      if (filter === 'trending') {
        // Get posts from last 24 hours
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        postsQuery = postsQuery.where('timestamp', '>=', oneDayAgo);
      }

      const postsSnapshot = await postsQuery.limit(parseInt(limit)).get();
      
      postsSnapshot.docs.forEach(doc => {
        allPosts.push({
          id: doc.id,
          communityId,
          communityName: communitiesSnapshot.docs.find(c => c.id === communityId)?.data().name,
          ...doc.data(),
          isLiked: doc.data().likes?.includes(uid) || false
        });
      });
    }

    // Sort posts
    if (filter === 'trending') {
      allPosts.sort((a, b) => (b.likes?.length || 0) - (a.likes?.length || 0));
    } else {
      allPosts.sort((a, b) => b.timestamp?.toDate() - a.timestamp?.toDate());
    }

    // Apply pagination
    const paginatedPosts = allPosts.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    res.json(paginatedPosts);
  } catch (error) {
    console.error('Error fetching feed:', error);
    res.status(500).json({ message: 'Failed to fetch feed' });
  }
});

// Get trending posts
router.get('/trending', verifyToken, async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;

    // Get posts from last 24 hours with most likes
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const communitiesQuery = admin.firestore()
      .collection('communities');

    const communitiesSnapshot = await communitiesQuery.get();
    const allPosts = [];

    for (const communityDoc of communitiesSnapshot.docs) {
      const postsQuery = admin.firestore()
        .collection('communities')
        .doc(communityDoc.id)
        .collection('posts')
        .where('timestamp', '>=', oneDayAgo)
        .orderBy('timestamp', 'desc');

      const postsSnapshot = await postsQuery.get();
      
      postsSnapshot.docs.forEach(doc => {
        allPosts.push({
          id: doc.id,
          communityId: communityDoc.id,
          communityName: communityDoc.data().name,
          ...doc.data(),
          isLiked: doc.data().likes?.includes(req.user.uid) || false
        });
      });
    }

    // Sort by likes count
    allPosts.sort((a, b) => (b.likes?.length || 0) - (a.likes?.length || 0));

    // Apply pagination
    const paginatedPosts = allPosts.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    res.json(paginatedPosts);
  } catch (error) {
    console.error('Error fetching trending posts:', error);
    res.status(500).json({ message: 'Failed to fetch trending posts' });
  }
});

// Search posts
router.get('/search', verifyToken, async (req, res) => {
  try {
    const { q, limit = 20, offset = 0 } = req.query;

    if (!q || q.trim().length < 2) {
      return res.status(400).json({ message: 'Search query must be at least 2 characters' });
    }

    const searchTerm = q.toLowerCase().trim();
    
    // Search in all communities
    const communitiesQuery = admin.firestore()
      .collection('communities');

    const communitiesSnapshot = await communitiesQuery.get();
    const matchingPosts = [];

    for (const communityDoc of communitiesSnapshot.docs) {
      const postsQuery = admin.firestore()
        .collection('communities')
        .doc(communityDoc.id)
        .collection('posts')
        .orderBy('timestamp', 'desc');

      const postsSnapshot = await postsQuery.get();
      
      postsSnapshot.docs.forEach(doc => {
        const postData = doc.data();
        const text = postData.text?.toLowerCase() || '';
        
        if (text.includes(searchTerm)) {
          matchingPosts.push({
            id: doc.id,
            communityId: communityDoc.id,
            communityName: communityDoc.data().name,
            ...postData,
            isLiked: postData.likes?.includes(req.user.uid) || false
          });
        }
      });
    }

    // Sort by timestamp
    matchingPosts.sort((a, b) => b.timestamp?.toDate() - a.timestamp?.toDate());

    // Apply pagination
    const paginatedPosts = matchingPosts.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    res.json(paginatedPosts);
  } catch (error) {
    console.error('Error searching posts:', error);
    res.status(500).json({ message: 'Failed to search posts' });
  }
});

// Get post details
router.get('/:postId', verifyToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const { communityId } = req.query;

    if (!communityId) {
      return res.status(400).json({ message: 'Community ID is required' });
    }

    const postDoc = await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .doc(postId)
      .get();

    if (!postDoc.exists) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const postData = postDoc.data();
    res.json({
      id: postDoc.id,
      ...postData,
      isLiked: postData.likes?.includes(req.user.uid) || false
    });
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({ message: 'Failed to fetch post' });
  }
});

// Add comment to post
router.post('/:postId/comments', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { postId } = req.params;
    const { communityId, text } = req.body;

    if (!text || !communityId) {
      return res.status(400).json({ message: 'Comment text and community ID are required' });
    }

    const commentData = {
      text,
      author: uid,
      authorName: req.user.name || req.user.email?.split('@')[0] || 'Anonymous',
      authorPhoto: req.user.picture,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    };

    const commentRef = await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .doc(postId)
      .collection('comments')
      .add(commentData);

    // Update post comment count
    await admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .doc(postId)
      .update({
        comments: admin.firestore.FieldValue.increment(1)
      });

    res.json({
      id: commentRef.id,
      message: 'Comment added successfully'
    });
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ message: 'Failed to add comment' });
  }
});

// Get post comments
router.get('/:postId/comments', verifyToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const { communityId, limit = 20, offset = 0 } = req.query;

    if (!communityId) {
      return res.status(400).json({ message: 'Community ID is required' });
    }

    const commentsQuery = admin.firestore()
      .collection('communities')
      .doc(communityId)
      .collection('posts')
      .doc(postId)
      .collection('comments')
      .orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset));

    const snapshot = await commentsQuery.get();
    const comments = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(comments);
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ message: 'Failed to fetch comments' });
  }
});

module.exports = router;

