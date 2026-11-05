const express = require('express');
const router = express.Router();
const passport = require('passport');

// Facebook
router.get('/facebook', 
  passport.authenticate('facebook', { 
    scope: ['email', 'publish_to_groups', 'pages_manage_posts'] 
  })
);

router.get('/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.facebookToken = req.user.accessToken;
    res.send('<script>window.close();</script>');
  }
);

// Instagram (mediante Facebook Graph API)
router.get('/instagram',
  passport.authenticate('facebook', { 
    scope: ['instagram_basic', 'instagram_content_publish'] 
  })
);

router.get('/instagram/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.instagramToken = req.user.accessToken;
    res.send('<script>window.close();</script>');
  }
);

// Twitter
router.get('/twitter',
  passport.authenticate('twitter')
);

router.get('/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.twitterToken = req.user.accessToken;
    req.session.twitterTokenSecret = req.user.tokenSecret;
    res.send('<script>window.close();</script>');
  }
);

// LinkedIn
router.get('/linkedin',
  passport.authenticate('linkedin')
);

router.get('/linkedin/callback',
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.linkedinToken = req.user.accessToken;
    res.send('<script>window.close();</script>');
  }
);

// TikTok (requiere configuración especial)
router.get('/tiktok', (req, res) => {
  // TikTok usa OAuth 2.0 con flujo específico
  res.json({ message: 'TikTok OAuth en desarrollo' });
});

module.exports = router;