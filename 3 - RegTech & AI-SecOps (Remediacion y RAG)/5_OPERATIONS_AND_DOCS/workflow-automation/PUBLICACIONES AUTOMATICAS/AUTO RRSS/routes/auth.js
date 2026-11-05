const express = require('express');
const router = express.Router();
const passport = require('passport');
const crypto = require('crypto');
const axios = require('axios');

// ==========================================
// FACEBOOK AUTHENTICATION
// ==========================================

router.get('/facebook', 
  passport.authenticate('facebook', { 
    scope: [
      'email',
      'public_profile',
      'pages_manage_posts',
      'pages_read_engagement',
      'publish_to_groups'
    ]
  })
);

router.get('/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/login',
    session: true 
  }),
  (req, res) => {
    req.session.facebookToken = req.user.accessToken;
    req.session.facebookId = req.user.id;
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Autenticación Exitosa</title>
        <style>
          body { font-family: Arial; text-align: center; padding: 50px; }
          .success { color: green; font-size: 24px; }
        </style>
      </head>
      <body>
        <div class="success">✅ Facebook conectado exitosamente</div>
        <p>Cerrando ventana...</p>
        <script>
          setTimeout(() => window.close(), 2000);
        </script>
      </body>
      </html>
    `);
  }
);

// ==========================================
// INSTAGRAM (vía Facebook Graph API)
// ==========================================

router.get('/instagram',
  passport.authenticate('facebook', { 
    scope: [
      'instagram_basic',
      'instagram_content_publish',
      'pages_read_engagement',
      'pages_show_list'
    ]
  })
);

router.get('/instagram/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/login',
    session: true 
  }),
  async (req, res) => {
    try {
      req.session.instagramToken = req.user.accessToken;
      
      // Obtener Instagram Business Account ID
      const response = await axios.get(
        `https://graph.facebook.com/v18.0/me/accounts`,
        { params: { access_token: req.user.accessToken } }
      );
      
      if (response.data.data && response.data.data.length > 0) {
        req.session.instagramPageId = response.data.data[0].id;
      }
      
      res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Instagram Conectado</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <div style="color: green; font-size: 24px;">✅ Instagram conectado</div>
          <script>setTimeout(() => window.close(), 2000);</script>
        </body>
        </html>
      `);
    } catch (error) {
      console.error('Error conectando Instagram:', error);
      res.status(500).send('Error al conectar Instagram');
    }
  }
);

// ==========================================
// TWITTER/X (OAuth 2.0 Manual)
// ==========================================

router.get('/twitter', (req, res) => {
  if (!process.env.TWITTER_CLIENT_ID || !process.env.TWITTER_CLIENT_SECRET) {
    return res.status(500).json({ 
      error: 'Twitter OAuth no configurado',
      message: 'Configura TWITTER_CLIENT_ID y TWITTER_CLIENT_SECRET en .env'
    });
  }

  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  req.session.twitterState = state;
  req.session.twitterCodeVerifier = codeVerifier;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.TWITTER_CLIENT_ID,
    redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/twitter/callback`,
    scope: 'tweet.read tweet.write users.read offline.access',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://twitter.com/i/oauth2/authorize?${params.toString()}`);
});

router.get('/twitter/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state || state !== req.session.twitterState) {
    return res.status(400).send('Estado de autenticación inválido');
  }

  try {
    const credentials = Buffer.from(
      `${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`
    ).toString('base64');

    const response = await axios.post(
      'https://api.twitter.com/2/oauth2/token',
      new URLSearchParams({
        code: code,
        grant_type: 'authorization_code',
        client_id: process.env.TWITTER_CLIENT_ID,
        redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/twitter/callback`,
        code_verifier: req.session.twitterCodeVerifier
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${credentials}`
        }
      }
    );

    req.session.twitterToken = response.data.access_token;
    req.session.twitterRefreshToken = response.data.refresh_token;

    // Obtener información del usuario
    const userResponse = await axios.get('https://api.twitter.com/2/users/me', {
      headers: {
        'Authorization': `Bearer ${response.data.access_token}`
      }
    });

    req.session.twitterUserId = userResponse.data.data.id;

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Twitter Conectado</title></head>
      <body style="font-family: Arial; text-align: center; padding: 50px;">
        <div style="color: green; font-size: 24px;">✅ Twitter/X conectado</div>
        <script>setTimeout(() => window.close(), 2000);</script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error en Twitter OAuth:', error.response?.data || error.message);
    res.status(500).send(`Error de autenticación: ${error.message}`);
  }
});

// ==========================================
// LINKEDIN (OAuth 2.0 Manual)
// ==========================================

router.get('/linkedin', (req, res) => {
  if (!process.env.LINKEDIN_CLIENT_ID || !process.env.LINKEDIN_CLIENT_SECRET) {
    return res.status(500).json({ 
      error: 'LinkedIn OAuth no configurado',
      message: 'Configura LINKEDIN_CLIENT_ID y LINKEDIN_CLIENT_SECRET en .env'
    });
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.linkedinState = state;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/linkedin/callback`,
    state: state,
    scope: 'r_liteprofile r_emailaddress w_member_social'
  });

  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`);
});

router.get('/linkedin/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state || state !== req.session.linkedinState) {
    return res.status(400).send('Estado de autenticación inválido');
  }

  try {
    const response = await axios.post(
      'https://www.linkedin.com/oauth/v2/accessToken',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/linkedin/callback`,
        client_id: process.env.LINKEDIN_CLIENT_ID,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    req.session.linkedinToken = response.data.access_token;

    // Obtener perfil del usuario
    const profileResponse = await axios.get('https://api.linkedin.com/v2/me', {
      headers: {
        'Authorization': `Bearer ${response.data.access_token}`
      }
    });

    req.session.linkedinUserId = profileResponse.data.id;

    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>LinkedIn Conectado</title></head>
      <body style="font-family: Arial; text-align: center; padding: 50px;">
        <div style="color: green; font-size: 24px;">✅ LinkedIn conectado</div>
        <script>setTimeout(() => window.close(), 2000);</script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error en LinkedIn OAuth:', error.response?.data || error.message);
    res.status(500).send(`Error de autenticación: ${error.message}`);
  }
});

// ==========================================
// GOOGLE/YOUTUBE
// ==========================================

router.get('/google',
  passport.authenticate('google', { 
    scope: [
      'profile',
      'email',
      'https://www.googleapis.com/auth/youtube.upload'
    ]
  })
);

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.googleToken = req.user.accessToken;
    req.session.googleRefreshToken = req.user.refreshToken;
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Google Conectado</title></head>
      <body style="font-family: Arial; text-align: center; padding: 50px;">
        <div style="color: green; font-size: 24px;">✅ YouTube conectado</div>
        <script>setTimeout(() => window.close(), 2000);</script>
      </body>
      </html>
    `);
  }
);

// ==========================================
// TIKTOK (Placeholder - requiere aprobación)
// ==========================================

router.get('/tiktok', (req, res) => {
  res.json({
    message: 'TikTok requiere aprobación de desarrollador',
    info: 'Solicita acceso en https://developers.tiktok.com'
  });
});

module.exports = router;