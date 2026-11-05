const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;

module.exports = function(passport) {
  
  // ==========================================
  // SERIALIZACIÓN DE USUARIO
  // ==========================================
  
  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((user, done) => {
    done(null, user);
  });

  // ==========================================
  // ESTRATEGIA FACEBOOK
  // ==========================================
  
  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/facebook/callback`,
      profileFields: ['id', 'emails', 'name', 'displayName', 'photos'],
      enableProof: true
    },
    function(accessToken, refreshToken, profile, done) {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails ? profile.emails[0].value : null,
        provider: 'facebook',
        accessToken: accessToken,
        refreshToken: refreshToken
      };
      return done(null, user);
    }));
  } else {
    console.warn('⚠️  Facebook OAuth no configurado (falta APP_ID o APP_SECRET)');
  }

  // ==========================================
  // ESTRATEGIA GOOGLE (para YouTube)
  // ==========================================
  
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/auth/google/callback`,
      scope: ['profile', 'email', 'https://www.googleapis.com/auth/youtube.upload']
    },
    function(accessToken, refreshToken, profile, done) {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails ? profile.emails[0].value : null,
        provider: 'google',
        accessToken: accessToken,
        refreshToken: refreshToken
      };
      return done(null, user);
    }));
  } else {
    console.warn('⚠️  Google OAuth no configurado (falta CLIENT_ID o CLIENT_SECRET)');
  }

  // Nota: Twitter y LinkedIn se manejan con OAuth 2.0 manual en routes/auth.js
  // para evitar dependencias con vulnerabilidades xmldom
  
};