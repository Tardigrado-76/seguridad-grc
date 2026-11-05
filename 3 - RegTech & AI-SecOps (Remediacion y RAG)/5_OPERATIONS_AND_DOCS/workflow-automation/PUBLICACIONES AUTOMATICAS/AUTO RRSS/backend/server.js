require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const path = require('path');
const fs = require('fs');

// Importar rutas
const authRoutes = require('./routes/auth');
const publishRoutes = require('./routes/publish');
const aiRoutes = require('./routes/ai');

const app = express();
const PORT = process.env.PORT || 3001;

// Crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ==========================================
// SEGURIDAD RGPD - HEADERS Y CONFIGURACIÓN
// ==========================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.twitter.com", "https://graph.facebook.com", "https://api.linkedin.com"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true
}));

// Rate limiting para prevenir abuso (RGPD - Integridad)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // límite de 100 peticiones por IP
  message: {
    error: 'Demasiadas peticiones desde esta IP',
    retryAfter: '15 minutos'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// CORS configurado (solo dominio permitido)
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  'http://localhost:5173', // Vite
  'http://127.0.0.1:3000'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==========================================
// SESIONES SEGURAS (RGPD - Confidencialidad)
// ==========================================

app.use(session({
  secret: process.env.SESSION_SECRET || 'cambiar-en-produccion-super-secreto-' + Math.random(),
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Nombre personalizado (no "connect.sid")
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS en producción
    httpOnly: true, // No accesible desde JavaScript
    maxAge: 24 * 60 * 60 * 1000, // 24 horas
    sameSite: 'lax', // Protección CSRF
    domain: process.env.COOKIE_DOMAIN || undefined
  }
}));

// Inicializar Passport
app.use(passport.initialize());
app.use(passport.session());

// Configurar estrategias de Passport
require('./config/passport')(passport);

// ==========================================
// RUTAS
// ==========================================

app.use('/api/auth', authRoutes);
app.use('/api', publishRoutes);
app.use('/api', aiRoutes);

// Ruta de estado de conexiones
app.get('/api/connections', (req, res) => {
  const connections = {
    facebook: !!(req.session.facebookToken),
    instagram: !!(req.session.instagramToken),
    twitter: !!(req.session.twitterToken),
    linkedin: !!(req.session.linkedinToken),
    tiktok: false // No implementado aún
  };
  
  res.json(connections);
});

// Ruta de salud del servidor
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    rgpd_compliant: true
  });
});

// Ruta de logout (RGPD - Derecho de supresión)
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Error al cerrar sesión' });
    }
    res.clearCookie('sessionId');
    res.json({ message: 'Sesión cerrada correctamente' });
  });
});

// ==========================================
// MANEJO DE ERRORES
// ==========================================

// 404 - Ruta no encontrada
app.use((req, res) => {
  res.status(404).json({
    error: 'Ruta no encontrada',
    path: req.path
  });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  
  // No exponer detalles en producción
  const errorResponse = {
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Ha ocurrido un error',
    timestamp: new Date().toISOString()
  };
  
  res.status(err.status || 500).json(errorResponse);
});

// ==========================================
// INICIO DEL SERVIDOR
// ==========================================

app.listen(PORT, () => {
  console.log('');
  console.log('🚀 ========================================');
  console.log(`✅ Servidor ejecutándose en puerto ${PORT}`);
  console.log(`🌍 Entorno: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Seguridad RGPD: ACTIVADA`);
  console.log(`📱 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log('🚀 ========================================');
  console.log('');
});

// Manejo de cierre graceful
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM recibido, cerrando servidor...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT recibido, cerrando servidor...');
  process.exit(0);
});

module.exports = app;