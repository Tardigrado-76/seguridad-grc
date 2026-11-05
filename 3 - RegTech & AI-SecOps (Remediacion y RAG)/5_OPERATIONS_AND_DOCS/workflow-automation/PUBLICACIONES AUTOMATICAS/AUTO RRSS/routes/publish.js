const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const { TwitterApi } = require('twitter-api-v2');

// ==========================================
// CONFIGURACIÓN MULTER
// ==========================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, '..', 'uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${name}-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
    files: 10
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|mov|avi|mkv/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Solo se permiten imágenes (JPG, PNG, GIF, WEBP) y videos (MP4, MOV, AVI)'));
    }
  }
});

// ==========================================
// FUNCIÓN: PUBLICAR EN FACEBOOK
// ==========================================

async function publishToFacebook(accessToken, caption, filePath, isVideo = false) {
  try {
    const formData = new FormData();
    formData.append('message', caption);

    if (isVideo) {
      formData.append('source', fs.createReadStream(filePath));
      var endpoint = 'videos';
    } else {
      formData.append('source', fs.createReadStream(filePath));
      var endpoint = 'photos';
    }

    const response = await axios.post(
      `https://graph.facebook.com/v19.0/me/${endpoint}`,
      formData,
      {
        params: { access_token: accessToken },
        headers: formData.getHeaders(),
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    );

    return {
      success: true,
      data: response.data,
      postId: response.data.id
    };
  } catch (error) {
    console.error('❌ Error publicando en Facebook:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.error?.message || error.message
    };
  }
}

// ==========================================
// FUNCIÓN: PUBLICAR EN INSTAGRAM
// ==========================================

async function publishToInstagram(accessToken, caption, filePath, pageId) {
  try {
    // Paso 1: Crear container
    const createResponse = await axios.post(
      `https://graph.facebook.com/v19.0/${pageId}/media`,
      {
        image_url: filePath, // Debe ser URL pública en producción
        caption: caption,
        access_token: accessToken
      }
    );

    const containerId = createResponse.data.id;

    // Paso 2: Publicar
    const publishResponse = await axios.post(
      `https://graph.facebook.com/v19.0/${pageId}/media_publish`,
      {
        creation_id: containerId,
        access_token: accessToken
      }
    );

    return {
      success: true,
      data: publishResponse.data,
      postId: publishResponse.data.id
    };
  } catch (error) {
    console.error('❌ Error publicando en Instagram:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.error?.message || error.message
    };
  }
}

// ==========================================
// FUNCIÓN: PUBLICAR EN TWITTER/X
// ==========================================

async function publishToTwitter(accessToken, caption, filePath, isVideo = false) {
  try {
    const twitterClient = new TwitterApi(accessToken);

    // Subir media
    const mediaId = await twitterClient.v1.uploadMedia(filePath, {
      mimeType: isVideo ? 'video/mp4' : undefined
    });

    // Crear tweet
    const tweet = await twitterClient.v2.tweet({
      text: caption,
      media: { media_ids: [mediaId] }
    });

    return {
      success: true,
      data: tweet.data,
      tweetId: tweet.data.id
    };
  } catch (error) {
    console.error('❌ Error publicando en Twitter:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// ==========================================
// FUNCIÓN: PUBLICAR EN LINKEDIN
// ==========================================

async function publishToLinkedIn(accessToken, userId, caption, filePath) {
  try {
    // Paso 1: Registrar upload
    const registerResponse = await axios.post(
      'https://api.linkedin.com/v2/assets?action=registerUpload',
      {
        registerUploadRequest: {
          recipes: ['urn:li:digitalmediaRecipe:feedshare-image'],
          owner: `urn:li:person:${userId}`,
          serviceRelationships: [{
            relationshipType: 'OWNER',
            identifier: 'urn:li:userGeneratedContent'
          }]
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const uploadUrl = registerResponse.data.value.uploadMechanism['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest'].uploadUrl;
    const asset = registerResponse.data.value.asset;

    // Paso 2: Subir imagen
    const imageBuffer = fs.readFileSync(filePath);
    await axios.put(uploadUrl, imageBuffer, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/octet-stream'
      }
    });

    // Paso 3: Crear post
    const postResponse = await axios.post(
      'https://api.linkedin.com/v2/ugcPosts',
      {
        author: `urn:li:person:${userId}`,
        lifecycleState: 'PUBLISHED',
        specificContent: {
          'com.linkedin.ugc.ShareContent': {
            shareCommentary: {
              text: caption
            },
            shareMediaCategory: 'IMAGE',
            media: [{
              status: 'READY',
              description: {
                text: caption
              },
              media: asset,
              title: {
                text: 'Publicación'
              }
            }]
          }
        },
        visibility: {
          'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
        }
      },
      {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0'
    }
  }
);
    } catch (error) {
console.error('❌ Error publicando en LinkedIn:', error.response?.data || error.message);
return {
success: false,
error: error.response?.data?.message || error.message
};
}
}