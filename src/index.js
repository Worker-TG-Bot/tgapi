// Cloudflare Workers - Telegram 图床/文件代理服务 (D1 版本 v10.0)
// 功能：密码验证 + 消息ID友好链接 + 永久有效 + Bot 授权验证 + 链接清理 + 定时清理

export default {
  // HTTP 请求处理
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const config = {
      ACCESS_PASSWORD: env.ACCESS_PASSWORD || "",
      ENCRYPTION_KEY: env.ENCRYPTION_KEY || "",
      ADMIN_IDS: (env.ADMIN_IDS || "").split(",").map(id => id.trim()).filter(Boolean),
      BOT_TOKEN: env.BOT_TOKEN,
      FILE_DB: env.FILE_DB
    };
    
    try {
      return await handleRequest(request, url, config, env);
    } catch (error) {
      console.error('请求处理失败:', error);
      return jsonResponse({ error: '服务器内部错误', detail: error.message }, 500);
    }
  },
  
  // Cron 定时任务处理 - 自动清理无效链接
  async scheduled(event, env, ctx) {
    const config = {
      BOT_TOKEN: env.BOT_TOKEN,
      ENCRYPTION_KEY: env.ENCRYPTION_KEY || "",
      ADMIN_IDS: (env.ADMIN_IDS || "").split(",").map(id => id.trim()).filter(Boolean),
      FILE_DB: env.FILE_DB
    };
    
    console.log('⏰ 开始定时清理任务...');
    
    try {
      const result = await performScheduledClean(config);
      console.log('✅ 定时清理完成:', JSON.stringify(result));
    } catch (error) {
      console.error('❌ 定时清理失败:', error);
    }
  }
};

// 执行定时清理任务
async function performScheduledClean(config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY, ADMIN_IDS } = config;
  
  if (!FILE_DB || !BOT_TOKEN || !ENCRYPTION_KEY) {
    return { error: '缺少必要配置' };
  }
  
  // 获取总数
  const totalResult = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
  const totalCount = totalResult?.count || 0;
  
  if (totalCount === 0) {
    return { message: '数据库中没有文件' };
  }
  
  let totalChecked = 0;
  let totalValid = 0;
  let totalInvalid = 0;
  const batchSize = 40;
  const allInvalidKeys = [];
  let offset = 0;
  
  // 分批循环检测
  while (true) {
    const files = await FILE_DB.prepare(
      'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at ASC LIMIT ? OFFSET ?'
    ).bind(batchSize, offset).all();
    
    if (!files.results?.length) {
      break;
    }
    
    let batchInvalid = 0;
    const batchInvalidKeys = [];
    
    for (const file of files.results) {
      try {
        const decrypted = JSON.parse(await decryptData(file.encrypted_data, ENCRYPTION_KEY));
        const isValid = await verifyFileLink(decrypted);
        
        if (isValid) {
          totalValid++;
        } else {
          batchInvalid++;
          batchInvalidKeys.push({
            key: file.file_key,
            filename: decrypted.filename || '未知'
          });
        }
      } catch (e) {
        batchInvalid++;
        batchInvalidKeys.push({
          key: file.file_key,
          filename: '解密失败'
        });
      }
    }
    
    // 立即删除本批无效链接
    for (const item of batchInvalidKeys) {
      await deleteFileMapping(FILE_DB, item.key);
      allInvalidKeys.push(item);
    }
    
    totalChecked += files.results.length;
    totalInvalid += batchInvalid;
    
    // 更新 offset（只跳过有效的链接，无效的已删除）
    offset += files.results.length - batchInvalid;
    
    if (files.results.length < batchSize) {
      break; // 最后一批
    }
  }
  
  // 生成报告
  const report = generateCleanReport(totalCount, totalChecked, totalValid, totalInvalid, allInvalidKeys);
  
  // 发送报告给所有管理员
  if (ADMIN_IDS && ADMIN_IDS.length > 0) {
    for (const adminId of ADMIN_IDS) {
      try {
        await sendMessage(BOT_TOKEN, parseInt(adminId), 
          `⏰ <b>定时清理报告</b>\n\n` + report
        );
      } catch (e) {
        console.error(`发送报告给 ${adminId} 失败:`, e);
      }
    }
  }
  
  return {
    total: totalCount,
    checked: totalChecked,
    valid: totalValid,
    invalid: totalInvalid,
    remaining: totalCount - totalInvalid
  };
}

// ==================== 路由处理 ====================
async function handleRequest(request, url, config, env) {
  const { FILE_DB, BOT_TOKEN, ACCESS_PASSWORD, ENCRYPTION_KEY, ADMIN_IDS } = config;
  
  if (request.method === 'OPTIONS') {
    return corsResponse();
  }
  
  // 初始化数据库
  if (url.pathname === '/init-db') {
    return await handleInitDb(FILE_DB, ADMIN_IDS);
  }
  
  // Webhook 处理
  if (url.pathname.startsWith('/webhook/') && request.method === 'POST') {
    return await handleWebhook(request, url, config);
  }
  
  // 设置/删除 Webhook
  if (url.pathname === '/set-webhook' && request.method === 'POST') {
    return await handleSetWebhook(request, url, config);
  }
  
  if (url.pathname === '/delete-webhook' && request.method === 'POST') {
    return await handleDeleteWebhook(request, url, config);
  }
  
  // 根路径 - HTML 页面
  if (url.pathname === '/' || url.pathname === '') {
    return htmlResponse(generateHtmlPage(url.origin, FILE_DB));
  }
  
  // API 文档 (JSON)
  if (url.pathname === '/api') {
    return jsonResponse(generateApiDoc(url.origin));
  }
  
  // 文件下载（无需密码）
  if (url.pathname.startsWith('/file/')) {
    return await handleFileDownload(url, FILE_DB, ENCRYPTION_KEY);
  }
  
  // ===== 以下接口需要密码验证 =====
  const password = getPassword(request, url);
  
  // 添加转发文件
  if (url.pathname === '/add-forwarded-file' && request.method === 'POST') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleAddForwardedFile(request, config, url);
  }
  
  // 获取文件列表 API
  if (url.pathname === '/files' && request.method === 'GET') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleGetFiles(url, FILE_DB, ENCRYPTION_KEY, url.origin);
  }
  
  // 删除文件 API
  if (url.pathname === '/delete-file' && request.method === 'POST') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleDeleteFile(request, FILE_DB);
  }
  
  // 搜索文件 API
  if (url.pathname === '/search' && request.method === 'GET') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleSearchFiles(url, FILE_DB, ENCRYPTION_KEY, url.origin);
  }
  
  // 清理无效链接 API
  if (url.pathname === '/clean' && request.method === 'POST') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleCleanInvalidLinks(request, FILE_DB, ENCRYPTION_KEY, url.origin);
  }
  
  // 验证链接 API
  if (url.pathname === '/verify' && request.method === 'GET') {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleVerifyLink(url, FILE_DB, ENCRYPTION_KEY);
  }
  
  // Bot API 代理
  if (url.pathname.startsWith('/bot/')) {
    if (!verifyPassword(password, ACCESS_PASSWORD)) {
      return jsonResponse({ error: '需要访问密码' }, 401);
    }
    return await handleBotApiProxy(request, config, url);
  }
  
  return jsonResponse({ error: '未知路径', path: url.pathname }, 404);
}

// ==================== 通用工具函数 ====================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function corsResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Access-Password',
      'Access-Control-Max-Age': '86400',
    }
  });
}

function getPassword(request, url) {
  return request.headers.get('X-Access-Password') || 
         url.searchParams.get('password') ||
         url.searchParams.get('pwd');
}

function verifyPassword(provided, required) {
  return provided === required;
}

function formatSize(bytes) {
  if (!bytes) return '未知';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(2)} ${units[i]}`;
}

function formatBeijingTime(date) {
  if (!date) date = new Date();
  return date.toLocaleString('zh-CN', { 
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).replace(/\//g, '-');
}

function formatBeijingDate(timestamp) {
  const date = new Date(timestamp * 1000);
  return date.toLocaleDateString('zh-CN', { 
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).replace(/\//g, '-');
}

function extractFileInfo(msg) {
  const fileTypes = [
    { key: 'document', getName: (f) => f.file_name || 'document' },
    { key: 'photo', getName: (f, msg) => `photo_${msg.message_id}.jpg`, isArray: true },
    { key: 'video', getName: (f) => f.file_name || `video.mp4` },
    { key: 'audio', getName: (f) => f.file_name || `audio.mp3` },
    { key: 'animation', getName: (f) => f.file_name || `animation.gif` },
    { key: 'voice', getName: (f, msg) => `voice_${msg.message_id}.ogg` },
    { key: 'video_note', getName: (f, msg) => `video_note_${msg.message_id}.mp4` },
    { key: 'sticker', getName: (f, msg) => `sticker_${msg.message_id}.webp` }
  ];
  
  for (const type of fileTypes) {
    if (msg[type.key]) {
      const file = type.isArray ? msg[type.key][msg[type.key].length - 1] : msg[type.key];
      return {
        fileId: file.file_id,
        filename: type.getName(file, msg),
        fileSize: file.file_size,
        fileType: type.key,
        mimeType: file.mime_type || null
      };
    }
  }
  
  return null;
}

function generateFileLinks(chatId, messageId, chatUsername, origin) {
  let channelIdentifier = null;
  let telegramLink = null;
  let friendlyUrl = null;
  
  if (chatUsername) {
    channelIdentifier = `@${chatUsername}`;
    telegramLink = `https://t.me/${chatUsername}/${messageId}`;
    friendlyUrl = `${origin}/file/@${chatUsername}/${messageId}`;
  } else if (chatId) {
    const cleanChatId = chatId.toString().replace(/^-100/, '');
    channelIdentifier = cleanChatId;
    telegramLink = `https://t.me/c/${cleanChatId}/${messageId}`;
    friendlyUrl = `${origin}/file/${cleanChatId}/${messageId}`;
  }
  
  return { channelIdentifier, telegramLink, friendlyUrl };
}

function getFileTypeIcon(filename) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  const icons = {
    jpg: '🖼', jpeg: '🖼', png: '🖼', gif: '🎞', webp: '🖼', svg: '🖼',
    mp4: '🎬', mkv: '🎬', avi: '🎬', mov: '🎬', webm: '🎬',
    mp3: '🎵', wav: '🎵', flac: '🎵', ogg: '🎵', m4a: '🎵',
    pdf: '📕', doc: '📘', docx: '📘', xls: '📗', xlsx: '📗', ppt: '📙', pptx: '📙',
    txt: '📄', md: '📝', json: '📋', xml: '📋', csv: '📊',
    zip: '📦', rar: '📦', '7z': '📦', tar: '📦', gz: '📦',
    js: '💻', ts: '💻', py: '💻', java: '💻', cpp: '💻', c: '💻', html: '💻', css: '💻',
    apk: '📱', exe: '⚙️', dmg: '💿', iso: '💿'
  };
  return icons[ext] || '📄';
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ==================== 加密解密函数 ====================

async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const keyBuffer = encoder.encode(key.padEnd(32, '0').substring(0, 32));
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBuffer, { name: 'AES-GCM' }, false, ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, cryptoKey, dataBuffer
  );
  
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  
  return btoa(String.fromCharCode(...combined))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function decryptData(encryptedData, key) {
  const encoder = new TextEncoder();
  const padding = '='.repeat((4 - encryptedData.length % 4) % 4);
  const base64 = encryptedData.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const combined = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);
  const keyBuffer = encoder.encode(key.padEnd(32, '0').substring(0, 32));
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBuffer, { name: 'AES-GCM' }, false, ['decrypt']
  );
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, cryptoKey, encrypted
  );
  
  return new TextDecoder().decode(decrypted);
}

// ==================== Telegram API 函数 ====================

async function sendTelegramRequest(token, method, data) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return response.json();
}

async function sendMessage(token, chatId, text, options = {}) {
  return sendTelegramRequest(token, 'sendMessage', {
    chat_id: chatId,
    text: text,
    parse_mode: 'HTML',
    ...options
  });
}

async function editMessage(token, chatId, messageId, text, options = {}) {
  return sendTelegramRequest(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text: text,
    parse_mode: 'HTML',
    ...options
  });
}

async function answerCallback(token, callbackId, text = '') {
  return sendTelegramRequest(token, 'answerCallbackQuery', {
    callback_query_id: callbackId,
    text: text
  });
}

async function getFile(token, fileId) {
  return sendTelegramRequest(token, 'getFile', { file_id: fileId });
}

async function deleteMessage(token, chatId, messageId) {
  return sendTelegramRequest(token, 'deleteMessage', {
    chat_id: chatId,
    message_id: messageId
  });
}

// ==================== 数据库操作函数 ====================

async function saveFileMapping(db, fileKey, encryptedData) {
  const timestamp = Math.floor(Date.now() / 1000);
  await db.prepare(
    'INSERT OR REPLACE INTO file_mappings (file_key, encrypted_data, created_at) VALUES (?, ?, ?)'
  ).bind(fileKey, encryptedData, timestamp).run();
}

async function getFileMapping(db, fileKey) {
  return db.prepare(
    'SELECT encrypted_data FROM file_mappings WHERE file_key = ?'
  ).bind(fileKey).first();
}

async function deleteFileMapping(db, fileKey) {
  return db.prepare('DELETE FROM file_mappings WHERE file_key = ?').bind(fileKey).run();
}

async function isAdmin(userId, db, adminIds) {
  if (adminIds.includes(userId.toString())) return true;
  if (!db) return false;
  
  const admin = await db.prepare(
    'SELECT user_id FROM admins WHERE user_id = ?'
  ).bind(userId).first();
  return !!admin;
}

async function isAuthorizedUser(userId, db) {
  if (!db) return false;
  const user = await db.prepare(
    'SELECT user_id FROM authorized_users WHERE user_id = ?'
  ).bind(userId).first();
  return !!user;
}

async function isAuthorizedChat(chatId, db) {
  if (!db) return false;
  const chat = await db.prepare(
    'SELECT chat_id FROM authorized_chats WHERE chat_id = ?'
  ).bind(chatId).first();
  return !!chat;
}

async function checkAuthorization(msg, db, adminIds) {
  const userId = msg.from?.id;
  const chatId = msg.chat.id;
  const chatType = msg.chat.type;
  
  if (userId && await isAdmin(userId, db, adminIds)) return true;
  if (!db) return true;
  
  if (chatType === 'private') {
    return await isAuthorizedUser(userId, db);
  } else {
    return await isAuthorizedChat(chatId, db);
  }
}

// ==================== 链接验证函数 ====================

async function verifyFileLink(fileData) {
  try {
    const telegramFileUrl = `https://api.telegram.org/file/bot${fileData.token}/${fileData.path}`;
    const response = await fetch(telegramFileUrl, { method: 'HEAD' });
    return response.ok;
  } catch (error) {
    return false;
  }
}

// ==================== 初始化数据库 ====================

async function handleInitDb(db, adminIds) {
  if (!db) {
    return jsonResponse({ error: '未配置 FILE_DB' }, 500);
  }
  
  try {
    const tables = [
      `CREATE TABLE IF NOT EXISTS file_mappings (
        file_key TEXT PRIMARY KEY,
        encrypted_data TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )`,
      `CREATE INDEX IF NOT EXISTS idx_created_at ON file_mappings(created_at)`,
      `CREATE TABLE IF NOT EXISTS authorized_users (
        user_id INTEGER PRIMARY KEY,
        username TEXT,
        first_name TEXT,
        added_by INTEGER,
        created_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS authorized_chats (
        chat_id INTEGER PRIMARY KEY,
        chat_title TEXT,
        chat_type TEXT,
        chat_username TEXT,
        added_by INTEGER,
        created_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS admins (
        user_id INTEGER PRIMARY KEY,
        username TEXT,
        first_name TEXT,
        created_at INTEGER NOT NULL
      )`
    ];
    
    for (const sql of tables) {
      await db.prepare(sql).run();
    }
    
    const timestamp = Math.floor(Date.now() / 1000);
    for (const adminId of adminIds) {
      await db.prepare(
        'INSERT OR IGNORE INTO admins (user_id, first_name, created_at) VALUES (?, ?, ?)'
      ).bind(parseInt(adminId), 'ENV_ADMIN', timestamp).run();
    }
    
    return jsonResponse({
      success: true,
      message: '数据库初始化成功',
      tables: ['file_mappings', 'authorized_users', 'authorized_chats', 'admins'],
      admin_count: adminIds.length
    });
  } catch (error) {
    return jsonResponse({ error: '初始化失败', detail: error.message }, 500);
  }
}

// ==================== Webhook 处理 ====================

async function handleWebhook(request, url, config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY, ADMIN_IDS } = config;
  const webhookToken = url.pathname.substring(9);
  
  if (!BOT_TOKEN || webhookToken !== BOT_TOKEN.split(':')[1]) {
    return new Response('Forbidden', { status: 403 });
  }
  
  try {
    const update = await request.json();
    console.log('收到更新:', JSON.stringify(update).substring(0, 500));
    
    // 处理回调查询
    if (update.callback_query) {
      await handleCallbackQuery(update.callback_query, config, url.origin);
      return new Response('OK');
    }
    
    const msg = update.message || update.channel_post || 
                update.edited_message || update.edited_channel_post;
    
    if (!msg) return new Response('OK');
    
    // 处理命令
    if (msg.text && msg.text.startsWith('/')) {
      await handleCommand(msg, config, url.origin);
      return new Response('OK');
    }
    
    // 验证授权
    if (!await checkAuthorization(msg, FILE_DB, ADMIN_IDS)) {
      if (msg.chat.type === 'private') {
        await sendMessage(BOT_TOKEN, msg.chat.id, 
          '⛔ <b>未授权</b>\n\n您没有使用权限，请联系管理员。\n\n' +
          `您的用户ID: <code>${msg.from.id}</code>`
        );
      }
      return new Response('OK');
    }
    
    // 处理文件
    const fileInfo = extractFileInfo(msg);
    if (fileInfo) {
      const result = await processAndSaveFile(msg, fileInfo, config, url.origin);
      if (result?.success) {
        await sendFileNotification(BOT_TOKEN, msg.chat.id, result, msg.message_id);
      }
    }
    
    return new Response('OK');
  } catch (error) {
    console.error('Webhook 处理失败:', error);
    return new Response('OK');
  }
}

async function processAndSaveFile(msg, fileInfo, config, origin) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  try {
    const fileResult = await getFile(BOT_TOKEN, fileInfo.fileId);
    if (!fileResult.ok || !fileResult.result.file_path) return null;
    
    const chatId = msg.chat.id;
    const messageId = msg.message_id;
    const chatUsername = msg.chat.username;
    
    const data = {
      token: BOT_TOKEN,
      path: fileResult.result.file_path,
      file_id: fileInfo.fileId, // 保存 file_id 用于刷新链接
      filename: fileInfo.filename,
      message_id: messageId,
      message_thread_id: msg.message_thread_id || null,
      chat_id: chatId,
      file_size: fileInfo.fileSize || fileResult.result.file_size
    };
    
    const encrypted = await encryptData(JSON.stringify(data), ENCRYPTION_KEY);
    const links = generateFileLinks(chatId, messageId, chatUsername, origin);
    
    if (FILE_DB && links.channelIdentifier) {
      const fileKey = `${links.channelIdentifier}/${messageId}`;
      await saveFileMapping(FILE_DB, fileKey, encrypted);
      
      if (msg.chat.type !== 'private') {
        await FILE_DB.prepare(
          'UPDATE authorized_chats SET chat_title = ?, chat_username = ?, chat_type = ? WHERE chat_id = ?'
        ).bind(msg.chat.title || null, chatUsername || null, msg.chat.type, chatId).run();
      }
    }
    
    return {
      success: true,
      fileKey: links.channelIdentifier ? `${links.channelIdentifier}/${messageId}` : null,
      filename: fileInfo.filename,
      fileType: fileInfo.fileType,
      size: fileInfo.fileSize || fileResult.result.file_size,
      downloadUrl: links.friendlyUrl,
      telegramLink: links.telegramLink,
      messageId: messageId
    };
  } catch (error) {
    console.error('保存文件失败:', error);
    return null;
  }
}

async function sendFileNotification(token, chatId, result, replyToMessageId) {
  const icon = getFileTypeIcon(result.filename);
  const size = formatSize(result.size);
  const time = formatBeijingTime(new Date());
  const isLargeFile = result.size && result.size > 20 * 1024 * 1024;
  
  let text = `✅ <b>文件已保存</b>\n\n` +
    `${icon} <b>文件名:</b> ${escapeHtml(result.filename)}\n` +
    `📦 <b>大小:</b> ${size}\n` +
    `🔢 <b>消息ID:</b> <code>${result.messageId}</code>\n` +
    `⏰ <b>时间:</b> ${time}\n\n` +
    `🔗 <b>下载链接:</b>\n<code>${result.downloadUrl}</code>`;
  
  if (isLargeFile) {
    text += `\n\n⚠️ <b>注意:</b> 此文件超过 20MB，请点击下方按钮在 Telegram 中直接下载。`;
  }
  
  const keyboard = { inline_keyboard: [] };
  
  if (isLargeFile) {
    // 大文件优先显示 Telegram 链接
    keyboard.inline_keyboard.push([
      { text: '📱 在 Telegram 中下载', url: result.telegramLink }
    ]);
    keyboard.inline_keyboard.push([
      { text: '🔗 打开代理链接 (查看说明)', url: result.downloadUrl }
    ]);
  } else {
    keyboard.inline_keyboard.push([
      { text: '🔗 打开链接', url: result.downloadUrl },
      { text: '📨 查看原消息', url: result.telegramLink }
    ]);
  }
  
  await sendMessage(token, chatId, text, {
    reply_to_message_id: replyToMessageId,
    reply_markup: keyboard,
    disable_web_page_preview: true
  });
}

// ==================== 命令处理 ====================

async function handleCommand(msg, config, origin) {
  const { BOT_TOKEN, FILE_DB, ADMIN_IDS } = config;
  const text = msg.text;
  const chatId = msg.chat.id;
  const userId = msg.from?.id;
  const isUserAdmin = await isAdmin(userId, FILE_DB, ADMIN_IDS);
  
  const [command, ...args] = text.split(' ');
  const cmd = command.split('@')[0].toLowerCase();
  
  const handlers = {
    '/start': () => handleStartCommand(chatId, userId, isUserAdmin, config),
    '/help': () => handleHelpCommand(chatId, isUserAdmin, config),
    '/myid': () => handleMyIdCommand(msg, config),
    '/list': () => handleListCommand(chatId, args[0], config, origin),
    '/stats': () => handleStatsCommand(chatId, isUserAdmin, config),
    '/adduser': () => handleAddUserCommand(chatId, userId, args[0], isUserAdmin, config),
    '/deluser': () => handleDelUserCommand(chatId, args[0], isUserAdmin, config),
    '/addchat': () => handleAddChatCommand(chatId, userId, args[0], isUserAdmin, config),
    '/delchat': () => handleDelChatCommand(chatId, args[0], isUserAdmin, config),
    '/listusers': () => handleListUsersCommand(chatId, isUserAdmin, config),
    '/listchats': () => handleListChatsCommand(chatId, isUserAdmin, config),
    '/addadmin': () => handleAddAdminCommand(chatId, args[0], isUserAdmin, config),
    '/deladmin': () => handleDelAdminCommand(chatId, args[0], isUserAdmin, config, ADMIN_IDS),
    '/search': () => handleSearchCommand(chatId, args.join(' '), isUserAdmin, config, origin),
    '/delete': () => handleDeleteCommand(chatId, args[0], isUserAdmin, config),
    '/clean': () => handleCleanCommand(chatId, args[0], isUserAdmin, config),
    '/verify': () => handleVerifyCommand(chatId, args[0], isUserAdmin, config),
    '/info': () => handleInfoCommand(chatId, args[0], isUserAdmin, config, origin)
  };
  
  const handler = handlers[cmd];
  if (handler) {
    await handler();
  }
}

async function handleStartCommand(chatId, userId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  const keyboard = {
    inline_keyboard: [
      [
        { text: '📋 我的文件', callback_data: 'my_files' },
        { text: '❓ 帮助', callback_data: 'help' }
      ]
    ]
  };
  
  if (isUserAdmin) {
    keyboard.inline_keyboard.push(
      [
        { text: '👤 用户管理', callback_data: 'manage_users' },
        { text: '👥 群组管理', callback_data: 'manage_chats' }
      ],
      [
        { text: '📊 统计', callback_data: 'stats' },
        { text: '🧹 清理无效链接', callback_data: 'clean_prompt' }
      ]
    );
  }
  
  let statusText = '';
  if (isUserAdmin) {
    statusText = '🔑 <b>您是管理员</b>';
  } else {
    const isAuth = await isAuthorizedUser(userId, FILE_DB);
    statusText = isAuth ? '✅ <b>您已授权</b>' : '⛔ <b>未授权</b> - 请联系管理员';
  }
  
  const text = `👋 <b>欢迎使用 Telegram 文件代理服务</b>\n\n` +
    `<b>功能介绍：</b>\n` +
    `📤 自动保存群组/频道文件\n` +
    `🔗 生成永久下载链接\n` +
    `🔒 AES-256 加密存储\n` +
    `🧹 无效链接自动清理\n\n` +
    `${statusText}\n\n` +
    `<i>发送任意文件即可自动保存</i>`;
  
  await sendMessage(BOT_TOKEN, chatId, text, { reply_markup: keyboard });
}

async function handleHelpCommand(chatId, isUserAdmin, config) {
  const { BOT_TOKEN } = config;
  
  let text = `📖 <b>使用帮助</b>\n\n` +
    `<b>基本命令：</b>\n` +
    `• /start - 开始使用\n` +
    `• /help - 查看帮助\n` +
    `• /list - 查看已保存的文件\n` +
    `• /myid - 查看您的用户ID\n\n` +
    `<b>使用方法：</b>\n` +
    `1️⃣ 直接发送文件给我\n` +
    `2️⃣ 将我添加到群组/频道\n` +
    `3️⃣ 自动生成下载链接\n\n` +
    `<b>⚠️ 文件大小限制：</b>\n` +
    `• 代理下载: ≤ 20MB\n` +
    `• 超过 20MB 请在 Telegram 中直接下载\n`;
  
  if (isUserAdmin) {
    text += `\n<b>管理员命令：</b>\n` +
      `• /adduser &lt;ID&gt; - 授权用户\n` +
      `• /deluser &lt;ID&gt; - 取消授权\n` +
      `• /addchat &lt;ID&gt; - 授权群组\n` +
      `• /delchat &lt;ID&gt; - 取消授权\n` +
      `• /listusers - 查看授权用户\n` +
      `• /listchats - 查看授权群组\n` +
      `• /search &lt;关键词&gt; - 搜索文件\n` +
      `• /info &lt;file_key&gt; - 查看文件详情\n` +
      `• /delete &lt;file_key&gt; - 删除文件\n` +
      `• /clean - 清理无效链接\n` +
      `• /verify &lt;file_key&gt; - 验证链接\n` +
      `• /stats - 查看统计\n`;
  }
  
  const keyboard = {
    inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
  };
  
  await sendMessage(BOT_TOKEN, chatId, text, { reply_markup: keyboard });
}

async function handleMyIdCommand(msg, config) {
  const { BOT_TOKEN } = config;
  
  let text = `🆔 <b>ID 信息</b>\n\n` +
    `👤 <b>用户ID:</b> <code>${msg.from.id}</code>\n` +
    `💬 <b>聊天ID:</b> <code>${msg.chat.id}</code>\n` +
    `📝 <b>类型:</b> ${msg.chat.type}`;
  
  if (msg.chat.username) {
    text += `\n🔗 <b>用户名:</b> @${msg.chat.username}`;
  }
  if (msg.message_thread_id) {
    text += `\n🧵 <b>话题ID:</b> <code>${msg.message_thread_id}</code>`;
  }
  
  await sendMessage(BOT_TOKEN, msg.chat.id, text);
}

async function handleListCommand(chatId, pageArg, config, origin) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!FILE_DB) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 数据库未配置');
    return;
  }
  
  const page = parseInt(pageArg) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;
  
  try {
    const files = await FILE_DB.prepare(
      'SELECT file_key, created_at FROM file_mappings ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all();
    
    const total = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    const totalPages = Math.ceil((total?.count || 0) / limit);
    
    if (!files.results?.length) {
      await sendMessage(BOT_TOKEN, chatId, '📭 暂无保存的文件');
      return;
    }
    
    let text = `📋 <b>已保存的文件</b> (第 ${page}/${totalPages} 页)\n\n`;
    
    for (const file of files.results) {
      const date = formatBeijingDate(file.created_at);
      const icon = getFileTypeIcon(file.file_key);
      text += `${icon} <code>${origin}/file/${file.file_key}</code>\n`;
      text += `   📅 ${date}\n\n`;
    }
    
    const keyboard = { inline_keyboard: [] };
    const nav = [];
    if (page > 1) nav.push({ text: '⬅️ 上一页', callback_data: `list_page_${page - 1}` });
    if (page < totalPages) nav.push({ text: '➡️ 下一页', callback_data: `list_page_${page + 1}` });
    if (nav.length) keyboard.inline_keyboard.push(nav);
    keyboard.inline_keyboard.push([{ text: '🔄 刷新', callback_data: `list_page_${page}` }]);
    
    await sendMessage(BOT_TOKEN, chatId, text, { 
      reply_markup: keyboard,
      disable_web_page_preview: true 
    });
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 查询失败: ${error.message}`);
  }
}

async function handleStatsCommand(chatId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  if (!FILE_DB) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 数据库未配置');
    return;
  }
  
  try {
    const [files, users, chats, admins] = await Promise.all([
      FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM authorized_users').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM authorized_chats').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM admins').first()
    ]);
    
    const weekAgo = Math.floor(Date.now() / 1000) - 7 * 24 * 60 * 60;
    const recentFiles = await FILE_DB.prepare(
      'SELECT COUNT(*) as count FROM file_mappings WHERE created_at > ?'
    ).bind(weekAgo).first();
    
    const text = `📊 <b>服务统计</b>\n\n` +
      `📁 <b>总文件数:</b> ${files?.count || 0}\n` +
      `📈 <b>近7天新增:</b> ${recentFiles?.count || 0}\n` +
      `👤 <b>授权用户:</b> ${users?.count || 0}\n` +
      `👥 <b>授权群组:</b> ${chats?.count || 0}\n` +
      `🔑 <b>管理员:</b> ${admins?.count || 0}\n\n` +
      `⏰ <b>统计时间:</b> ${formatBeijingTime(new Date())}`;
    
    const keyboard = {
      inline_keyboard: [[{ text: '🔄 刷新', callback_data: 'stats' }]]
    };
    
    await sendMessage(BOT_TOKEN, chatId, text, { reply_markup: keyboard });
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 统计失败: ${error.message}`);
  }
}

async function handleAddUserCommand(chatId, operatorId, targetId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 请提供有效的用户ID\n\n用法: <code>/adduser 123456789</code>');
    return;
  }
  
  try {
    const timestamp = Math.floor(Date.now() / 1000);
    await FILE_DB.prepare(
      'INSERT OR REPLACE INTO authorized_users (user_id, added_by, created_at) VALUES (?, ?, ?)'
    ).bind(id, operatorId, timestamp).run();
    
    await sendMessage(BOT_TOKEN, chatId, `✅ 已授权用户: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleDelUserCommand(chatId, targetId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 请提供有效的用户ID');
    return;
  }
  
  try {
    await FILE_DB.prepare('DELETE FROM authorized_users WHERE user_id = ?').bind(id).run();
    await sendMessage(BOT_TOKEN, chatId, `✅ 已取消授权: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleAddChatCommand(chatId, operatorId, targetId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, 
      '❌ 请提供有效的群组/频道ID\n\n' +
      '用法: <code>/addchat -1001234567890</code>\n\n' +
      '💡 提示: 使用 /myid 获取当前群组ID'
    );
    return;
  }
  
  try {
    const timestamp = Math.floor(Date.now() / 1000);
    await FILE_DB.prepare(
      'INSERT OR REPLACE INTO authorized_chats (chat_id, added_by, created_at) VALUES (?, ?, ?)'
    ).bind(id, operatorId, timestamp).run();
    
    await sendMessage(BOT_TOKEN, chatId, `✅ 已授权群组/频道: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleDelChatCommand(chatId, targetId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 请提供有效的群组/频道ID');
    return;
  }
  
  try {
    await FILE_DB.prepare('DELETE FROM authorized_chats WHERE chat_id = ?').bind(id).run();
    await sendMessage(BOT_TOKEN, chatId, `✅ 已取消授权: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleListUsersCommand(chatId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  try {
    const users = await FILE_DB.prepare(
      'SELECT * FROM authorized_users ORDER BY created_at DESC'
    ).all();
    
    if (!users.results?.length) {
      await sendMessage(BOT_TOKEN, chatId, '📭 暂无授权用户');
      return;
    }
    
    let text = `👤 <b>授权用户列表</b> (${users.results.length})\n\n`;
    for (const user of users.results) {
      const date = formatBeijingDate(user.created_at);
      text += `• <code>${user.user_id}</code>`;
      if (user.username) text += ` @${user.username}`;
      if (user.first_name) text += ` (${user.first_name})`;
      text += `\n  📅 ${date}\n`;
    }
    
    await sendMessage(BOT_TOKEN, chatId, text);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 查询失败: ${error.message}`);
  }
}

async function handleListChatsCommand(chatId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  try {
    const chats = await FILE_DB.prepare(
      'SELECT * FROM authorized_chats ORDER BY created_at DESC'
    ).all();
    
    if (!chats.results?.length) {
      await sendMessage(BOT_TOKEN, chatId, '📭 暂无授权群组/频道');
      return;
    }
    
    let text = `👥 <b>授权群组/频道</b> (${chats.results.length})\n\n`;
    for (const chat of chats.results) {
      const date = formatBeijingDate(chat.created_at);
      text += `• <code>${chat.chat_id}</code>`;
      if (chat.chat_username) text += ` @${chat.chat_username}`;
      if (chat.chat_title) text += `\n  📝 ${chat.chat_title}`;
      text += `\n  📅 ${date}\n\n`;
    }
    
    await sendMessage(BOT_TOKEN, chatId, text);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 查询失败: ${error.message}`);
  }
}

async function handleAddAdminCommand(chatId, targetId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 请提供有效的用户ID');
    return;
  }
  
  try {
    const timestamp = Math.floor(Date.now() / 1000);
    await FILE_DB.prepare(
      'INSERT OR REPLACE INTO admins (user_id, created_at) VALUES (?, ?)'
    ).bind(id, timestamp).run();
    
    await sendMessage(BOT_TOKEN, chatId, `✅ 已添加管理员: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleDelAdminCommand(chatId, targetId, isUserAdmin, config, envAdminIds) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  const id = parseInt(targetId);
  if (!id) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 请提供有效的用户ID');
    return;
  }
  
  if (envAdminIds.includes(id.toString())) {
    await sendMessage(BOT_TOKEN, chatId, '❌ 无法删除环境变量中配置的管理员');
    return;
  }
  
  try {
    await FILE_DB.prepare('DELETE FROM admins WHERE user_id = ?').bind(id).run();
    await sendMessage(BOT_TOKEN, chatId, `✅ 已删除管理员: <code>${id}</code>`);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 操作失败: ${error.message}`);
  }
}

async function handleSearchCommand(chatId, keyword, isUserAdmin, config, origin) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  if (!keyword) {
    await sendMessage(BOT_TOKEN, chatId, 
      '🔍 <b>搜索文件</b>\n\n' +
      '用法: <code>/search 关键词</code>\n\n' +
      '示例:\n' +
      '• <code>/search photo</code>\n' +
      '• <code>/search .pdf</code>\n' +
      '• <code>/search @channel</code>'
    );
    return;
  }
  
  try {
    const files = await FILE_DB.prepare(
      'SELECT file_key, encrypted_data, created_at FROM file_mappings WHERE file_key LIKE ? ORDER BY created_at DESC LIMIT 20'
    ).bind(`%${keyword}%`).all();
    
    if (!files.results?.length) {
      await sendMessage(BOT_TOKEN, chatId, `🔍 未找到包含 "<code>${escapeHtml(keyword)}</code>" 的文件`);
      return;
    }
    
    let text = `🔍 <b>搜索结果</b> (${files.results.length})\n\n`;
    
    for (const file of files.results) {
      try {
        const decrypted = JSON.parse(await decryptData(file.encrypted_data, ENCRYPTION_KEY));
        const icon = getFileTypeIcon(decrypted.filename);
        const date = formatBeijingDate(file.created_at);
        
        text += `${icon} <b>${escapeHtml(decrypted.filename)}</b>\n`;
        text += `   🔗 <code>${origin}/file/${file.file_key}</code>\n`;
        text += `   📅 ${date}\n\n`;
      } catch (e) {
        text += `📄 <code>${file.file_key}</code>\n\n`;
      }
    }
    
    await sendMessage(BOT_TOKEN, chatId, text, { disable_web_page_preview: true });
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 搜索失败: ${error.message}`);
  }
}

async function handleDeleteCommand(chatId, fileKey, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  if (!fileKey) {
    await sendMessage(BOT_TOKEN, chatId, 
      '🗑 <b>删除文件</b>\n\n' +
      '用法: <code>/delete file_key</code>\n\n' +
      '示例: <code>/delete @channel/123</code>'
    );
    return;
  }
  
  try {
    const result = await FILE_DB.prepare(
      'DELETE FROM file_mappings WHERE file_key = ?'
    ).bind(fileKey).run();
    
    if (result.meta?.changes > 0) {
      await sendMessage(BOT_TOKEN, chatId, `✅ 已删除: <code>${escapeHtml(fileKey)}</code>`);
    } else {
      await sendMessage(BOT_TOKEN, chatId, `❌ 未找到: <code>${escapeHtml(fileKey)}</code>`);
    }
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 删除失败: ${error.message}`);
  }
}

// 清理无效链接命令 - 自动分批循环直到全部清完
async function handleCleanCommand(chatId, countArg, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY, ADMIN_IDS } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  // 发送开始消息
  const startMsg = await sendMessage(BOT_TOKEN, chatId, 
    `🔍 <b>开始全量清理无效链接...</b>\n\n` +
    `⏳ 正在分批检测，请稍候...\n` +
    `每批检查 40 个链接（Cloudflare 限制）`
  );
  
  try {
    // 获取总数
    const totalResult = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    const totalCount = totalResult?.count || 0;
    
    if (totalCount === 0) {
      await sendMessage(BOT_TOKEN, chatId, '📭 数据库中没有文件');
      return;
    }
    
    let totalChecked = 0;
    let totalValid = 0;
    let totalInvalid = 0;
    let batchNumber = 0;
    const batchSize = 40;
    const allInvalidKeys = [];
    
    // 分批循环检测
    while (true) {
      batchNumber++;
      
      // 每次获取最旧的 40 个（按创建时间正序，这样删除后不影响偏移）
      const files = await FILE_DB.prepare(
        'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at ASC LIMIT ?'
      ).bind(batchSize).all();
      
      if (!files.results?.length) {
        break; // 没有更多文件了
      }
      
      let batchValid = 0;
      let batchInvalid = 0;
      const batchInvalidKeys = [];
      
      for (const file of files.results) {
        try {
          const decrypted = JSON.parse(await decryptData(file.encrypted_data, ENCRYPTION_KEY));
          const isValid = await verifyFileLink(decrypted);
          
          if (isValid) {
            batchValid++;
          } else {
            batchInvalid++;
            batchInvalidKeys.push({
              key: file.file_key,
              filename: decrypted.filename || '未知'
            });
          }
        } catch (e) {
          batchInvalid++;
          batchInvalidKeys.push({
            key: file.file_key,
            filename: '解密失败'
          });
        }
      }
      
      // 立即删除本批无效链接
      for (const item of batchInvalidKeys) {
        await deleteFileMapping(FILE_DB, item.key);
        allInvalidKeys.push(item);
      }
      
      totalChecked += files.results.length;
      totalValid += batchValid;
      totalInvalid += batchInvalid;
      
      // 更新进度消息（每 3 批更新一次，避免频率限制）
      if (batchNumber % 3 === 0) {
        try {
          await editMessage(BOT_TOKEN, chatId, startMsg.result?.message_id,
            `🔍 <b>正在清理无效链接...</b>\n\n` +
            `📊 进度: 第 ${batchNumber} 批\n` +
            `📁 已检查: ${totalChecked} / ${totalCount}\n` +
            `✅ 有效: ${totalValid}\n` +
            `❌ 无效: ${totalInvalid}\n\n` +
            `⏳ 继续检测中...`
          );
        } catch (e) {
          // 忽略编辑消息失败
        }
      }
      
      // 如果本批没有无效链接，且已检查的数量等于总数，说明全部检查完了
      if (files.results.length < batchSize) {
        break; // 最后一批，数量不足 batchSize
      }
      
      // 如果没有删除任何链接，需要手动跳过这批（避免死循环）
      // 使用 OFFSET 来跳过已检查的有效链接
      if (batchInvalid === 0) {
        // 所有链接都有效，检查下一批
        const remainingResult = await FILE_DB.prepare(
          'SELECT COUNT(*) as count FROM file_mappings'
        ).first();
        
        if (remainingResult?.count <= totalValid) {
          break; // 剩余的都是有效的
        }
        
        // 继续检查（但需要跳过已检查的有效链接）
        // 由于有效链接没有被删除，我们需要用 OFFSET
        const nextFiles = await FILE_DB.prepare(
          'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at ASC LIMIT ? OFFSET ?'
        ).bind(batchSize, totalValid).all();
        
        if (!nextFiles.results?.length) {
          break;
        }
        
        // 检查下一批
        continue;
      }
    }
    
    // 生成最终报告
    const finalReport = generateCleanReport(totalCount, totalChecked, totalValid, totalInvalid, allInvalidKeys);
    
    // 发送最终报告
    await sendMessage(BOT_TOKEN, chatId, finalReport);
    
    // 如果是通过命令触发的，同时通知其他管理员
    if (ADMIN_IDS && ADMIN_IDS.length > 0 && totalInvalid > 0) {
      for (const adminId of ADMIN_IDS) {
        if (adminId.toString() !== chatId.toString()) {
          try {
            await sendMessage(BOT_TOKEN, parseInt(adminId), 
              `📋 <b>自动清理报告</b>\n\n` + finalReport
            );
          } catch (e) {
            // 忽略发送失败
          }
        }
      }
    }
    
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 清理失败: ${error.message}`);
  }
}

// 生成清理报告
function generateCleanReport(total, checked, valid, invalid, invalidKeys) {
  const time = formatBeijingTime(new Date());
  
  let report = `🧹 <b>清理完成！</b>\n\n` +
    `📊 <b>统计信息</b>\n` +
    `━━━━━━━━━━━━━━━\n` +
    `📁 原有文件: ${total}\n` +
    `🔍 已检查: ${checked}\n` +
    `✅ 有效链接: ${valid}\n` +
    `❌ 无效链接: ${invalid}\n` +
    `📁 剩余文件: ${total - invalid}\n` +
    `━━━━━━━━━━━━━━━\n\n`;
  
  if (invalid > 0) {
    report += `<b>已删除的无效链接:</b>\n`;
    for (const item of invalidKeys.slice(0, 10)) {
      const icon = getFileTypeIcon(item.filename);
      report += `${icon} ${escapeHtml(item.filename)}\n`;
    }
    if (invalidKeys.length > 10) {
      report += `\n<i>...共 ${invalidKeys.length} 个</i>\n`;
    }
  } else {
    report += `🎉 所有链接都有效！\n`;
  }
  
  report += `\n⏰ ${time}`;
  
  return report;
}

// 查看文件详情命令
async function handleInfoCommand(chatId, fileKey, isUserAdmin, config, origin) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  if (!fileKey) {
    await sendMessage(BOT_TOKEN, chatId, 
      '📄 <b>查看文件详情</b>\n\n' +
      '用法: <code>/info file_key</code>\n\n' +
      '示例: <code>/info @channel/123</code>'
    );
    return;
  }
  
  try {
    const result = await FILE_DB.prepare(
      'SELECT encrypted_data, created_at FROM file_mappings WHERE file_key = ?'
    ).bind(fileKey).first();
    
    if (!result) {
      await sendMessage(BOT_TOKEN, chatId, `❌ 未找到: <code>${escapeHtml(fileKey)}</code>`);
      return;
    }
    
    const decrypted = JSON.parse(await decryptData(result.encrypted_data, ENCRYPTION_KEY));
    const date = formatBeijingTime(new Date(result.created_at * 1000));
    const icon = getFileTypeIcon(decrypted.filename);
    const size = formatSize(decrypted.file_size);
    const telegramLink = generateTelegramLink(decrypted);
    const downloadUrl = `${origin}/file/${fileKey}`;
    
    // 检查文件是否超过 20MB
    const isLargeFile = decrypted.file_size && decrypted.file_size > 20 * 1024 * 1024;
    
    let text = `📄 <b>文件详情</b>\n\n` +
      `${icon} <b>文件名:</b> ${escapeHtml(decrypted.filename)}\n` +
      `📦 <b>大小:</b> ${size}\n` +
      `🔗 <b>Key:</b> <code>${escapeHtml(fileKey)}</code>\n` +
      `📅 <b>创建时间:</b> ${date}\n\n` +
      `🔗 <b>下载链接:</b>\n<code>${downloadUrl}</code>\n`;
    
    if (isLargeFile) {
      text += `\n⚠️ <b>注意:</b> 此文件超过 20MB，无法通过代理下载，请在 Telegram 中直接下载。\n`;
    }
    
    const keyboard = { inline_keyboard: [] };
    
    if (telegramLink) {
      keyboard.inline_keyboard.push([
        { text: '📱 在 Telegram 中打开', url: telegramLink }
      ]);
    }
    
    if (!isLargeFile) {
      keyboard.inline_keyboard.push([
        { text: '🔗 打开下载链接', url: downloadUrl }
      ]);
    }
    
    keyboard.inline_keyboard.push([
      { text: '🗑 删除此文件', callback_data: `delete_file_${fileKey}` }
    ]);
    
    await sendMessage(BOT_TOKEN, chatId, text, { 
      reply_markup: keyboard,
      disable_web_page_preview: true 
    });
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 查询失败: ${error.message}`);
  }
}

// 验证单个链接命令
async function handleVerifyCommand(chatId, fileKey, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  if (!isUserAdmin) {
    await sendMessage(BOT_TOKEN, chatId, '⛔ 需要管理员权限');
    return;
  }
  
  if (!fileKey) {
    await sendMessage(BOT_TOKEN, chatId, 
      '🔍 <b>验证链接</b>\n\n' +
      '用法: <code>/verify file_key</code>\n\n' +
      '示例: <code>/verify @channel/123</code>'
    );
    return;
  }
  
  try {
    const result = await FILE_DB.prepare(
      'SELECT encrypted_data, created_at FROM file_mappings WHERE file_key = ?'
    ).bind(fileKey).first();
    
    if (!result) {
      await sendMessage(BOT_TOKEN, chatId, `❌ 未找到: <code>${escapeHtml(fileKey)}</code>`);
      return;
    }
    
    const decrypted = JSON.parse(await decryptData(result.encrypted_data, ENCRYPTION_KEY));
    const isValid = await verifyFileLink(decrypted);
    const date = formatBeijingDate(result.created_at);
    const icon = getFileTypeIcon(decrypted.filename);
    
    let text = `🔍 <b>链接验证结果</b>\n\n` +
      `${icon} <b>文件名:</b> ${escapeHtml(decrypted.filename)}\n` +
      `🔗 <b>Key:</b> <code>${escapeHtml(fileKey)}</code>\n` +
      `📅 <b>创建时间:</b> ${date}\n\n`;
    
    if (isValid) {
      text += `✅ <b>状态:</b> 链接有效`;
    } else {
      text += `❌ <b>状态:</b> 链接无效（文件可能已被删除）`;
      
      const keyboard = {
        inline_keyboard: [
          [{ text: '🗑 删除此记录', callback_data: `delete_file_${fileKey}` }]
        ]
      };
      
      await sendMessage(BOT_TOKEN, chatId, text, { reply_markup: keyboard });
      return;
    }
    
    await sendMessage(BOT_TOKEN, chatId, text);
  } catch (error) {
    await sendMessage(BOT_TOKEN, chatId, `❌ 验证失败: ${error.message}`);
  }
}

// ==================== 回调查询处理 ====================

async function handleCallbackQuery(query, config, origin) {
  const { BOT_TOKEN, FILE_DB, ADMIN_IDS, ENCRYPTION_KEY } = config;
  const chatId = query.message.chat.id;
  const messageId = query.message.message_id;
  const data = query.data;
  const userId = query.from.id;
  
  await answerCallback(BOT_TOKEN, query.id);
  
  if (!data) return;
  
  const isUserAdmin = await isAdmin(userId, FILE_DB, ADMIN_IDS);
  
  // 处理各种回调
  if (data === 'help') {
    await handleHelpCallback(chatId, messageId, isUserAdmin, config);
  } else if (data === 'my_files') {
    await handleMyFilesCallback(chatId, messageId, config, origin);
  } else if (data === 'back_to_start') {
    await handleBackToStartCallback(chatId, messageId, userId, isUserAdmin, config);
  } else if (data === 'manage_users') {
    await handleManageUsersCallback(chatId, messageId, isUserAdmin, config);
  } else if (data === 'manage_chats') {
    await handleManageChatsCallback(chatId, messageId, isUserAdmin, config);
  } else if (data === 'stats') {
    await handleStatsCallback(chatId, messageId, isUserAdmin, config);
  } else if (data === 'clean_prompt') {
    await handleCleanPromptCallback(chatId, messageId, isUserAdmin, config);
  } else if (data.startsWith('list_page_')) {
    const page = parseInt(data.replace('list_page_', ''));
    await handleListPageCallback(chatId, messageId, page, config, origin);
  } else if (data === 'clean_run_all' || data.startsWith('clean_run_')) {
    await handleCleanRunCallback(chatId, messageId, 0, isUserAdmin, config);
  } else if (data.startsWith('clean_confirm_')) {
    const count = parseInt(data.replace('clean_confirm_', ''));
    await handleCleanConfirmCallback(chatId, messageId, count, isUserAdmin, config);
  } else if (data.startsWith('delete_file_')) {
    const fileKey = data.replace('delete_file_', '');
    await handleDeleteFileCallback(chatId, messageId, fileKey, isUserAdmin, config);
  }
}

async function handleHelpCallback(chatId, messageId, isUserAdmin, config) {
  const { BOT_TOKEN } = config;
  
  let text = `📖 <b>使用帮助</b>\n\n` +
    `<b>基本功能：</b>\n` +
    `发送任意文件，自动保存并生成下载链接\n\n` +
    `<b>支持的文件类型：</b>\n` +
    `📄 文档 | 🖼 图片 | 🎬 视频\n` +
    `🎵 音频 | 🎤 语音 | 📍 贴纸\n\n` +
    `<b>常用命令：</b>\n` +
    `• /list - 查看文件列表\n` +
    `• /myid - 查看用户ID`;
  
  if (isUserAdmin) {
    text += `\n• /stats - 统计信息\n• /search - 搜索文件\n• /clean - 清理无效链接`;
  }
  
  const keyboard = {
    inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
  };
  
  await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
}

async function handleMyFilesCallback(chatId, messageId, config, origin) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!FILE_DB) {
    await editMessage(BOT_TOKEN, chatId, messageId, '❌ 数据库未配置', {
      reply_markup: { inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]] }
    });
    return;
  }
  
  try {
    const files = await FILE_DB.prepare(
      'SELECT file_key, created_at FROM file_mappings ORDER BY created_at DESC LIMIT 10'
    ).all();
    
    const total = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    const totalPages = Math.ceil((total?.count || 0) / 10);
    
    if (!files.results?.length) {
      await editMessage(BOT_TOKEN, chatId, messageId, '📭 暂无保存的文件', {
        reply_markup: { inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]] }
      });
      return;
    }
    
    let text = `📋 <b>已保存的文件</b> (第 1/${totalPages} 页)\n\n`;
    for (const file of files.results) {
      const date = formatBeijingDate(file.created_at);
      const icon = getFileTypeIcon(file.file_key);
      text += `${icon} <code>${origin}/file/${file.file_key}</code>\n`;
      text += `   📅 ${date}\n\n`;
    }
    
    const keyboard = { inline_keyboard: [] };
    if (totalPages > 1) {
      keyboard.inline_keyboard.push([{ text: '➡️ 下一页', callback_data: 'list_page_2' }]);
    }
    keyboard.inline_keyboard.push([{ text: '⬅️ 返回', callback_data: 'back_to_start' }]);
    
    await editMessage(BOT_TOKEN, chatId, messageId, text, { 
      reply_markup: keyboard,
      disable_web_page_preview: true 
    });
  } catch (error) {
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 查询失败: ${error.message}`);
  }
}

async function handleBackToStartCallback(chatId, messageId, userId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  const keyboard = {
    inline_keyboard: [
      [
        { text: '📋 我的文件', callback_data: 'my_files' },
        { text: '❓ 帮助', callback_data: 'help' }
      ]
    ]
  };
  
  if (isUserAdmin) {
    keyboard.inline_keyboard.push(
      [
        { text: '👤 用户管理', callback_data: 'manage_users' },
        { text: '👥 群组管理', callback_data: 'manage_chats' }
      ],
      [
        { text: '📊 统计', callback_data: 'stats' },
        { text: '🧹 清理无效链接', callback_data: 'clean_prompt' }
      ]
    );
  }
  
  let statusText = '';
  if (isUserAdmin) {
    statusText = '🔑 <b>您是管理员</b>';
  } else {
    const isAuth = await isAuthorizedUser(userId, FILE_DB);
    statusText = isAuth ? '✅ <b>您已授权</b>' : '⛔ <b>未授权</b>';
  }
  
  const text = `👋 <b>欢迎使用 Telegram 文件代理服务</b>\n\n` +
    `<b>功能介绍：</b>\n` +
    `📤 自动保存群组/频道文件\n` +
    `🔗 生成永久下载链接\n` +
    `🔒 AES-256 加密存储\n` +
    `🧹 无效链接自动清理\n\n` +
    `${statusText}`;
  
  await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
}

async function handleManageUsersCallback(chatId, messageId, isUserAdmin, config) {
  const { BOT_TOKEN } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  const text = `👤 <b>用户管理</b>\n\n` +
    `<b>添加授权用户：</b>\n` +
    `<code>/adduser 用户ID</code>\n\n` +
    `<b>取消授权用户：</b>\n` +
    `<code>/deluser 用户ID</code>\n\n` +
    `<b>查看授权列表：</b>\n` +
    `<code>/listusers</code>\n\n` +
    `💡 用户ID可通过 /myid 命令获取`;
  
  const keyboard = {
    inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
  };
  
  await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
}

async function handleManageChatsCallback(chatId, messageId, isUserAdmin, config) {
  const { BOT_TOKEN } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  const text = `👥 <b>群组/频道管理</b>\n\n` +
    `<b>添加授权：</b>\n` +
    `<code>/addchat -1001234567890</code>\n\n` +
    `<b>取消授权：</b>\n` +
    `<code>/delchat -1001234567890</code>\n\n` +
    `<b>查看授权列表：</b>\n` +
    `<code>/listchats</code>\n\n` +
    `💡 在群组中使用 /myid 获取群组ID`;
  
  const keyboard = {
    inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
  };
  
  await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
}

async function handleStatsCallback(chatId, messageId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  try {
    const [files, users, chats, admins] = await Promise.all([
      FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM authorized_users').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM authorized_chats').first(),
      FILE_DB.prepare('SELECT COUNT(*) as count FROM admins').first()
    ]);
    
    const weekAgo = Math.floor(Date.now() / 1000) - 7 * 24 * 60 * 60;
    const recentFiles = await FILE_DB.prepare(
      'SELECT COUNT(*) as count FROM file_mappings WHERE created_at > ?'
    ).bind(weekAgo).first();
    
    const text = `📊 <b>服务统计</b>\n\n` +
      `📁 <b>总文件数:</b> ${files?.count || 0}\n` +
      `📈 <b>近7天新增:</b> ${recentFiles?.count || 0}\n` +
      `👤 <b>授权用户:</b> ${users?.count || 0}\n` +
      `👥 <b>授权群组:</b> ${chats?.count || 0}\n` +
      `🔑 <b>管理员:</b> ${admins?.count || 0}\n\n` +
      `⏰ ${formatBeijingTime(new Date())}`;
    
    const keyboard = {
      inline_keyboard: [
        [{ text: '🔄 刷新', callback_data: 'stats' }],
        [{ text: '⬅️ 返回', callback_data: 'back_to_start' }]
      ]
    };
    
    await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
  } catch (error) {
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 统计失败: ${error.message}`);
  }
}

async function handleCleanPromptCallback(chatId, messageId, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  // 获取总数
  let totalInfo = '';
  let totalCount = 0;
  if (FILE_DB) {
    const total = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    totalCount = total?.count || 0;
    totalInfo = `\n📊 数据库中共有 <b>${totalCount}</b> 个链接\n`;
  }
  
  const text = `🧹 <b>清理无效链接</b>\n\n` +
    `当原始消息被删除后，下载链接会失效。\n` +
    `此功能可以检测并清理这些无效链接。\n` +
    totalInfo + `\n` +
    `<b>清理方式:</b>\n` +
    `• 自动分批检测全部链接\n` +
    `• 每批 40 个（Cloudflare 限制）\n` +
    `• 发现无效链接立即删除\n` +
    `• 完成后推送报告给管理员\n\n` +
    `<b>命令方式:</b>\n` +
    `<code>/clean</code> - 开始全量清理\n` +
    `<code>/verify @channel/123</code> - 验证单个链接`;
  
  const keyboard = {
    inline_keyboard: [
      [{ text: `🚀 开始清理全部 ${totalCount} 个链接`, callback_data: 'clean_run_all' }],
      [{ text: '⬅️ 返回', callback_data: 'back_to_start' }]
    ]
  };
  
  await editMessage(BOT_TOKEN, chatId, messageId, text, { reply_markup: keyboard });
}

async function handleListPageCallback(chatId, messageId, page, config, origin) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  const limit = 10;
  const offset = (page - 1) * limit;
  
  try {
    const files = await FILE_DB.prepare(
      'SELECT file_key, created_at FROM file_mappings ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all();
    
    const total = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    const totalPages = Math.ceil((total?.count || 0) / limit);
    
    let text = `📋 <b>已保存的文件</b> (第 ${page}/${totalPages} 页)\n\n`;
    
    for (const file of files.results) {
      const date = formatBeijingDate(file.created_at);
      const icon = getFileTypeIcon(file.file_key);
      text += `${icon} <code>${origin}/file/${file.file_key}</code>\n`;
      text += `   📅 ${date}\n\n`;
    }
    
    const keyboard = { inline_keyboard: [] };
    const nav = [];
    if (page > 1) nav.push({ text: '⬅️ 上一页', callback_data: `list_page_${page - 1}` });
    if (page < totalPages) nav.push({ text: '➡️ 下一页', callback_data: `list_page_${page + 1}` });
    if (nav.length) keyboard.inline_keyboard.push(nav);
    keyboard.inline_keyboard.push([
      { text: '🔄 刷新', callback_data: `list_page_${page}` },
      { text: '⬅️ 返回', callback_data: 'back_to_start' }
    ]);
    
    await editMessage(BOT_TOKEN, chatId, messageId, text, { 
      reply_markup: keyboard,
      disable_web_page_preview: true 
    });
  } catch (error) {
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 查询失败: ${error.message}`);
  }
}

async function handleCleanConfirmCallback(chatId, messageId, count, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  await editMessage(BOT_TOKEN, chatId, messageId, `🗑 <b>正在删除无效链接...</b>`);
  
  try {
    const files = await FILE_DB.prepare(
      'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at DESC LIMIT ?'
    ).bind(count).all();
    
    let deletedCount = 0;
    
    for (const file of files.results) {
      try {
        const decrypted = JSON.parse(await decryptData(file.encrypted_data, ENCRYPTION_KEY));
        const isValid = await verifyFileLink(decrypted);
        
        if (!isValid) {
          await deleteFileMapping(FILE_DB, file.file_key);
          deletedCount++;
        }
      } catch (e) {
        await deleteFileMapping(FILE_DB, file.file_key);
        deletedCount++;
      }
    }
    
    const keyboard = {
      inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
    };
    
    await editMessage(BOT_TOKEN, chatId, messageId, 
      `✅ <b>清理完成</b>\n\n` +
      `🗑 已删除: ${deletedCount} 个无效链接`,
      { reply_markup: keyboard }
    );
  } catch (error) {
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 清理失败: ${error.message}`);
  }
}

// 执行清理检查回调 - 自动分批循环直到全部清完
async function handleCleanRunCallback(chatId, messageId, count, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY, ADMIN_IDS } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  await editMessage(BOT_TOKEN, chatId, messageId, 
    `🔍 <b>开始全量清理无效链接...</b>\n\n` +
    `⏳ 正在分批检测，请稍候...\n` +
    `每批检查 40 个链接（Cloudflare 限制）`
  );
  
  try {
    // 获取总数
    const totalResult = await FILE_DB.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    const totalCount = totalResult?.count || 0;
    
    if (totalCount === 0) {
      const keyboard = { inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]] };
      await editMessage(BOT_TOKEN, chatId, messageId, '📭 数据库中没有文件', { reply_markup: keyboard });
      return;
    }
    
    let totalChecked = 0;
    let totalValid = 0;
    let totalInvalid = 0;
    let batchNumber = 0;
    const batchSize = 40;
    const allInvalidKeys = [];
    let offset = 0;
    
    // 分批循环检测
    while (true) {
      batchNumber++;
      
      const files = await FILE_DB.prepare(
        'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at ASC LIMIT ? OFFSET ?'
      ).bind(batchSize, offset).all();
      
      if (!files.results?.length) {
        break;
      }
      
      let batchInvalid = 0;
      const batchInvalidKeys = [];
      
      for (const file of files.results) {
        try {
          const decrypted = JSON.parse(await decryptData(file.encrypted_data, ENCRYPTION_KEY));
          const isValid = await verifyFileLink(decrypted);
          
          if (isValid) {
            totalValid++;
          } else {
            batchInvalid++;
            batchInvalidKeys.push({
              key: file.file_key,
              filename: decrypted.filename || '未知'
            });
          }
        } catch (e) {
          batchInvalid++;
          batchInvalidKeys.push({
            key: file.file_key,
            filename: '解密失败'
          });
        }
      }
      
      // 立即删除本批无效链接
      for (const item of batchInvalidKeys) {
        await deleteFileMapping(FILE_DB, item.key);
        allInvalidKeys.push(item);
      }
      
      totalChecked += files.results.length;
      totalInvalid += batchInvalid;
      
      // 更新 offset（只跳过有效的链接，无效的已删除）
      offset += files.results.length - batchInvalid;
      
      // 更新进度消息（每 2 批更新一次）
      if (batchNumber % 2 === 0) {
        try {
          await editMessage(BOT_TOKEN, chatId, messageId,
            `🔍 <b>正在清理无效链接...</b>\n\n` +
            `📊 进度: 第 ${batchNumber} 批\n` +
            `📁 已检查: ${totalChecked} / ${totalCount}\n` +
            `✅ 有效: ${totalValid}\n` +
            `❌ 无效: ${totalInvalid}\n\n` +
            `⏳ 继续检测中...`
          );
        } catch (e) {
          // 忽略编辑消息失败
        }
      }
      
      if (files.results.length < batchSize) {
        break; // 最后一批
      }
    }
    
    // 生成最终报告
    const report = generateCleanReport(totalCount, totalChecked, totalValid, totalInvalid, allInvalidKeys);
    
    const keyboard = { inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]] };
    await editMessage(BOT_TOKEN, chatId, messageId, report, { reply_markup: keyboard });
    
    // 通知其他管理员
    if (ADMIN_IDS && ADMIN_IDS.length > 0 && totalInvalid > 0) {
      for (const adminId of ADMIN_IDS) {
        if (adminId.toString() !== chatId.toString()) {
          try {
            await sendMessage(BOT_TOKEN, parseInt(adminId), 
              `📋 <b>清理报告</b>\n\n` + report
            );
          } catch (e) {
            // 忽略发送失败
          }
        }
      }
    }
    
  } catch (error) {
    const keyboard = { inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]] };
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 清理失败: ${error.message}`, { reply_markup: keyboard });
  }
}

async function handleDeleteFileCallback(chatId, messageId, fileKey, isUserAdmin, config) {
  const { BOT_TOKEN, FILE_DB } = config;
  
  if (!isUserAdmin) {
    await editMessage(BOT_TOKEN, chatId, messageId, '⛔ 需要管理员权限');
    return;
  }
  
  try {
    await deleteFileMapping(FILE_DB, fileKey);
    
    const keyboard = {
      inline_keyboard: [[{ text: '⬅️ 返回', callback_data: 'back_to_start' }]]
    };
    
    await editMessage(BOT_TOKEN, chatId, messageId, 
      `✅ 已删除: <code>${escapeHtml(fileKey)}</code>`,
      { reply_markup: keyboard }
    );
  } catch (error) {
    await editMessage(BOT_TOKEN, chatId, messageId, `❌ 删除失败: ${error.message}`);
  }
}

// ==================== 设置 Webhook ====================

async function handleSetWebhook(request, url, config) {
  const { BOT_TOKEN, ACCESS_PASSWORD } = config;
  const password = getPassword(request, url);
  
  if (!verifyPassword(password, ACCESS_PASSWORD)) {
    return jsonResponse({ error: '需要访问密码' }, 401);
  }
  
  if (!BOT_TOKEN) {
    return jsonResponse({ error: '未设置 BOT_TOKEN' }, 500);
  }
  
  const webhookPath = BOT_TOKEN.split(':')[1];
  const webhookUrl = `${url.origin}/webhook/${webhookPath}`;
  
  const result = await sendTelegramRequest(BOT_TOKEN, 'setWebhook', {
    url: webhookUrl,
    allowed_updates: ['message', 'channel_post', 'edited_message', 'edited_channel_post', 'callback_query']
  });
  
  if (result.ok) {
    await sendTelegramRequest(BOT_TOKEN, 'setMyCommands', {
      commands: [
        { command: 'start', description: '开始使用' },
        { command: 'help', description: '查看帮助' },
        { command: 'list', description: '文件列表' },
        { command: 'myid', description: '查看ID' },
        { command: 'clean', description: '清理无效链接' }
      ]
    });
    
    return jsonResponse({
      success: true,
      message: 'Webhook 设置成功',
      webhook_url: webhookUrl
    });
  }
  
  return jsonResponse({ error: 'Webhook 设置失败', detail: result.description }, 500);
}

async function handleDeleteWebhook(request, url, config) {
  const { BOT_TOKEN, ACCESS_PASSWORD } = config;
  const password = getPassword(request, url);
  
  if (!verifyPassword(password, ACCESS_PASSWORD)) {
    return jsonResponse({ error: '需要访问密码' }, 401);
  }
  
  const result = await sendTelegramRequest(BOT_TOKEN, 'deleteWebhook', {});
  return jsonResponse(result, result.ok ? 200 : 500);
}

// ==================== 文件下载 ====================

async function handleFileDownload(url, db, encryptionKey) {
  const pathParts = url.pathname.substring(6).split('/');
  
  if (!pathParts[0]) {
    return jsonResponse({ error: '缺少文件标识' }, 400);
  }
  
  let fileData = null;
  let fileKey = pathParts.length === 2 ? `${pathParts[0]}/${pathParts[1]}` : pathParts[0];
  
  if (db) {
    try {
      const result = await getFileMapping(db, fileKey);
      if (result?.encrypted_data) {
        fileData = JSON.parse(await decryptData(result.encrypted_data, encryptionKey));
      }
    } catch (e) {
      console.error('D1 读取失败:', e);
    }
  }
  
  if (!fileData && pathParts.length === 1) {
    try {
      fileData = JSON.parse(await decryptData(fileKey, encryptionKey));
    } catch (e) {}
  }
  
  if (!fileData) {
    return jsonResponse({
      error: '文件不存在',
      message: '找不到该文件，可能已被删除或链接无效'
    }, 404);
  }
  
  // 检查文件大小是否超过 Bot API 限制 (20MB)
  const BOT_API_LIMIT = 20 * 1024 * 1024; // 20MB
  
  // 先用 HEAD 请求检查文件状态和大小
  const telegramUrl = `https://api.telegram.org/file/bot${fileData.token}/${fileData.path}`;
  
  try {
    const headResponse = await fetch(telegramUrl, { method: 'HEAD' });
    
    if (!headResponse.ok) {
      // 文件链接已失效，尝试重新获取
      const refreshed = await refreshFileLink(fileData);
      if (refreshed) {
        fileData = refreshed;
      } else {
        return jsonResponse({ 
          error: '文件下载失败', 
          message: '文件链接已过期，原始文件可能已被删除',
          telegram_link: generateTelegramLink(fileData),
          hint: '您可以尝试在 Telegram 中直接查看原消息'
        }, 404);
      }
    }
    
    const contentLength = parseInt(headResponse.headers.get('content-length') || '0');
    
    // 如果文件超过 20MB，返回备选方案
    if (contentLength > BOT_API_LIMIT) {
      const telegramLink = generateTelegramLink(fileData);
      
      return new Response(generateLargeFileHtml(fileData, contentLength, telegramLink), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
    
    // 正常下载
    const response = await fetch(telegramUrl);
    
    if (!response.ok) {
      return jsonResponse({ 
        error: '文件下载失败', 
        message: '原始文件可能已被删除',
        status: response.status 
      }, response.status);
    }
    
    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Cache-Control', 'public, max-age=31536000');
    
    if (fileData.filename) {
      headers.set('Content-Disposition', `inline; filename="${encodeURIComponent(fileData.filename)}"`);
    }
    
    return new Response(response.body, { status: 200, headers });
  } catch (error) {
    return jsonResponse({ error: '下载失败', detail: error.message }, 500);
  }
}

// 生成 Telegram 消息链接
function generateTelegramLink(fileData) {
  if (!fileData.chat_id || !fileData.message_id) return null;
  
  const chatId = fileData.chat_id.toString();
  const messageId = fileData.message_id;
  
  if (chatId.startsWith('@')) {
    return `https://t.me/${chatId.substring(1)}/${messageId}`;
  } else if (chatId.startsWith('-100')) {
    return `https://t.me/c/${chatId.substring(4)}/${messageId}`;
  } else {
    return `https://t.me/c/${chatId.replace('-', '')}/${messageId}`;
  }
}

// 尝试刷新文件链接（重新获取 file_path）
async function refreshFileLink(fileData) {
  // 如果没有存储 file_id，无法刷新
  if (!fileData.file_id || !fileData.token) return null;
  
  try {
    const result = await getFile(fileData.token, fileData.file_id);
    if (result.ok && result.result.file_path) {
      fileData.path = result.result.file_path;
      return fileData;
    }
  } catch (e) {
    console.error('刷新文件链接失败:', e);
  }
  
  return null;
}

// 生成大文件提示页面
function generateLargeFileHtml(fileData, size, telegramLink) {
  const sizeText = formatSize(size);
  const filename = escapeHtml(fileData.filename || '未知文件');
  const icon = getFileTypeIcon(fileData.filename);
  
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${filename} - 大文件下载</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
  </style>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center p-4">
  <div class="bg-white rounded-2xl shadow-xl max-w-md w-full overflow-hidden">
    <div class="gradient-bg p-6 text-white text-center">
      <div class="text-6xl mb-4">${icon}</div>
      <h1 class="text-xl font-bold mb-1">${filename}</h1>
      <p class="opacity-80">${sizeText}</p>
    </div>
    
    <div class="p-6">
      <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
        <div class="flex items-start gap-3">
          <span class="text-2xl">⚠️</span>
          <div>
            <h3 class="font-semibold text-yellow-800">文件超过 20MB</h3>
            <p class="text-sm text-yellow-700 mt-1">
              由于 Telegram Bot API 限制，超过 20MB 的文件无法通过代理下载。
              请使用以下方式获取文件：
            </p>
          </div>
        </div>
      </div>
      
      ${telegramLink ? `
      <a href="${telegramLink}" target="_blank" 
         class="block w-full bg-blue-500 hover:bg-blue-600 text-white text-center py-3 px-4 rounded-lg font-medium transition mb-3">
        <span class="mr-2">📱</span>在 Telegram 中打开
      </a>
      ` : ''}
      
      <div class="bg-gray-50 rounded-lg p-4 mt-4">
        <h4 class="font-semibold text-gray-700 mb-2">💡 其他下载方式</h4>
        <ul class="text-sm text-gray-600 space-y-2">
          <li>• 在 Telegram 客户端中直接下载</li>
          <li>• 使用 Telegram Desktop 下载大文件更快</li>
          <li>• 第三方工具：tg-files-downloader</li>
        </ul>
      </div>
      
      <div class="mt-6 text-center text-xs text-gray-400">
        <p>文件大小限制说明：</p>
        <p>Bot API: 20MB | 本地 API: 2GB</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// ==================== API 接口 ====================

async function handleGetFiles(url, db, encryptionKey, origin) {
  if (!db) {
    return jsonResponse({ error: '数据库未配置' }, 500);
  }
  
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 20, 100);
  const offset = (page - 1) * limit;
  
  try {
    const files = await db.prepare(
      'SELECT file_key, encrypted_data, created_at FROM file_mappings ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all();
    
    const total = await db.prepare('SELECT COUNT(*) as count FROM file_mappings').first();
    
    const results = [];
    for (const file of files.results) {
      try {
        const data = JSON.parse(await decryptData(file.encrypted_data, encryptionKey));
        results.push({
          file_key: file.file_key,
          filename: data.filename,
          url: `${origin}/file/${file.file_key}`,
          created_at: file.created_at,
          created_at_formatted: formatBeijingTime(new Date(file.created_at * 1000))
        });
      } catch (e) {
        results.push({
          file_key: file.file_key,
          url: `${origin}/file/${file.file_key}`,
          created_at: file.created_at
        });
      }
    }
    
    return jsonResponse({
      success: true,
      page,
      limit,
      total: total?.count || 0,
      total_pages: Math.ceil((total?.count || 0) / limit),
      files: results
    });
  } catch (error) {
    return jsonResponse({ error: '查询失败', detail: error.message }, 500);
  }
}

async function handleDeleteFile(request, db) {
  if (!db) {
    return jsonResponse({ error: '数据库未配置' }, 500);
  }
  
  try {
    const body = await request.json();
    const { file_key } = body;
    
    if (!file_key) {
      return jsonResponse({ error: '缺少 file_key 参数' }, 400);
    }
    
    const result = await deleteFileMapping(db, file_key);
    
    return jsonResponse({
      success: true,
      deleted: result.meta?.changes > 0,
      file_key
    });
  } catch (error) {
    return jsonResponse({ error: '删除失败', detail: error.message }, 500);
  }
}

async function handleSearchFiles(url, db, encryptionKey, origin) {
  if (!db) {
    return jsonResponse({ error: '数据库未配置' }, 500);
  }
  
  const keyword = url.searchParams.get('q') || '';
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 20, 100);
  
  if (!keyword) {
    return jsonResponse({ error: '缺少搜索关键词 q' }, 400);
  }
  
  try {
    const files = await db.prepare(
      'SELECT file_key, encrypted_data, created_at FROM file_mappings WHERE file_key LIKE ? ORDER BY created_at DESC LIMIT ?'
    ).bind(`%${keyword}%`, limit).all();
    
    const results = [];
    for (const file of files.results) {
      try {
        const data = JSON.parse(await decryptData(file.encrypted_data, encryptionKey));
        results.push({
          file_key: file.file_key,
          filename: data.filename,
          url: `${origin}/file/${file.file_key}`,
          created_at: file.created_at,
          created_at_formatted: formatBeijingTime(new Date(file.created_at * 1000))
        });
      } catch (e) {
        results.push({
          file_key: file.file_key,
          url: `${origin}/file/${file.file_key}`,
          created_at: file.created_at
        });
      }
    }
    
    return jsonResponse({
      success: true,
      keyword,
      count: results.length,
      files: results
    });
  } catch (error) {
    return jsonResponse({ error: '搜索失败', detail: error.message }, 500);
  }
}

async function handleCleanInvalidLinks(request, db, encryptionKey, origin) {
  if (!db) {
    return jsonResponse({ error: '数据库未配置' }, 500);
  }
  
  try {
    const body = await request.json().catch(() => ({}));
    const limit = Math.min(parseInt(body.limit) || 50, 200);
    const dryRun = body.dry_run !== false;
    
    const files = await db.prepare(
      'SELECT file_key, encrypted_data FROM file_mappings ORDER BY created_at DESC LIMIT ?'
    ).bind(limit).all();
    
    const invalidFiles = [];
    const validFiles = [];
    
    for (const file of files.results) {
      try {
        const decrypted = JSON.parse(await decryptData(file.encrypted_data, encryptionKey));
        const isValid = await verifyFileLink(decrypted);
        
        if (isValid) {
          validFiles.push(file.file_key);
        } else {
          invalidFiles.push({
            file_key: file.file_key,
            filename: decrypted.filename
          });
          
          if (!dryRun) {
            await deleteFileMapping(db, file.file_key);
          }
        }
      } catch (e) {
        invalidFiles.push({ file_key: file.file_key, error: e.message });
        if (!dryRun) {
          await deleteFileMapping(db, file.file_key);
        }
      }
    }
    
    return jsonResponse({
      success: true,
      checked: files.results.length,
      valid_count: validFiles.length,
      invalid_count: invalidFiles.length,
      deleted: dryRun ? 0 : invalidFiles.length,
      dry_run: dryRun,
      invalid_files: invalidFiles
    });
  } catch (error) {
    return jsonResponse({ error: '清理失败', detail: error.message }, 500);
  }
}

async function handleVerifyLink(url, db, encryptionKey) {
  if (!db) {
    return jsonResponse({ error: '数据库未配置' }, 500);
  }
  
  const fileKey = url.searchParams.get('file_key') || '';
  
  if (!fileKey) {
    return jsonResponse({ error: '缺少 file_key 参数' }, 400);
  }
  
  try {
    const result = await db.prepare(
      'SELECT encrypted_data, created_at FROM file_mappings WHERE file_key = ?'
    ).bind(fileKey).first();
    
    if (!result) {
      return jsonResponse({ error: '文件不存在', file_key: fileKey }, 404);
    }
    
    const decrypted = JSON.parse(await decryptData(result.encrypted_data, encryptionKey));
    const isValid = await verifyFileLink(decrypted);
    
    return jsonResponse({
      success: true,
      file_key: fileKey,
      filename: decrypted.filename,
      valid: isValid,
      created_at: result.created_at,
      created_at_formatted: formatBeijingTime(new Date(result.created_at * 1000))
    });
  } catch (error) {
    return jsonResponse({ error: '验证失败', detail: error.message }, 500);
  }
}

async function handleAddForwardedFile(request, config, url) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  if (!BOT_TOKEN) {
    return jsonResponse({ error: '未配置 BOT_TOKEN' }, 500);
  }
  
  try {
    const body = await request.json();
    const { chat_id, message_id, message_thread_id } = body;
    
    if (!chat_id || !message_id) {
      return jsonResponse({
        error: '参数缺失',
        required: ['chat_id', 'message_id'],
        optional: ['message_thread_id']
      }, 400);
    }
    
    const forwardResult = await sendTelegramRequest(BOT_TOKEN, 'forwardMessage', {
      chat_id,
      from_chat_id: chat_id,
      message_id,
      ...(message_thread_id && { message_thread_id })
    });
    
    if (!forwardResult.ok) {
      return jsonResponse({
        error: '获取消息失败',
        detail: forwardResult.description
      }, 400);
    }
    
    const msg = forwardResult.result;
    const fileInfo = extractFileInfo(msg);
    
    await deleteMessage(BOT_TOKEN, chat_id, msg.message_id);
    
    if (!fileInfo) {
      return jsonResponse({ error: '消息中没有文件' }, 400);
    }
    
    const fileResult = await getFile(BOT_TOKEN, fileInfo.fileId);
    
    if (!fileResult.ok) {
      return jsonResponse({
        error: '获取文件路径失败',
        detail: fileResult.description
      }, 400);
    }
    
    const data = {
      token: BOT_TOKEN,
      path: fileResult.result.file_path,
      file_id: fileInfo.fileId, // 保存 file_id 用于刷新链接
      filename: fileInfo.filename,
      message_id,
      message_thread_id: message_thread_id || null,
      chat_id,
      file_size: fileInfo.fileSize || fileResult.result.file_size
    };
    
    const encrypted = await encryptData(JSON.stringify(data), ENCRYPTION_KEY);
    const links = generateFileLinks(
      chat_id,
      message_id,
      typeof chat_id === 'string' && chat_id.startsWith('@') ? chat_id.substring(1) : null,
      url.origin
    );
    
    if (FILE_DB && links.channelIdentifier) {
      const fileKey = `${links.channelIdentifier}/${message_id}`;
      await saveFileMapping(FILE_DB, fileKey, encrypted);
    }
    
    return jsonResponse({
      success: true,
      cdn: {
        url: links.friendlyUrl,
        url_encrypted: `${url.origin}/file/${encrypted}`,
        filename: fileInfo.filename,
        file_type: fileInfo.fileType,
        size: fileInfo.fileSize || fileResult.result.file_size,
        message_id,
        telegram_link: links.telegramLink,
        markdown: `![${fileInfo.filename}](${links.friendlyUrl})`,
        html: `<img src="${links.friendlyUrl}" alt="${fileInfo.filename}" />`
      }
    });
  } catch (error) {
    return jsonResponse({ error: '处理失败', detail: error.message }, 500);
  }
}

async function handleBotApiProxy(request, config, url) {
  const { BOT_TOKEN, FILE_DB, ENCRYPTION_KEY } = config;
  
  const pathMatch = url.pathname.match(/^\/bot\/(.+)$/);
  if (!pathMatch) {
    return jsonResponse({ error: 'URL 格式错误', usage: '/bot/<方法名>' }, 400);
  }
  
  const method = pathMatch[1];
  const telegramUrl = `https://api.telegram.org/bot${BOT_TOKEN}/${method}`;
  
  try {
    const headers = new Headers(request.headers);
    headers.delete('x-access-password');
    
    let finalUrl = telegramUrl;
    if (request.method === 'GET' && url.search) {
      const params = new URLSearchParams(url.search);
      params.delete('password');
      params.delete('pwd');
      const cleanParams = params.toString();
      if (cleanParams) finalUrl = `${telegramUrl}?${cleanParams}`;
    }
    
    const proxyRequest = new Request(finalUrl, {
      method: request.method,
      headers,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
      duplex: 'half'
    });
    
    const response = await fetch(proxyRequest);
    let responseData;
    
    try {
      responseData = await response.json();
    } catch (e) {
      return new Response(await response.text(), {
        status: response.status,
        headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }
    
    const fileMethods = ['sendDocument', 'sendPhoto', 'sendVideo', 'sendAudio', 'sendAnimation', 'sendVoice', 'sendVideoNote', 'sendSticker'];
    
    if (responseData.ok && fileMethods.some(m => method.toLowerCase().includes(m.toLowerCase()))) {
      const result = responseData.result;
      const fileInfo = extractFileInfo(result);
      
      if (fileInfo && result.message_id) {
        const fileResult = await getFile(BOT_TOKEN, fileInfo.fileId);
        
        if (fileResult.ok) {
          const chatId = result.chat?.id || result.sender_chat?.id;
          const chatUsername = result.chat?.username || result.sender_chat?.username;
          
          const data = {
            token: BOT_TOKEN,
            path: fileResult.result.file_path,
            filename: fileInfo.filename,
            message_id: result.message_id,
            chat_id: chatId
          };
          
          const encrypted = await encryptData(JSON.stringify(data), ENCRYPTION_KEY);
          const links = generateFileLinks(chatId, result.message_id, chatUsername, url.origin);
          
          if (FILE_DB && links.channelIdentifier) {
            const fileKey = `${links.channelIdentifier}/${result.message_id}`;
            await saveFileMapping(FILE_DB, fileKey, encrypted);
          }
          
          responseData.cdn = {
            url: links.friendlyUrl || `${url.origin}/file/${encrypted}`,
            url_encrypted: `${url.origin}/file/${encrypted}`,
            filename: fileInfo.filename,
            file_type: fileInfo.fileType,
            size: fileResult.result.file_size,
            message_id: result.message_id,
            telegram_link: links.telegramLink,
            permanent: true
          };
        }
      }
    }
    
    return jsonResponse(responseData, response.status);
  } catch (error) {
    return jsonResponse({ error: '代理请求失败', detail: error.message }, 500);
  }
}

// ==================== API 文档 ====================

function generateApiDoc(origin) {
  return {
    service: 'Telegram 文件代理服务',
    version: '9.0',
    description: '支持授权验证、Bot 交互、链接清理的完整文件代理服务',
    endpoints: {
      public: {
        'GET /': 'HTML 文档页面',
        'GET /api': 'API 文档 (JSON)',
        'GET /init-db': '初始化数据库',
        'GET /file/{key}': '下载文件 (无需密码)'
      },
      protected: {
        'POST /set-webhook': '设置 Webhook',
        'POST /delete-webhook': '删除 Webhook',
        'POST /add-forwarded-file': '添加转发文件',
        'GET /files': '获取文件列表',
        'GET /search': '搜索文件',
        'POST /delete-file': '删除文件',
        'POST /clean': '清理无效链接',
        'GET /verify': '验证链接有效性',
        'POST /bot/{method}': 'Bot API 代理'
      }
    },
    authentication: {
      header: 'X-Access-Password: 你的密码',
      query: '?password=你的密码'
    },
    examples: {
      send_message: `curl -X POST "${origin}/bot/sendMessage" -H "X-Access-Password: xxx" -H "Content-Type: application/json" -d '{"chat_id":"@channel","text":"<b>Hello</b>","parse_mode":"HTML"}'`,
      upload_file: `curl -X POST "${origin}/bot/sendDocument" -H "X-Access-Password: xxx" -F "chat_id=@channel" -F "document=@file.pdf"`,
      get_files: `curl "${origin}/files?page=1&limit=20&password=xxx"`,
      search: `curl "${origin}/search?q=photo&password=xxx"`,
      clean: `curl -X POST "${origin}/clean" -H "X-Access-Password: xxx" -H "Content-Type: application/json" -d '{"limit":100,"dry_run":true}'`,
      verify: `curl "${origin}/verify?file_key=@channel/123&password=xxx"`
    }
  };
}

// ==================== HTML 页面 ====================

function generateHtmlPage(origin, hasDb) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Telegram 文件代理服务 - API 文档</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .code-block { background: #1e1e1e; border-radius: 8px; overflow: hidden; margin: 1rem 0; }
    .code-header { background: #2d2d2d; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; }
    .code-content { padding: 16px; color: #d4d4d4; font-size: 13px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    .copy-btn { cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: all 0.2s; }
    .copy-btn:hover { background: #404040; }
    .copy-btn.copied { color: #4ade80; }
    .endpoint { border-left: 4px solid; padding-left: 1rem; margin: 1rem 0; }
    .endpoint.get { border-color: #22c55e; }
    .endpoint.post { border-color: #3b82f6; }
  </style>
</head>
<body class="bg-gray-50 text-gray-800 min-h-screen">
  <header class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8">
    <div class="max-w-5xl mx-auto px-4">
      <h1 class="text-3xl font-bold mb-2">📁 Telegram 文件代理服务</h1>
      <p class="opacity-80">v9.0 - 支持授权验证、Bot 交互、链接清理</p>
    </div>
  </header>

  <main class="max-w-5xl mx-auto px-4 py-8">
    <!-- 功能概览 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">✨ 功能概览</h2>
      <div class="grid md:grid-cols-4 gap-4">
        <div class="bg-blue-50 p-4 rounded-lg text-center">
          <div class="text-2xl mb-2">🔐</div>
          <h3 class="font-semibold">安全加密</h3>
          <p class="text-xs text-gray-600">AES-256-GCM 加密存储</p>
        </div>
        <div class="bg-green-50 p-4 rounded-lg text-center">
          <div class="text-2xl mb-2">👥</div>
          <h3 class="font-semibold">授权管理</h3>
          <p class="text-xs text-gray-600">用户/群组验证</p>
        </div>
        <div class="bg-purple-50 p-4 rounded-lg text-center">
          <div class="text-2xl mb-2">🤖</div>
          <h3 class="font-semibold">Bot 交互</h3>
          <p class="text-xs text-gray-600">命令+按钮操作</p>
        </div>
        <div class="bg-orange-50 p-4 rounded-lg text-center">
          <div class="text-2xl mb-2">🧹</div>
          <h3 class="font-semibold">链接清理</h3>
          <p class="text-xs text-gray-600">自动检测无效链接</p>
        </div>
      </div>
    </section>

    <!-- 快速开始 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">🚀 快速开始</h2>
      <ol class="space-y-3">
        <li class="flex gap-3"><span class="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm flex-shrink-0">1</span><div><b>初始化数据库</b>: 访问 <code class="bg-gray-100 px-2 py-0.5 rounded">/init-db</code></div></li>
        <li class="flex gap-3"><span class="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm flex-shrink-0">2</span><div><b>设置 Webhook</b>: POST <code class="bg-gray-100 px-2 py-0.5 rounded">/set-webhook</code></div></li>
        <li class="flex gap-3"><span class="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm flex-shrink-0">3</span><div><b>开始使用</b>: 私聊 Bot 发送 <code class="bg-gray-100 px-2 py-0.5 rounded">/start</code></div></li>
      </ol>
    </section>

    <!-- 发送消息 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">📨 发送消息 (HTML/Markdown 格式)</h2>
      <p class="text-gray-600 mb-4">使用 <code class="bg-gray-100 px-2 py-0.5 rounded">/bot/sendMessage</code> 接口发送格式化消息</p>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">发送 HTML 格式消息</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/bot/sendMessage" \\
  -H "X-Access-Password: your-password" \\
  -H "Content-Type: application/json" \\
  -d '{
    "chat_id": "@your_channel",
    "text": "&lt;b&gt;粗体&lt;/b&gt; &lt;i&gt;斜体&lt;/i&gt; &lt;code&gt;代码&lt;/code&gt;\\n&lt;a href=\\"https://example.com\\"&gt;链接&lt;/a&gt;",
    "parse_mode": "HTML"
  }'</pre>
      </div>
      
      <div class="mt-4 p-4 bg-blue-50 rounded-lg">
        <h4 class="font-semibold text-blue-700 mb-2">支持的 HTML 标签</h4>
        <ul class="text-sm text-blue-600 space-y-1">
          <li>• <code>&lt;b&gt;</code> / <code>&lt;strong&gt;</code> - 粗体</li>
          <li>• <code>&lt;i&gt;</code> / <code>&lt;em&gt;</code> - 斜体</li>
          <li>• <code>&lt;code&gt;</code> - 等宽字体</li>
          <li>• <code>&lt;pre&gt;</code> - 代码块</li>
          <li>• <code>&lt;a href="url"&gt;</code> - 链接</li>
          <li>• <code>&lt;s&gt;</code> / <code>&lt;del&gt;</code> - 删除线</li>
        </ul>
      </div>
    </section>

    <!-- 上传文件 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">📤 上传文件</h2>
      
      <div class="endpoint post">
        <code class="font-bold">POST /bot/sendDocument</code>
        <span class="ml-2 text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">需要密码</span>
      </div>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">上传文档</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/bot/sendDocument" \\
  -H "X-Access-Password: your-password" \\
  -F "chat_id=@your_channel" \\
  -F "document=@/path/to/file.pdf" \\
  -F "caption=文件描述"</pre>
      </div>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">上传图片</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/bot/sendPhoto" \\
  -H "X-Access-Password: your-password" \\
  -F "chat_id=@your_channel" \\
  -F "photo=@/path/to/image.jpg"</pre>
      </div>
    </section>

    <!-- 文件管理 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">📋 文件管理</h2>
      
      <div class="endpoint get">
        <code class="font-bold">GET /files</code> - 获取文件列表
      </div>
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">获取文件列表 (分页)</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl "${origin}/files?page=1&limit=20&password=your-password"</pre>
      </div>
      
      <div class="endpoint get">
        <code class="font-bold">GET /search</code> - 搜索文件
      </div>
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">搜索文件</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl "${origin}/search?q=photo&limit=20&password=your-password"</pre>
      </div>
      
      <div class="endpoint post">
        <code class="font-bold">POST /delete-file</code> - 删除文件
      </div>
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">删除文件</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/delete-file" \\
  -H "X-Access-Password: your-password" \\
  -H "Content-Type: application/json" \\
  -d '{"file_key": "@channel/123"}'</pre>
      </div>
    </section>

    <!-- 链接清理 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">🧹 链接清理</h2>
      <p class="text-gray-600 mb-4">当原始消息被删除后，下载链接会失效。使用以下 API 检测并清理无效链接。</p>
      
      <div class="p-4 bg-yellow-50 rounded-lg mb-4">
        <p class="text-yellow-700 text-sm">
          <b>⚠️ 注意:</b> 由于 Cloudflare Workers 子请求限制（每请求最多 50 个），
          API 每次最多检查 <b>50</b> 个链接，Bot 命令每次最多检查 <b>10</b> 个链接。
          如需清理更多，请多次执行。
        </p>
      </div>
      
      <div class="endpoint get">
        <code class="font-bold">GET /verify</code> - 验证单个链接
      </div>
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">验证链接有效性</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl "${origin}/verify?file_key=@channel/123&password=your-password"</pre>
      </div>
      
      <div class="endpoint post">
        <code class="font-bold">POST /clean</code> - 批量清理无效链接
      </div>
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">预览无效链接 (dry_run=true，不删除)</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/clean" \\
  -H "X-Access-Password: your-password" \\
  -H "Content-Type: application/json" \\
  -d '{"limit": 50, "dry_run": true}'</pre>
      </div>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">实际删除无效链接 (dry_run=false)</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content">curl -X POST "${origin}/clean" \\
  -H "X-Access-Password: your-password" \\
  -H "Content-Type: application/json" \\
  -d '{"limit": 50, "dry_run": false}'</pre>
      </div>
    </section>

    <!-- 下载文件 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">📥 下载文件</h2>
      <p class="text-gray-600 mb-4">下载链接无需密码，可直接公开分享。</p>
      
      <div class="endpoint get">
        <code class="font-bold">GET /file/{key}</code>
        <span class="ml-2 text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">无需密码</span>
      </div>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">下载文件</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content"># 公开频道
curl -O "${origin}/file/@mychannel/123"

# 私有频道
curl -O "${origin}/file/1826585339/123"</pre>
      </div>
    </section>

    <!-- Bot 命令 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">🤖 Bot 命令</h2>
      <div class="grid md:grid-cols-2 gap-6">
        <div>
          <h3 class="font-semibold mb-3 text-gray-700">👤 基础命令</h3>
          <ul class="space-y-2 text-sm">
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/start</code> - 开始使用</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/help</code> - 查看帮助</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/list</code> - 文件列表</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/myid</code> - 查看 ID</li>
          </ul>
        </div>
        <div>
          <h3 class="font-semibold mb-3 text-gray-700">🔑 管理员命令</h3>
          <ul class="space-y-2 text-sm">
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/adduser ID</code> - 授权用户</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/addchat ID</code> - 授权群组</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/search 关键词</code> - 搜索文件</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/clean 数量</code> - 清理无效链接</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/verify file_key</code> - 验证链接</li>
            <li><code class="bg-gray-100 px-2 py-0.5 rounded">/stats</code> - 统计信息</li>
          </ul>
        </div>
      </div>
    </section>

    <!-- 文件大小限制 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">📦 文件大小限制</h2>
      
      <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
        <div class="flex items-start gap-3">
          <span class="text-2xl">⚠️</span>
          <div>
            <h3 class="font-semibold text-yellow-800">Telegram Bot API 限制</h3>
            <p class="text-sm text-yellow-700 mt-1">
              由于 Telegram Bot API 的限制，通过代理下载的文件最大为 <b>20MB</b>。
              超过此大小的文件会显示提示页面，引导用户在 Telegram 中直接下载。
            </p>
          </div>
        </div>
      </div>
      
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b">
              <th class="text-left py-2 px-3">方式</th>
              <th class="text-left py-2 px-3">下载限制</th>
              <th class="text-left py-2 px-3">上传限制</th>
            </tr>
          </thead>
          <tbody class="divide-y">
            <tr>
              <td class="py-2 px-3 font-semibold">Bot API (本服务)</td>
              <td class="py-2 px-3">20 MB</td>
              <td class="py-2 px-3">50 MB</td>
            </tr>
            <tr>
              <td class="py-2 px-3">本地 Bot API 服务器</td>
              <td class="py-2 px-3">2 GB</td>
              <td class="py-2 px-3">2 GB</td>
            </tr>
            <tr>
              <td class="py-2 px-3">Telegram 客户端</td>
              <td class="py-2 px-3">2 GB</td>
              <td class="py-2 px-3">2 GB</td>
            </tr>
          </tbody>
        </table>
      </div>
      
      <div class="mt-4 p-4 bg-blue-50 rounded-lg">
        <h4 class="font-semibold text-blue-700 mb-2">💡 大文件下载方案</h4>
        <ul class="text-sm text-blue-600 space-y-1">
          <li>• 点击通知中的「在 Telegram 中下载」按钮</li>
          <li>• 使用 Telegram Desktop 下载速度更快</li>
          <li>• 自建本地 Bot API 服务器可突破限制</li>
        </ul>
      </div>
    </section>

    <!-- 环境变量 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">⚙️ 环境变量</h2>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b">
              <th class="text-left py-2 px-3">变量名</th>
              <th class="text-left py-2 px-3">必填</th>
              <th class="text-left py-2 px-3">说明</th>
            </tr>
          </thead>
          <tbody class="divide-y">
            <tr><td class="py-2 px-3 font-mono">BOT_TOKEN</td><td class="py-2 px-3 text-red-500">是</td><td class="py-2 px-3">Telegram Bot Token</td></tr>
            <tr><td class="py-2 px-3 font-mono">ACCESS_PASSWORD</td><td class="py-2 px-3 text-red-500">是</td><td class="py-2 px-3">访问密码</td></tr>
            <tr><td class="py-2 px-3 font-mono">ENCRYPTION_KEY</td><td class="py-2 px-3 text-red-500">是</td><td class="py-2 px-3">加密密钥 (至少32位)</td></tr>
            <tr><td class="py-2 px-3 font-mono">ADMIN_IDS</td><td class="py-2 px-3 text-gray-400">否</td><td class="py-2 px-3">管理员ID (逗号分隔，用于接收清理报告)</td></tr>
            <tr><td class="py-2 px-3 font-mono">FILE_DB</td><td class="py-2 px-3 text-red-500">是</td><td class="py-2 px-3">D1 数据库绑定</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 定时任务 -->
    <section class="bg-white rounded-xl shadow-sm p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">⏰ 定时清理 (Cron)</h2>
      <p class="text-gray-600 mb-4">支持 Cloudflare Workers Cron 触发器，自动定时清理无效链接。</p>
      
      <div class="code-block">
        <div class="code-header">
          <span class="text-gray-400 text-sm">wrangler.toml 配置</span>
          <button class="copy-btn text-gray-400" onclick="copyCode(this)">📋 复制</button>
        </div>
        <pre class="code-content"># 每天凌晨 3 点（UTC）自动清理
[triggers]
crons = ["0 3 * * *"]

# 或每 6 小时清理一次
# crons = ["0 */6 * * *"]</pre>
      </div>
      
      <div class="mt-4 p-4 bg-blue-50 rounded-lg">
        <h4 class="font-semibold text-blue-700 mb-2">清理流程</h4>
        <ol class="text-sm text-blue-600 space-y-1">
          <li>1. Cron 触发定时任务</li>
          <li>2. 自动分批检测全部链接（每批 40 个）</li>
          <li>3. 发现无效链接立即删除</li>
          <li>4. 完成后推送报告给所有管理员</li>
        </ol>
      </div>
    </section>

    <!-- 状态 -->
    <section class="bg-white rounded-xl shadow-sm p-6">
      <h2 class="text-xl font-bold mb-4">📊 服务状态</h2>
      <div class="flex gap-4 flex-wrap">
        <div class="flex items-center gap-2">
          <span class="${hasDb ? 'bg-green-500' : 'bg-red-500'} w-3 h-3 rounded-full"></span>
          <span>D1 数据库: ${hasDb ? '已连接' : '未配置'}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="bg-blue-500 w-3 h-3 rounded-full"></span>
          <span>API: <a href="${origin}/api" class="text-blue-500 hover:underline">${origin}/api</a></span>
        </div>
      </div>
    </section>
  </main>

  <footer class="bg-gray-800 text-gray-400 py-6 mt-8">
    <div class="max-w-5xl mx-auto px-4 text-center">
      <p>Telegram 文件代理服务 v9.0 | Cloudflare Workers + D1</p>
    </div>
  </footer>

  <script>
    function copyCode(btn) {
      const code = btn.closest('.code-block').querySelector('.code-content').textContent;
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = '✅ 已复制';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 复制';
          btn.classList.remove('copied');
        }, 2000);
      });
    }
  </script>
</body>
</html>`;
}
