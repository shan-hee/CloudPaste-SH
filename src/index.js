import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

const app = new Hono()

// 启用CORS
app.use('*', cors())

// 静态文件服务
app.use('/', serveStatic({ root: './' }))
app.use('/*', serveStatic({ root: './' }))

// 初始化数据库表
app.get('/api/init', async (c) => {
    try {
        // 创建分享表
        await c.env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                content TEXT,
                filename TEXT,
                description TEXT,
                password TEXT,
                max_views INTEGER DEFAULT 0,
                views INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                file_size INTEGER,
                original_name TEXT,
                mimetype TEXT
            )
        `).run();

        // 创建会话表
        await c.env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        `).run();

        // 创建设置表
        await c.env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        `).run();

        // 初始化默认设置
        await c.env.DB.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES 
                ('textUploadEnabled', ?),
                ('fileUploadEnabled', ?)
        `).bind(
            (c.env.TEXT_UPLOAD_ENABLED || 'true').toString(),
            (c.env.FILE_UPLOAD_ENABLED || 'true').toString()
        ).run();
        
        return c.json({ 
            success: true, 
            message: '数据库初始化成功',
            tables: ['shares', 'sessions', 'settings']
        });
    } catch (error) {
        console.error('数据库初始化失败:', error);
        return c.json({ 
            success: false, 
            message: error.message,
            error: error.toString()
        }, 500);
    }
});

// 获取存储列表
app.get('/api/file', async (c) => {
    try {
        // 从数据库获取未过期的分享
        const now = Date.now();
        const shares = await c.env.DB.prepare(`
            SELECT * FROM shares 
            WHERE (expires_at IS NULL OR expires_at > ?)
            AND id NOT LIKE 'temp_%'
        `).bind(now).all();

        // 分离文本和文件分享
        const kvData = shares.results
            .filter(item => item.type === 'text')
            .map(item => ({
                id: item.id,
                type: 'text',
                content: item.content,
                filename: item.filename || 'CloudPaste-Text',
                expiration: item.expires_at,
                createdAt: item.created_at
            }));

        const r2Data = shares.results
            .filter(item => item.type === 'file')
            .map(item => ({
                id: item.id,
                filename: item.filename,
                filesize: item.file_size,
                originalname: item.original_name || item.filename,
                type: 'file',
                expiration: item.expires_at,
                createdAt: item.created_at
            }));

        return c.json({
            success: true,
            data: {
                kv: kvData,
                r2: r2Data
            }
        });
    } catch (error) {
        console.error('获取分享列表失败:', error);
        return c.json({
            success: false,
            message: error.message || '获取分享列表失败'
        }, 500);
    }
});

// 获取统计信息
app.get('/api/share/stats', async (c) => {
  try {
        const now = Date.now();
        
        // 获取有效分享的统计信息
        const stats = await c.env.DB.prepare(`
            SELECT 
                COUNT(*) as total_shares,
                SUM(CASE WHEN type = 'text' THEN 1 ELSE 0 END) as text_shares,
                SUM(CASE WHEN type = 'file' THEN 1 ELSE 0 END) as file_shares,
                SUM(CASE WHEN type = 'text' THEN LENGTH(content) ELSE file_size END) as total_size
            FROM shares
            WHERE (expires_at IS NULL OR expires_at > ?)
            AND id NOT LIKE 'temp_%'
        `).bind(now).first();
    
    // 从环境变量获取总容量（GB），默认6GB
        const totalStorageGB = parseInt(c.env.TOTAL_STORAGE_GB) || 6;
        const totalStorage = totalStorageGB * 1024 * 1024 * 1024; // 转换为字节
        const totalSize = stats.total_size || 0;
        const usagePercent = (totalSize / totalStorage) * 100;
    
    // 计算存储空间状态
        let storageStatus = 'normal';
    if (usagePercent >= 90) {
            storageStatus = 'danger';
    } else if (usagePercent >= 70) {
            storageStatus = 'warning';
        }

    return c.json({
      success: true,
      data: {
                totalShares: stats.total_shares,
                activeShares: stats.total_shares,
        usedStorage: totalSize,
        totalStorage,
        usagePercent: usagePercent.toFixed(2),
        storageStatus
      }
        });
  } catch (error) {
        console.error('获取统计信息失败:', error);
    return c.json({
      success: false,
      message: error.message || '获取统计信息失败'
        }, 500);
  }
});

// 文本上传处理
app.post('/api/text', async (c) => {
  try {
        const data = await c.req.json();
        const { content, filename, password, duration, maxViews } = data;

    console.log('收到文本上传请求:', {
      contentLength: content?.length,
      filename,
      password: password ? '已设置' : '未设置',
      duration,
      maxViews
        });

    // 验证上传权限
    const permissionCheck = await checkUploadPermission(c, 'text');
    if (permissionCheck !== true) {
      return permissionCheck;
    }

    // 生成唯一ID
        const id = crypto.randomUUID();
    
    // 计算过期时间
        let expiresAt = null;
    switch (duration) {
      case '1h':
                expiresAt = Date.now() + 60 * 60 * 1000;
                break;
      case '1d':
                expiresAt = Date.now() + 24 * 60 * 60 * 1000;
                break;
      case '7d':
                expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
                break;
      case '30d':
                expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
                break;
      // never 的情况下 expiresAt 保持为 null
    }

        // 存储到数据库
        await c.env.DB.prepare(`
            INSERT INTO shares (
                id, type, content, filename, password, 
                max_views, views, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            id,                    // id
            'text',               // type
            content || '',        // content
            filename || null,     // filename
            password || null,     // password
            maxViews || 0,       // max_views
            0,                    // views
            Date.now(),          // created_at
            expiresAt || null    // expires_at
        ).run();

        console.log('文本分享创建成功:', id);
    
    return c.json({
      success: true,
      data: {
        id,
        url: `/s/${id}`,
        expiresAt,
                createdAt: Date.now()
      }
        });
  } catch (error) {
        console.error('创建文本分享失败:', error);
    return c.json({
      success: false,
      message: error.message || '创建文本分享失败'
        }, 500);
  }
});

// 文件上传处理
app.post('/api/file', async (c) => {
    try {
        const formData = await c.req.formData();
        const file = formData.get('file');
        const customUrl = formData.get('customUrl');
        const password = formData.get('password');
        const duration = formData.get('duration');
        const maxViews = formData.get('maxViews');
        const originalname = formData.get('originalname');

        if (!file || !(file instanceof File)) {
            return c.json({
                success: false,
                message: '未找到上传的文件'
            }, 400);
        }

        // 检查文件大小
        const maxFileSize = parseInt(c.env.MAX_FILE_SIZE || '100') * 1024 * 1024; // 转换为字节
        if (file.size > maxFileSize) {
            return c.json({
                success: false,
                message: `文件大小超过限制（${parseInt(c.env.MAX_FILE_SIZE || '100')}MB）`
            }, 400);
        }

        // 验证上传权限
        const permissionCheck = await checkUploadPermission(c, 'file');
        if (permissionCheck !== true) {
            return permissionCheck;
        }

        // 生成唯一ID
        const id = customUrl || crypto.randomUUID();
        
        // 计算过期时间
        let expiresAt = null;
        if (duration) {
        switch (duration) {
            case '1h':
                expiresAt = Date.now() + 60 * 60 * 1000;
                break;
            case '1d':
                expiresAt = Date.now() + 24 * 60 * 60 * 1000;
                break;
            case '7d':
                expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
                break;
            case '30d':
                expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
                break;
            }
        }

        try {
        // 上传文件到 R2
        const arrayBuffer = await file.arrayBuffer();
        await c.env.CLOUDPASTE_BUCKET.put(id, arrayBuffer, {
            httpMetadata: {
                    contentType: file.type || 'application/octet-stream'
                }
            });
        } catch (error) {
            console.error('上传文件到 R2 失败:', error);
            return c.json({
                success: false,
                message: '文件存储失败'
            }, 500);
        }

        try {
            // 存储到数据库
            await c.env.DB.prepare(`
                INSERT INTO shares (
                    id, type, filename, original_name, file_size, mimetype, password, 
                    max_views, views, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                id,                    // id
                'file',               // type
                file.name,            // filename
                originalname || file.name,  // original_name
                file.size,            // file_size
                file.type || 'application/octet-stream',  // mimetype
                password || null,     // password
                maxViews ? parseInt(maxViews) : 0,  // max_views
                0,                    // views
                Date.now(),          // created_at
                expiresAt || null    // expires_at
            ).run();
        } catch (error) {
            // 如果数据库存储失败，尝试删除已上传的文件
            console.error('存储文件元数据失败:', error);
            try {
                await c.env.CLOUDPASTE_BUCKET.delete(id);
            } catch (e) {
                console.error('回滚文件删除失败:', e);
            }
            throw error;
        }

        console.log('文件分享创建成功:', id);
        
        return c.json({
            success: true,
            data: {
                id,
                url: `/s/${id}`,
                filename: file.name,
                expiresAt,
                createdAt: Date.now()
            }
        });
    } catch (error) {
        console.error('创建文件分享失败:', error);
        return c.json({
            success: false,
            message: error.message || '创建文件分享失败'
        }, 500);
    }
});

// 书签上传处理
app.post('/bookmark', async (c) => {
  try {
        const data = await c.req.json();
        const { url, title, description, customUrl, password, duration, maxViews } = data;

        // 验证URL
        try {
            new URL(url);
        } catch (e) {
            return c.json({
                success: false,
                message: '无效的URL'
            }, 400);
        }

        // 生成唯一ID
        const id = customUrl || crypto.randomUUID();

        // 计算过期时间
        let expiresAt = null;
        switch (duration) {
            case '1h':
                expiresAt = Date.now() + 60 * 60 * 1000;
                break;
            case '1d':
                expiresAt = Date.now() + 24 * 60 * 60 * 1000;
                break;
            case '7d':
                expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
                break;
            case '30d':
                expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
                break;
            // never 的情况下 expiresAt 保持为 null
        }

        // 存储到数据库
        await c.env.DB.prepare(`
            INSERT INTO shares (
                id, type, content, filename, description, password,
                max_views, views, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            id,                    // id
            'bookmark',           // type
            url,                  // content (存储URL)
            title || url,         // filename (存储标题)
            description || '',    // description
            password || null,     // password
            maxViews || 0,       // max_views
            0,                    // views
            Date.now(),          // created_at
            expiresAt || null    // expires_at
        ).run();
    
    return c.json({
      success: true,
            data: {
                id,
                url: `/s/${id}`,
                expiresAt,
                createdAt: Date.now()
            }
        });
  } catch (error) {
        console.error('创建书签分享失败:', error);
    return c.json({
      success: false,
            message: error.message || '创建书签分享失败'
        }, 500);
  }
});

// 下载处理
app.get('/download/:id', async (c) => {
  try {
    const id = c.req.param('id')
    
    // TODO: 处理下载逻辑
    // 1. 从KV获取元数据
    // 2. 验证密码和访问次数
    // 3. 从R2获取文件或重定向到书签URL
    
    return c.json({
      success: true,
      message: '下载成功'
    })
  } catch (error) {
    return c.json({
      success: false,
      error: error.message
    }, 500)
  }
})

// 更新文本内容
app.put('/api/text/:id', async (c) => {
  try {
        const id = c.req.param('id');
        const data = await c.req.json();
        const { filename, content, password, duration, maxViews } = data;

        // 从数据库中获取原始分享数据
        const shareData = await c.env.DB.prepare(`
            SELECT * FROM shares WHERE id = ? AND type = 'text'
        `).bind(id).first();

    if (!shareData) {
      return c.json({
        success: false,
        message: '分享不存在'
            }, 404);
    }

    // 计算新的过期时间
        let expiresAt = null;
    if (duration) {
      switch (duration) {
        case '1h':
                    expiresAt = Date.now() + 60 * 60 * 1000;
                    break;
        case '1d':
                    expiresAt = Date.now() + 24 * 60 * 60 * 1000;
                    break;
        case '7d':
                    expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
                    break;
        case '30d':
                    expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
                    break;
      }
    }

    // 更新分享数据
        await c.env.DB.prepare(`
            UPDATE shares 
            SET filename = COALESCE(?, filename),
                content = COALESCE(?, content),
                password = COALESCE(?, password),
                max_views = COALESCE(?, max_views),
                expires_at = COALESCE(?, expires_at)
            WHERE id = ?
        `).bind(
            filename || null,
            content || null,
            password || null,
            maxViews || null,
            expiresAt || null,
            id
        ).run();

        console.log('文本分享更新成功:', id);
    
    return c.json({
      success: true,
      data: {
        id,
        url: `/s/${id}`,
                expiresAt
      }
        });
  } catch (error) {
        console.error('更新文本分享失败:', error);
    return c.json({
      success: false,
      message: error.message || '更新文本分享失败'
        }, 500);
  }
});

// 删除分享
app.delete('/api/share/:id', async (c) => {
  try {
        const id = c.req.param('id');
        console.log('处理删除请求:', id);

        // 从数据库中获取分享信息
        const shareData = await c.env.DB.prepare(`
            SELECT * FROM shares WHERE id = ?
        `).bind(id).first();

    if (!shareData) {
      return c.json({
        success: false,
        message: '分享不存在'
            }, 404);
    }

        console.log('找到分享:', shareData);

    // 如果是文件类型，从 R2 中删除文件
    if (shareData.type === 'file') {
            console.log('删除 R2 文件:', id);
      try {
                await c.env.CLOUDPASTE_BUCKET.delete(id);
                console.log('R2 文件删除成功');
      } catch (err) {
                console.error('删除 R2 文件失败:', err);
                // 即使删除 R2 文件失败，也继续删除数据库记录
            }
        }

        // 从数据库中删除分享记录
        console.log('删除数据库记录');
        await c.env.DB.prepare(`
            DELETE FROM shares WHERE id = ?
        `).bind(id).run();
        console.log('数据库记录删除成功');

    return c.json({
      success: true,
      message: '分享已删除'
        });
  } catch (error) {
        console.error('删除分享失败:', error);
    return c.json({
      success: false,
      message: error.message || '删除分享失败'
        }, 500);
  }
});

// 获取分享内容
app.get('/s/:id', async (c) => {
    try {
        const id = c.req.param('id');
        const isApi = c.req.header('X-Requested-With') === 'XMLHttpRequest';
        
        // 如果不是API请求，重定向到share.html页面
        if (!isApi) {
            return c.redirect(`/share.html?id=${id}`);
        }
        
        // 从数据库中获取分享数据
        const shareData = await c.env.DB.prepare(`
            SELECT * FROM shares WHERE id = ?
        `).bind(id).first();

        if (!shareData) {
            return c.json({
                success: false,
                message: '分享不存在或已过期'
            }, 404);
        }

        // 检查是否过期
        if (shareData.expires_at && Date.now() > shareData.expires_at) {
            return c.json({
                success: false,
                message: '分享已过期'
            }, 410);
        }

        // 检查是否需要密码
        if (shareData.password) {
            const accessToken = c.req.header('X-Access-Token');
            if (!accessToken) {
                return c.json({
                    success: false,
                    message: '需要密码访问',
                    requirePassword: true
                }, 403);
            }

            // 验证密码
            if (shareData.password !== accessToken) {
                return c.json({
                    success: false,
                    message: '密码错误'
                }, 403);
            }
        }

        // 检查访问次数
        if (shareData.max_views > 0 && shareData.views >= shareData.max_views) {
            return c.json({
                success: false,
                message: '分享已达到最大访问次数'
            }, 410);
        }

        // 更新访问次数
        await c.env.DB.prepare(`
            UPDATE shares 
            SET views = views + 1 
            WHERE id = ?
        `).bind(id).run();

        // 根据分享类型返回不同的响应
        switch (shareData.type) {
            case 'text':
                return c.json({
                    success: true,
                    data: {
                        type: 'text',
                        filename: shareData.filename,
                        content: shareData.content,
                        created: shareData.created_at,
                        views: shareData.views + 1,
                        maxViews: shareData.max_views,
                        expiresAt: shareData.expires_at,
                        hasPassword: !!shareData.password
                    }
                });

            case 'file':
                return c.json({
                    success: true,
                    data: {
                        type: 'file',
                        filename: shareData.filename,
                        originalname: shareData.original_name,
                        size: shareData.file_size,
                        mimeType: shareData.mimetype,
                        created: shareData.created_at,
                        views: shareData.views + 1,
                        maxViews: shareData.max_views,
                        expiresAt: shareData.expires_at,
                        hasPassword: !!shareData.password
                    }
                });

            default:
                return c.json({
                    success: false,
                    message: '不支持的分享类型'
                }, 400);
        }
    } catch (error) {
        console.error('获取分享内容失败:', error);
        return c.json({
            success: false,
            message: error.message || '获取分享内容失败'
        }, 500);
    }
});

// 文件下载处理
app.get('/s/:id/download', async (c) => {
    try {
        const id = c.req.param('id');
        
        // 从数据库中获取分享数据
        const shareData = await c.env.DB.prepare(`
            SELECT * FROM shares WHERE id = ? AND type = 'file'
        `).bind(id).first();

        if (!shareData) {
            return c.json({
                success: false,
                message: '文件不存在或已过期'
            }, 404);
        }

        // 检查是否过期
        if (shareData.expires_at && Date.now() > shareData.expires_at) {
            return c.json({
                success: false,
                message: '文件已过期'
            }, 410);
        }

        // 从 R2 获取文件
        const file = await c.env.CLOUDPASTE_BUCKET.get(id);
        if (!file) {
            return c.json({
                success: false,
                message: '文件不存在'
            }, 404);
        }

        // 设置响应头
        const headers = new Headers();
        headers.set('Content-Type', shareData.mimetype || 'application/octet-stream');
        headers.set('Content-Disposition', `attachment; filename="${encodeURIComponent(shareData.original_name || shareData.filename)}"`);

        // 更新下载次数
        await c.env.DB.prepare(`
            UPDATE shares 
            SET views = views + 1 
            WHERE id = ?
        `).bind(id).run();

        // 返回文件内容
        return new Response(file.body, { headers });
    } catch (error) {
        console.error('下载文件失败:', error);
        return c.json({
            success: false,
            message: error.message || '下载文件失败'
        }, 500);
    }
});

// 验证分享密码
app.post('/s/:id/verify', async (c) => {
  try {
        const id = c.req.param('id');
        const { password } = await c.req.json();

        // 从数据库中获取分享数据
        const shareData = await c.env.DB.prepare(`
            SELECT password FROM shares WHERE id = ?
        `).bind(id).first();

    if (!shareData) {
      return c.json({
        success: false,
        message: '分享不存在或已过期'
            }, 404);
    }

    // 验证密码
    if (shareData.password !== password) {
      return c.json({
        success: false,
        message: '密码错误'
            }, 403);
    }

    return c.json({
      success: true,
      message: '密码验证成功'
        });
  } catch (error) {
        console.error('验证密码失败:', error);
    return c.json({
      success: false,
      message: error.message || '验证密码失败'
        }, 500);
  }
});

// 管理员登录验证
app.post('/api/admin/login', async (c) => {
  try {
        const { username, password } = await c.req.json();

    // 从环境变量获取管理员凭证，如果未配置则使用默认值
        const adminUsername = c.env.ADMIN_USERNAME || 'admin';
        const adminPassword = c.env.ADMIN_PASSWORD || 'admin';

    // 验证用户名和密码
    if (username === adminUsername && password === adminPassword) {
      // 生成会话ID
            const sessionId = crypto.randomUUID();
      
      // 计算过期时间
            let expiresAt = null;
      switch (c.env.SESSION_DURATION || '7d') {
        case '1h':
                    expiresAt = Date.now() + 60 * 60 * 1000;
                    break;
        case '1d':
                    expiresAt = Date.now() + 24 * 60 * 60 * 1000;
                    break;
        case '7d':
                    expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
                    break;
        case '30d':
                    expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
                    break;
        default:
                    expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 默认7天
            }

            // 创建会话表（如果不存在）
            await c.env.DB.prepare(`
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
            `).run();

            // 保存会话信息到数据库
            await c.env.DB.prepare(`
                INSERT INTO sessions (id, username, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            `).bind(
                sessionId,
                adminUsername,
                Date.now(),
        expiresAt
            ).run();

      return c.json({
        success: true,
        message: '登录成功',
        data: {
          sessionId,
          expiresAt
        }
            });
    } else {
      return c.json({
        success: false,
        message: '用户名或密码错误'
            }, 401);
    }
  } catch (error) {
        console.error('登录验证失败:', error);
    return c.json({
      success: false,
      message: error.message || '登录验证失败'
        }, 500);
  }
});

// 验证会话状态
app.get('/api/admin/session', async (c) => {
  try {
        const sessionId = c.req.header('X-Session-Id');
    if (!sessionId) {
      return c.json({
        success: false,
        message: '未提供会话ID'
            }, 401);
        }

        // 从数据库获取会话信息
        const sessionData = await c.env.DB.prepare(`
            SELECT * FROM sessions WHERE id = ?
        `).bind(sessionId).first();

    if (!sessionData) {
      return c.json({
        success: false,
        message: '会话已过期或不存在'
            }, 401);
    }

    // 检查是否过期
        if (Date.now() > sessionData.expires_at) {
      // 删除过期会话
            await c.env.DB.prepare(`
                DELETE FROM sessions WHERE id = ?
            `).bind(sessionId).run();

      return c.json({
        success: false,
        message: '会话已过期'
            }, 401);
    }

    return c.json({
      success: true,
      data: {
        username: sessionData.username,
                expiresAt: sessionData.expires_at
      }
        });
  } catch (error) {
        console.error('验证会话失败:', error);
    return c.json({
      success: false,
      message: error.message || '验证会话失败'
        }, 500);
  }
});

// 退出登录
app.post('/api/admin/logout', async (c) => {
  try {
        const sessionId = c.req.header('X-Session-Id');
    if (sessionId) {
            // 从数据库中删除会话
            await c.env.DB.prepare(`
                DELETE FROM sessions WHERE id = ?
            `).bind(sessionId).run();
    }
    return c.json({
      success: true,
      message: '已退出登录'
        });
  } catch (error) {
        console.error('退出登录失败:', error);
    return c.json({
      success: false,
      message: error.message || '退出登录失败'
        }, 500);
  }
});

// 获取设置
app.get('/api/admin/settings', async (c) => {
  try {
        // 创建设置表（如果不存在）
        await c.env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        `).run();

        // 从数据库中获取设置
        const settings = await c.env.DB.prepare(`
            SELECT * FROM settings WHERE key IN ('textUploadEnabled', 'fileUploadEnabled')
        `).all();

        // 如果设置不存在，使用环境变量的默认值
        const result = {
      textUploadEnabled: c.env.TEXT_UPLOAD_ENABLED === 'true',
      fileUploadEnabled: c.env.FILE_UPLOAD_ENABLED === 'true'
    };

        // 使用数据库中的设置覆盖默认值
        settings.results?.forEach(setting => {
            result[setting.key] = setting.value === 'true';
        });
    
    return c.json({
      success: true,
            settings: result
    });
  } catch (error) {
    console.error('获取设置失败:', error);
    return c.json({
      success: false,
      message: '获取设置失败'
    }, 500);
  }
});

// 更新设置
app.post('/api/admin/settings', async (c) => {
  try {
    const { textUploadEnabled, fileUploadEnabled } = await c.req.json();
    
        // 保存设置到数据库
        await c.env.DB.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?), (?, ?)
        `).bind(
            'textUploadEnabled',
            textUploadEnabled.toString(),
            'fileUploadEnabled',
            fileUploadEnabled.toString()
        ).run();
    
    return c.json({
      success: true,
      message: '设置已保存'
    });
  } catch (error) {
    console.error('保存设置失败:', error);
    return c.json({
      success: false,
      message: '保存设置失败'
    }, 500);
  }
});

// 验证上传权限
async function checkUploadPermission(c, type) {
  try {
        // 从数据库中获取设置
        const settings = await c.env.DB.prepare(`
            SELECT * FROM settings WHERE key IN ('textUploadEnabled', 'fileUploadEnabled')
        `).all();

        // 如果设置不存在，使用环境变量的默认值
        const result = {
      textUploadEnabled: c.env.TEXT_UPLOAD_ENABLED === 'true',
      fileUploadEnabled: c.env.FILE_UPLOAD_ENABLED === 'true'
    };
    
        // 使用数据库中的设置覆盖默认值
        settings.results?.forEach(setting => {
            result[setting.key] = setting.value === 'true';
        });
        
        if (type === 'text' && !result.textUploadEnabled) {
      return c.json({
        success: false,
        message: '文本上传功能已关闭'
      }, 403);
    }
    
        if (type === 'file' && !result.fileUploadEnabled) {
      return c.json({
        success: false,
        message: '文件上传功能已关闭'
      }, 403);
    }
    
    return true;
  } catch (error) {
    console.error('验证上传权限失败:', error);
    return c.json({
      success: false,
      message: '验证上传权限失败'
    }, 500);
  }
}

export default app 