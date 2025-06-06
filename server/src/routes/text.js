const express = require('express');
const router = express.Router();
const Share = require('../models/Share');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

// 创建文本分享
router.post('/', async (req, res) => {
    try {
        console.log('Creating text share:', req.body);
        const { filename, content, password, duration, customUrl, maxViews} = req.body;

        // 验证必需字段
        if (!content) {
            console.log('Content is empty');
            return res.status(400).json({
                success: false,
                message: '内容不能为空'
            });
        }

        // 计算过期时间
        let expiresAt = new Date();
        switch (duration) {
            case '1h':
                expiresAt.setHours(expiresAt.getHours() + 1);
                break;
            case '1d':
                expiresAt.setDate(expiresAt.getDate() + 1);
                break;
            case '7d':
                expiresAt.setDate(expiresAt.getDate() + 7);
                break;
            case '30d':
                expiresAt.setDate(expiresAt.getDate() + 30);
                break;
            case 'never':
                expiresAt = null;
                break;
            default:
                expiresAt.setDate(expiresAt.getDate() + 1); // 默认1天
        }

        // 处理密码
        let hashedPassword = null;
        if (password) {
            hashedPassword = await bcrypt.hash(password, 10);
        }

        // 创建分享
        const share = new Share({
            id: uuidv4(),
            type: 'text',
            filename: filename,
            content,
            password: hashedPassword,
            expiresAt,
            maxViews: maxViews || 0,
            customUrl: customUrl || null,
            created: new Date(),
            lastAccessed: new Date(),
            views: 0
        });

        console.log('Saving share:', share);
        await share.save();
        console.log('Share saved successfully');

        const responseData = {
            success: true,
            data: {
                id: share.id,
                url: customUrl ? `/s/${customUrl}` : `/s/${share.id}`
            }
        };
        console.log('Sending response:', responseData);
        res.json(responseData);
    } catch (err) {
        console.error('Error creating text share:', err);
        res.status(500).json({
            success: false,
            message: err.message || '创建分享失败'
        });
    }
});

// 获取文本分享内容
router.get('/:id', async (req, res) => {
    try {
        const share = await Share.findOne({
            $or: [
                { id: req.params.id },
                { customUrl: req.params.id }
            ]
        });

        if (!share) {
            return res.status(404).json({
                success: false,
                message: '分享不存在或已过期'
            });
        }

        // 检查是否需要密码
        if (share.password && !req.headers['x-access-token']) {
            return res.status(403).json({
                success: false,
                message: '需要密码访问',
                requirePassword: true
            });
        }

        // 验证密码
        if (share.password) {
            const isValid = await bcrypt.compare(req.headers['x-access-token'], share.password);
            if (!isValid) {
                return res.status(403).json({
                    success: false,
                    message: '密码错误'
                });
            }
        }

        // 检查访问次数
        if (share.maxViews > 0 && share.views >= share.maxViews) {
            return res.status(403).json({
                success: false,
                message: '已达到最大访问次数'
            });
        }

        // 更新访问信息
        share.views += 1;
        share.lastAccessed = new Date();
        await share.save();

        res.json({
            success: true,
            data: {
                type: 'text',
                filename: share.filename,
                content: share.content,
                created: share.created,
                views: share.views,
                expiresAt: share.expiresAt,
                maxViews: share.maxViews || 0,
                hasPassword: !!share.password
            }
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// 更新文本分享内容
router.put('/:id', async (req, res) => {
    try {
        const { content, maxViews } = req.body;
        
        // 验证必需字段
        if (!content) {
            return res.status(400).json({
                success: false,
                message: '内容不能为空'
            });
        }

        const share = await Share.findOne({
            $or: [
                { id: req.params.id },
                { customUrl: req.params.id }
            ]
        });

        if (!share) {
            return res.status(404).json({
                success: false,
                message: '分享不存在或已过期'
            });
        }

        // 更新内容和访问次数
        share.content = content;
        if (typeof maxViews === 'number') {
            share.maxViews = maxViews;
        }
        
        await share.save();

        res.json({
            success: true,
            message: '更新成功'
        });
    } catch (err) {
        console.error('更新分享内容失败:', err);
        res.status(500).json({
            success: false,
            message: err.message || '更新分享内容失败'
        });
    }
});

module.exports = router; 