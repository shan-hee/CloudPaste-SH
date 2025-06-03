// 显示Toast提示
function showToast(message = '内容已复制到剪贴板', duration = 2000, type = 'info') {
    const toast = document.getElementById('toast');
    const messageSpan = toast.querySelector('span');
    
    // 设置最高层级
    toast.style.zIndex = '999999';
    
    // 清空现有内容
    messageSpan.textContent = '';
    
    // 根据类型设置不同的样式和图标
    toast.className = 'toast';
    if (type === 'error') {
        toast.classList.add('error');
        messageSpan.innerHTML = `<i class="fas fa-times" style="margin-right: 8px; color: #ff4d4f;"></i>${message}`;
    } else if (type === 'warning') {
        toast.classList.add('warning');
        messageSpan.innerHTML = `<i class="fas fa-exclamation-circle" style="margin-right: 8px; color: #faad14;"></i>${message}`;
    } else {
        messageSpan.innerHTML = `<i class="fas fa-check-circle" style="margin-right: 8px; color: #4CAF50;"></i>${message}`;
    }
    
    // 清除之前的定时器
    if (toast.hideTimeout) {
        clearTimeout(toast.hideTimeout);
    }
    
    // 显示 toast
    toast.classList.add('show');
    
    // 设置定时器隐藏 toast
    toast.hideTimeout = setTimeout(() => {
        toast.classList.remove('show');
        // 重置样式
        setTimeout(() => {
            toast.classList.remove('error', 'warning');
            messageSpan.textContent = '';
        }, 300);
    }, duration);
}

// 主题切换功能
const themeToggle = document.getElementById('themeToggle');
const themeIcon = themeToggle.querySelector('i');

function updateThemeIcon(theme) {
    themeIcon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
}

// 检测系统主题
function detectSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

// 应用主题
function applyTheme(theme) {
    if (theme === 'auto') {
        theme = detectSystemTheme();
    }
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);
}

// 监听系统主题变化
const systemThemeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
systemThemeMediaQuery.addListener(() => {
    const currentTheme = localStorage.getItem('theme') || 'auto';
    if (currentTheme === 'auto') {
        applyTheme('auto');
    }
});

// 初始化主题
const savedTheme = localStorage.getItem('theme') || 'auto';
applyTheme(savedTheme);

// 点击按钮切换主题
themeToggle.addEventListener('click', () => {
    const currentTheme = localStorage.getItem('theme') || 'auto';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    localStorage.setItem('theme', newTheme);
    applyTheme(newTheme);
});

// 获取分享ID
const shareId = window.location.pathname.split('/')[2];
const contentArea = document.getElementById('contentArea');

// 获取DOM元素
const editBtn = document.getElementById('editBtn');
const saveBtn = document.getElementById('saveBtn');
const cancelBtn = document.getElementById('cancelBtn');
const editMode = document.querySelector('.edit-mode');
const shareContentdiv = document.getElementById('shareContentdiv');
const shareContent = document.getElementById('shareContent');
const editContent = document.getElementById('editContent');
const previewContent = document.getElementById('previewContent');
const fullscreenBtn = document.getElementById('fullscreenBtn');
const undoBtn = document.getElementById('undoBtn');
const redoBtn = document.getElementById('redoBtn');
const previewModeBtn = document.getElementById('previewModeBtn');
const filename = document.getElementById('filename');

// 预览模式状态
let isPreviewMode = true;
let originalFilename = '';

// 确保预览区域存在并返回预览内容元素
function ensurePreviewContent() {
    const previewPane = document.querySelector('.preview-pane');
    if (!previewPane) {
        console.error('找不到预览区域容器');
        return null;
    }

    let previewContent = previewPane.querySelector('.preview-content');
    if (!previewContent) {
        previewContent = document.createElement('div');
        previewContent.className = 'preview-content markdown-body';
        previewPane.appendChild(previewContent);
    }
    return previewContent;
}

// 更新Markdown预览内容
function updateMarkdownPreview(markdown) {
    try {
        const previewContent = ensurePreviewContent();
        if (!previewContent) return;

        // 如果没有内容，清空预览区域并返回
        if (!markdown) {
            previewContent.innerHTML = '';
            return;
        }

        const html = marked.parse(markdown);
        previewContent.innerHTML = html;

        // 对新内容应用代码高亮
        previewContent.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightBlock(block);
        });
    } catch (error) {
        console.error('Markdown渲染错误:', error);
        const previewContent = ensurePreviewContent();
        if (previewContent) {
            previewContent.innerHTML = `<div class="error">Markdown渲染错误: ${error.message}</div>`;
        }
    }
}

// 编辑器历史记录管理
const editorHistory = {
    undoStack: [],
    redoStack: [],
    lastSavedContent: '',

    // 保存编辑历史
    save(content) {
        // 如果内容没有变化，不保存历史
        if (content === this.lastSavedContent) {
            return;
        }
        
        this.undoStack.push(this.lastSavedContent);
        this.lastSavedContent = content;
        // 清空重做栈
        this.redoStack = [];
        this.updateButtons();
    },

    // 重置历史记录
    reset(initialContent = '') {
        this.undoStack = [];
        this.redoStack = [];
        this.lastSavedContent = initialContent;
        this.updateButtons();
    },

    // 撤销
    undo() {
        if (this.undoStack.length > 0) {
            const currentContent = editContent.value;
            const previousContent = this.undoStack.pop();
            
            // 保存当前内容到重做栈
            this.redoStack.push(currentContent);
            
            // 更新编辑器内容
            editContent.value = previousContent;
            this.lastSavedContent = previousContent;
            
            // 更新预览
            updateMarkdownPreview(previousContent);
            
            // 更新按钮状态
            this.updateButtons();
        }
    },

    // 重做
    redo() {
        if (this.redoStack.length > 0) {
            const currentContent = editContent.value;
            const nextContent = this.redoStack.pop();
            
            // 保存当前内容到撤销栈
            this.undoStack.push(currentContent);
            
            // 更新编辑器内容
            editContent.value = nextContent;
            this.lastSavedContent = nextContent;
            
            // 更新预览
            updateMarkdownPreview(nextContent);
            
            // 更新按钮状态
            this.updateButtons();
        }
    },

    // 更新按钮状态
    updateButtons() {
        if (undoBtn) undoBtn.disabled = this.undoStack.length === 0;
        if (redoBtn) redoBtn.disabled = this.redoStack.length === 0;
    }
};

// 切换到编辑模式
editBtn.addEventListener('click', () => {
    if (isPreviewMode) {
        exitPreviewMode();
    }
    
    // 保存原始文件名和内容
    originalFilename = filename.value;
    
    // 启用文件名编辑
    filename.readOnly = false;
    
    // 显示编辑界面
    shareContentdiv.style.display = 'none';
    editMode.style.display = 'block';
    editContent.value = shareContent.value;
    
    // 添加编辑状态样式
    editBtn.classList.add('editing');
    
    // 初始化同步滚动
    initSyncScroll();
    
    // 启用可访问次数和过期时间输入框
    const viewCountInput = document.getElementById('viewCount');
    const expireTimeInput = document.getElementById('expireTime');
    viewCountInput.removeAttribute('readonly');
    expireTimeInput.removeAttribute('readonly');
    
    // 确保预览区域已初始化
    ensurePreviewContent();
    
    // 初始化编辑历史
    editorHistory.reset(shareContent.value);
    
    // 绑定预览更新事件
    editContent.addEventListener('input', () => {
        const currentContent = editContent.value;
        updateMarkdownPreview(currentContent);
        editorHistory.save(currentContent);
    });
    
    // 立即更新一次预览
    updateMarkdownPreview(editContent.value);
});

// 撤销功能
undoBtn.addEventListener('click', () => editorHistory.undo());

// 重做功能
redoBtn.addEventListener('click', () => editorHistory.redo());

// 工具栏功能
document.querySelectorAll('.toolbar-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const command = btn.getAttribute('title');
        const textarea = editContent;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selectedText = textarea.value.substring(start, end);
        const previewContent = document.querySelector('.preview-pane .preview-content');

        let newText = '';
        switch (command) {
            case '加粗':
                newText = `**${selectedText}**`;
                break;
            case '斜体':
                newText = `*${selectedText}*`;
                break;
            case '删除线':
                newText = `~~${selectedText}~~`;
                break;
            case '标题':
                newText = `# ${selectedText}`;
                break;
            case '无序列表':
                newText = `- ${selectedText}`;
                break;
            case '有序列表':
                newText = `1. ${selectedText}`;
                break;
            case '引用':
                newText = `> ${selectedText}`;
                break;
            case '插入链接':
                const url = prompt('请输入链接地址：');
                if (url) {
                    newText = `[${selectedText || '链接文字'}](${url})`;
                }
                break;
            case '插入图片':
                const imgUrl = prompt('请输入图片地址：');
                if (imgUrl) {
                    newText = `![${selectedText || '图片描述'}](${imgUrl})`;
                }
                break;
            case '插入代码':
                if (selectedText.includes('\n')) {
                    newText = `\`\`\`\n${selectedText}\n\`\`\``;
                } else {
                    newText = `\`${selectedText}\``;
                }
                break;
            case '插入表格':
                newText = `| 表头1 | 表头2 |\n| --- | --- |\n| 内容1 | 内容2 |`;
                break;
            case '清空':
                // 保存当前内容到撤销栈
                editorHistory.save(textarea.value);
                // 清空编辑器内容
                textarea.value = '';
                previewContent.innerHTML = '';
                // 保存空内容到历史
                editorHistory.save('');
                return;
            case '全屏编辑':
                toggleFullscreen();
                return;
        }
        
        if (newText) {
            const oldContent = textarea.value;
            const newContent = oldContent.substring(0, start) + newText + oldContent.substring(end);
            
            // 保存当前内容到历史
            editorHistory.save(oldContent);
            
            // 更新编辑器内容
            textarea.value = newContent;
            textarea.focus();
            textarea.selectionStart = start;
            textarea.selectionEnd = start + newText.length;
            
            // 更新预览
            updateMarkdownPreview(newContent);
            
            // 保存新内容到历史
            editorHistory.save(newContent);
        }
    });
});

// 取消编辑
cancelBtn.addEventListener('click', () => {
    // 恢复原始文件名
    filename.value = originalFilename;
    
    // 禁用文件名编辑
    filename.readOnly = true;
    
    // 切换回预览模式
    togglePreviewMode();
});

// 编辑历史记录
let undoStack = [];
let redoStack = [];

// 初始化预览模式
function initPreviewMode() {
    const previewContent = document.querySelector('.preview-pane .preview-content');
    if (!previewContent) {
        console.error('找不到预览区域元素');
        return;
    }

    if (isPreviewMode) {
        previewModeBtn.classList.add('active');
        // 确保预览内容是最新的
        if (editContent && editContent.value) {
            updateMarkdownPreview(editContent.value);
        }
    }
}

// 切换预览模式
function togglePreviewMode() {
    if (!isPreviewMode) {
        isPreviewMode = true;
        previewModeBtn.classList.add('active');
        shareContent.value=editContent.value  ;
        shareContentdiv.style.display = 'block';    
        shareContent.style.display = 'block';
        
        // 关闭编辑模式
        shareContent.style.display = 'block';
        editMode.style.display = 'none';
        // 禁用标题编辑
        filename.readOnly = true;
        // 移除编辑状态样式
        editBtn.classList.remove('editing');
        if (editMode.classList.contains('fullscreen')) {
            toggleFullscreen();
        }
    }
}



// 退出预览模式
function exitPreviewMode() {
    if (!isPreviewMode) {
        return;
    }
    
    isPreviewMode = false;
    previewModeBtn.classList.remove('active');
}

// 预览模式按钮点击事件
previewModeBtn.addEventListener('click', togglePreviewMode);

// 文件类型图标映射
const fileIconMap = {
    'image': 'fa-file-image',
    'video': 'fa-file-video',
    'audio': 'fa-file-audio',
    'pdf': 'fa-file-pdf',
    'word': 'fa-file-word',
    'excel': 'fa-file-excel',
    'powerpoint': 'fa-file-powerpoint',
    'archive': 'fa-file-archive',
    'code': 'fa-file-code',
    'text': 'fa-file-alt',
    'default': 'fa-file'
};

// 获取文件类型图标
function getFileIcon(mimeType) {
    if (!mimeType) return fileIconMap.default;
    
    if (mimeType.startsWith('image/')) return fileIconMap.image;
    if (mimeType.startsWith('video/')) return fileIconMap.video;
    if (mimeType.startsWith('audio/')) return fileIconMap.audio;
    if (mimeType === 'application/pdf') return fileIconMap.pdf;
    if (mimeType.includes('word')) return fileIconMap.word;
    if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) return fileIconMap.excel;
    if (mimeType.includes('powerpoint') || mimeType.includes('presentation')) return fileIconMap.powerpoint;
    if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('7z')) return fileIconMap.archive;
    if (mimeType.includes('javascript') || mimeType.includes('json') || mimeType.includes('html') || mimeType.includes('css')) return fileIconMap.code;
    if (mimeType.startsWith('text/')) return fileIconMap.text;
    
    return fileIconMap.default;
}

// 显示内容容器并隐藏加载状态
function showContent() {
    const loadingContainer = document.getElementById('loadingContainer');
    const contentContainer = document.getElementById('contentContainer');

    if (loadingContainer) {
        loadingContainer.style.display = 'none';
    }
    if (contentContainer) {
        contentContainer.style.display = 'block';
    }
}

// 显示错误状态
function showError(message) {
    const loadingContainer = document.getElementById('loadingContainer');
    if (loadingContainer) {
        loadingContainer.innerHTML = `
            <div class="loading-spinner">
                <i class="fas fa-exclamation-triangle" style="color: #ff6b6b;"></i>
            </div>
            <div class="loading-text" style="color: #ff6b6b;">${message}</div>
            <div style="margin-top: 20px;">
                <button onclick="window.location.reload()" style="padding: 8px 16px; border: 1px solid #ff6b6b; background: transparent; color: #ff6b6b; border-radius: 4px; cursor: pointer;">
                    重新加载
                </button>
            </div>
        `;
    }
}

// 加载分享内容
async function loadShareContent() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const shareId = urlParams.get('id');

        if (!shareId) {
            showToast('无效的分享链接', 3000);
            return;
        }
        
        let password = null;
        let needPassword = false;
        
        // 先尝试获取内容
        const response = await fetch(`/s/${shareId}`, {
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        let data = await response.json();
        
        // 如果需要密码验证
        while (response.status === 403 && data.requirePassword) {
            needPassword = true;
            // 显示密码输入对话框
            password = await showPasswordDialog(shareId);
            if (!password) {
                return; // 用户取消输入密码
            }
            
            // 验证密码
            const verifyResponse = await fetch(`/s/${shareId}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });
            
            const verifyResult = await verifyResponse.json();
            if (!verifyResult.success) {
                showToast('密码错误，请重试', 3000, 'error');
                continue; // 继续显示密码输入框
            }
            
            // 密码验证通过，重新获取内容
            const newResponse = await fetch(`/s/${shareId}`, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Access-Token': password
                }
            });
            
            data = await newResponse.json();
            if (!data.success) {
                showToast(data.message || '获取内容失败', 'error');
                continue; // 如果获取失败，继续要求输入密码
            }
            break; // 获取成功，跳出循环
        }
        
        if (data.success) {
            // 判断是否为文件
            if (data.data.type === 'file') {
                // 显示文件界面
                document.getElementById('fileDisplay').style.display = 'flex';
                document.getElementById('shareContentdiv').style.display = 'none';
                document.getElementById('editBtn').style.display = 'none';
                document.getElementById('previewModeBtn').style.display = 'none';
                document.getElementById('formatSelect').style.display = 'none';
                document.getElementById('downloadBtn').style.display = 'none';
                document.getElementById('copyBtn').style.display = 'none';
                // 隐藏二维码按钮
                const qrButton = document.querySelector('.qr-btn');
                if (qrButton) {
                    qrButton.style.display = 'none';
                }               
                // 更新文件信息
                const fileName = document.getElementById('fileName');
                fileName.textContent = data.data.originalname || data.data.filename;
                fileName.title = data.data.originalname || data.data.filename; // 添加悬停提示
                document.getElementById('fileSize').textContent = formatFileSize(data.data.size);
                
                // 更新文件图标
                const fileIcon = document.querySelector('.file-icon-container i');
                fileIcon.className = `fas ${getFileIcon(data.data.mimeType)} fa-4x`;
                
                // 设置下载按钮事件
                const downloadBtn = document.getElementById('downloadFileBtn');
                downloadBtn.onclick = () => window.location.href = `/s/${shareId}/download`;
            } else {
                // 文本内容显示
                document.getElementById('fileDisplay').style.display = 'none';
                document.getElementById('shareContentdiv').style.display = 'block';
                document.getElementById('editBtn').style.display = 'inline-flex';
                document.getElementById('previewModeBtn').style.display = 'inline-flex';
                document.getElementById('formatSelect').style.display = 'inline-block';
                document.getElementById('downloadBtn').style.display = 'inline-flex';
                shareContent.value = data.data.content;
                filename.value = data.data.filename;
                
                // 初始化预览模式
                initPreviewMode();
            }
            
            // 更新信息
            document.getElementById('createTime').textContent = formatDate(data.data.created);
            document.getElementById('viewCount').value = data.data.maxViews || 0;
            
            const expireTimeInput = document.getElementById('expireTime');
            if (data.data.expiresAt) {
                const expireDate = new Date(data.data.expiresAt);
                expireTimeInput.value = expireDate.toISOString().slice(0, 16);
            } else {
                expireTimeInput.value = '';
            }

            // 更新二维码按钮的URL
            const qrButton = document.querySelector('.qr-btn');
            if (qrButton) {
                qrButton.dataset.url = window.location.href;
            }

            // 显示内容，隐藏加载状态
            showContent();
        } else {
            showError(data.message || '加载分享内容失败');
        }
    } catch (error) {
        console.error('加载分享内容失败:', error);
        showError('加载分享内容失败');
    }
}

// 格式化日期
function formatDate(dateString) {
    if (!dateString) return '永久有效';
    const date = new Date(dateString);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 复制内容功能
document.getElementById('copyBtn').addEventListener('click', async () => {
    try {
        const shareContent = document.getElementById('shareContent');
        await navigator.clipboard.writeText(shareContent.value);
        showToast('内容已复制到剪贴板');
    } catch (err) {
        console.error('复制失败:', err);
        showToast('复制失败，请手动复制', 3000);
    }
});

// 复制分享链接
async function copyShareLink(id) {
    const shareLink = `${window.location.origin}/s/${id}`;
    try {
        await navigator.clipboard.writeText(shareLink);
        showToast();
    } catch (err) {
        console.error('复制失败:', err);
        alert('复制失败，请手动复制');
    }
}

// 删除文件
async function deleteFile(id) {
    if (!confirm('确定要删除这个文件吗？')) {
        return;
    }

    try {
        const response = await fetch(`/api/file/${id}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        
        if (data.success) {
            // 重新加载文件列表
            loadKVFiles();
            loadR2Files();
        } else {
            alert('删除失败：' + data.message);
        }
    } catch (error) {
        console.error('删除文件出错：', error);
        alert('删除文件出错');
    }
}

// 添加显示二维码函数
function toggleQRCode(url) {
    const qrCodeContainer = document.createElement('div');
    qrCodeContainer.className = 'qr-code-container';
    qrCodeContainer.style.cssText = 'display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); justify-content: center; align-items: center; z-index: 1000;';
    
    qrCodeContainer.innerHTML = `
        <div class="qr-code-modal" style="background: var(--container-bg); padding: 24px; border-radius: 8px; text-align: center; max-width: 90%; width: 320px; position: relative; transform: translateY(-20px); opacity: 0; transition: all 0.3s ease;">
            <h3 style="margin: 0 0 16px 0; font-size: 18px; color: var(--text-color);">扫描二维码访问</h3>
            <div class="qr-code" id="tempQrCode" style="margin-bottom: 16px; background: white; padding: 10px; border-radius: 4px;"></div>
            <div class="qr-code-actions" style="display: flex; gap: 10px; justify-content: center; align-items: center;">
                <button class="qr-download-btn" id="tempDownloadQRCode" style="padding: 8px 16px; border: 1px solid #e5e7eb; border-radius: 4px; cursor: pointer; min-width: 125px; background: var(--container-bg); color: var(--text-color); display: inline-flex; align-items: center; justify-content: center; gap: 4px; transition: all 0.2s ease;"><i class="fas fa-download"></i>下载二维码</button>
                <button class="qr-close-btn" style="padding: 8px 12px; border: 1px solid #e5e7eb; border-radius: 4px; cursor: pointer; min-width: 60px; background: var(--container-bg); color: var(--text-color); transition: all 0.2s ease;">关闭</button>
            </div>
        </div>
    `;
    
    // 添加悬浮效果
    const downloadBtn = qrCodeContainer.querySelector('.qr-download-btn');
    downloadBtn.addEventListener('mouseover', () => {
        const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
        if (isDarkTheme) {
            downloadBtn.style.background = 'white';
            downloadBtn.style.borderColor = '#4A90E2';
            downloadBtn.style.color = '#4A90E2';
        } else {
            downloadBtn.style.borderColor = '#4A90E2';
            downloadBtn.style.color = '#4A90E2';
        }
    });
    downloadBtn.addEventListener('mouseout', () => {
        const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
        if (isDarkTheme) {
            downloadBtn.style.background = 'var(--container-bg)';
            downloadBtn.style.borderColor = '#e5e7eb';
            downloadBtn.style.color = '#e5e7eb';
        } else {
            downloadBtn.style.borderColor = '#e5e7eb';
            downloadBtn.style.color = '#333';
        }
    });

    const modalCloseBtn = qrCodeContainer.querySelector('.qr-close-btn');
    modalCloseBtn.addEventListener('mouseover', () => {
        const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
        if (isDarkTheme) {
            modalCloseBtn.style.background = 'white';
            modalCloseBtn.style.borderColor = '#ff4d4f';
            modalCloseBtn.style.color = '#ff8f1f';
        } else {
            modalCloseBtn.style.borderColor = '#ff4d4f';
            modalCloseBtn.style.color = '#ff8f1f';
        }
    });
    modalCloseBtn.addEventListener('mouseout', () => {
        const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';
        if (isDarkTheme) {
            modalCloseBtn.style.background = 'var(--container-bg)';
            modalCloseBtn.style.borderColor = '#e5e7eb';
            modalCloseBtn.style.color = '#e5e7eb';
        } else {
            modalCloseBtn.style.borderColor = '#e5e7eb';
            modalCloseBtn.style.color = '#333';
        }
    });

    // 设置初始暗色主题样式
    if (document.documentElement.getAttribute('data-theme') === 'dark') {
        downloadBtn.style.color = '#e5e7eb';
        modalCloseBtn.style.color = '#e5e7eb';
    }
    
    document.body.appendChild(qrCodeContainer);
    
    // 生成二维码
    const qrCodeDiv = document.getElementById('tempQrCode');
    qrCodeDiv.innerHTML = '';
    
    // 生成新的二维码
    const qrcode = new QRCode(qrCodeDiv, {
        text: url,
        width: 250,
        height: 250,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H
    });
    
    // 下载按钮事件
    document.getElementById('tempDownloadQRCode').addEventListener('click', () => {
        const canvas = qrCodeDiv.querySelector('canvas');
        if (canvas) {
            const link = document.createElement('a');
            link.download = '分享链接二维码.png';
            link.href = canvas.toDataURL('image/png');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    });
    
    // 显示容器并添加动画
    qrCodeContainer.style.display = 'flex';
    setTimeout(() => {
        const modal = qrCodeContainer.querySelector('.qr-code-modal');
        modal.style.transform = 'translateY(0)';
        modal.style.opacity = '1';
    }, 10);
    
    // 关闭按钮事件
    modalCloseBtn.addEventListener('click', closeQRCode);
    
    // 阻止对话框上的点击事件冒泡到遮罩层
    const modal = qrCodeContainer.querySelector('.qr-code-modal');
    modal.addEventListener('click', (e) => {
        e.stopPropagation();
    });
    
    // 关闭函数
    function closeQRCode() {
        const modal = qrCodeContainer.querySelector('.qr-code-modal');
        modal.style.transform = 'translateY(-20px)';
        modal.style.opacity = '0';
        setTimeout(() => {
            qrCodeContainer.remove();
        }, 300);
    }
    
    // ESC键关闭
    document.addEventListener('keydown', function escListener(e) {
        if (e.key === 'Escape') {
            document.removeEventListener('keydown', escListener);
            closeQRCode();
        }
    });
} 

// 确保二维码按钮点击事件正确绑定
document.addEventListener('DOMContentLoaded', function() {
    const qrButton = document.querySelector('.qr-btn');
    if (qrButton) {
        qrButton.addEventListener('click', function() {
    const url = this.dataset.url || window.location.href;
    toggleQRCode(url);
        });
    }
});

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', function() {
    // 获取DOM元素
    const editBtn = document.getElementById('editBtn');
    const saveBtn = document.getElementById('saveBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const editMode = document.querySelector('.edit-mode');
    const shareContentdiv = document.getElementById('shareContentdiv');
    const shareContent = document.getElementById('shareContent');
    const editContent = document.getElementById('editContent');
    const previewContent = document.querySelector('.preview-pane .preview-content');
    const previewModeBtn = document.getElementById('previewModeBtn');
    
    // 初始化marked配置
    function initMarked() {
        try {
            if (typeof marked === 'undefined') {
                console.error('marked 未加载');
                return false;
            }

            const renderer = new marked.Renderer();
            
            // 处理代码块
            renderer.code = (code, language) => {
                if (!code) return '';
                code = String(code);
                
                if (language === 'math' || language === 'tex') {
                    try {
                        return `<div class="math-block">${katex.renderToString(code, {
                            displayMode: true,
                            throwOnError: false,
                            strict: false
                        })}</div>`;
                    } catch (error) {
                        console.error('KaTeX渲染错误:', error);
                        return `<pre class="error">KaTeX渲染错误: ${error.message}</pre>`;
                    }
                }
                
                // 处理普通代码块
                try {
                    if (typeof hljs !== 'undefined') {
                        const validLanguage = hljs.getLanguage(language) ? language : 'plaintext';
                        const highlightedCode = hljs.highlight(code, { language: validLanguage }).value;
                        return `<pre><code class="hljs ${validLanguage}">${highlightedCode}</code></pre>`;
                    }
                    // 如果 hljs 未定义，返回普通代码块
                    return `<pre><code>${code}</code></pre>`;
                } catch (error) {
                    console.error('代码高亮错误:', error);
                    return `<pre><code>${code}</code></pre>`;
                }
            };
            
            // 处理行内代码
            renderer.codespan = (code) => {
                if (!code) return '';
                code = String(code);
                
                if (code.startsWith('$') && code.endsWith('$')) {
                    try {
                        const tex = code.slice(1, -1);
                        return katex.renderToString(tex, {
                            displayMode: false,
                            throwOnError: false,
                            strict: false
                        });
                    } catch (error) {
                        console.error('KaTeX行内公式渲染错误:', error);
                        return `<code class="error">KaTeX错误: ${error.message}</code>`;
                    }
                }
                return `<code>${code}</code>`;
            };
            
            // 配置marked选项
            marked.setOptions({
                renderer: renderer,
                highlight: (code, lang) => {
                    if (!code) return '';
                    code = String(code);
                    
                    try {
                        if (typeof hljs !== 'undefined' && lang && hljs.getLanguage(lang)) {
                            return hljs.highlight(code, { language: lang }).value;
                        }
                        return code;
                    } catch (error) {
                        console.error('代码高亮错误:', error);
                        return code;
                    }
                },
                breaks: true,
                gfm: true,
                headerIds: true,
                mangle: false,
                pedantic: false,
                sanitize: false
            });
            
            return true;
        } catch (error) {
            console.error('marked初始化错误:', error);
            return false;
        }
    }

    // 更新预览函数
    function updatePreview() {
        try {
            const editContent = document.getElementById('editContent');
            const previewContent = document.querySelector('.preview-pane .preview-content');
            
            if (!editContent || !previewContent) {
                console.error('找不到编辑器或预览区域元素');
                return;
            }
            
            // 确保marked已初始化
            if (!initMarked()) {
                previewContent.innerHTML = '<div class="error">Markdown渲染器初始化失败</div>';
                return;
            }
            
            // 确保输入内容是字符串
            const markdown = String(editContent.value || '');
            
            try {
                const html = marked.parse(markdown);
                previewContent.innerHTML = html;
                
                // 渲染数学公式
                renderMathInElement(previewContent, {
                    delimiters: [
                        {left: '$$', right: '$$', display: true},
                        {left: '$', right: '$', display: false},
                        {left: '\\(', right: '\\)', display: false},
                        {left: '\\[', right: '\\]', display: true}
                    ],
                    throwOnError: false,
                    strict: false,
                    trust: true
                });
            } catch (error) {
                console.error('预览更新错误:', error);
                previewContent.innerHTML = `<div class="error">预览更新失败: ${error.message}</div>`;
            }
        } catch (error) {
            console.error('预览更新错误:', error);
            const previewContent = document.querySelector('.preview-pane .preview-content');
            if (previewContent) {
                previewContent.innerHTML = `<div class="error">预览更新失败: ${error.message}</div>`;
            }
        }
    }

// 切换到编辑模式
editBtn.addEventListener('click', () => {
    if (isPreviewMode) {
        exitPreviewMode();
    }
    
    // 保存原始文件名和内容
    originalFilename = filename.value;
    
    // 启用文件名编辑
    filename.readOnly = false;
    
    // 显示编辑界面
    shareContentdiv.style.display = 'none';
    editMode.style.display = 'block';
    editContent.value = shareContent.value;
    
    // 添加编辑状态样式
    editBtn.classList.add('editing');
    
    // 初始化同步滚动
    initSyncScroll();
    
    // 启用可访问次数和过期时间输入框
    const viewCountInput = document.getElementById('viewCount');
    const expireTimeInput = document.getElementById('expireTime');
    viewCountInput.removeAttribute('readonly');
    expireTimeInput.removeAttribute('readonly');
    
    // 确保预览区域已初始化
    ensurePreviewContent();
    
    // 初始化编辑历史
    editorHistory.reset(shareContent.value);
    
    // 绑定预览更新事件
    editContent.addEventListener('input', () => {
        const currentContent = editContent.value;
        updateMarkdownPreview(currentContent);
        editorHistory.save(currentContent);
    });
    
    // 立即更新一次预览
    updateMarkdownPreview(editContent.value);
});
    
    // 加载分享内容
    loadShareContent();
});

// 取消编辑
cancelBtn.addEventListener('click', () => {
    if (confirm('确定要取消编辑吗？未保存的更改将会丢失。')) {
        shareContentdiv.style.display = 'block';
        shareContent.style.display = 'block';
        editMode.style.display = 'none';
        // 移除编辑状态样式
        editBtn.classList.remove('editing');
        if (editMode.classList.contains('fullscreen')) {
            toggleFullscreen();
        }
        
        // 禁用可访问次数和过期时间编辑
        const viewCountInput = document.getElementById('viewCount');
        const expireTimeInput = document.getElementById('expireTime');
        viewCountInput.setAttribute('readonly', 'readonly');
        expireTimeInput.setAttribute('readonly', 'readonly');
        
        // 恢复预览模式
        isPreviewMode = true;
        previewModeBtn.classList.add('active');
    }
});

// 保存编辑
saveBtn.addEventListener('click', async () => {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const shareId = urlParams.get('id');
        const filename = document.getElementById('filename').value;
        const viewCount = parseInt(document.getElementById('viewCount').value) || 0;
        const expireTime = document.getElementById('expireTime').value;
        const currentContent = editContent.value;
        
        const requestData = {
            filename: filename,
            content: currentContent,
            maxViews: viewCount,
            expiresAt: expireTime || null
        };
        
        const response = await fetch(`/api/text/${shareId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(requestData)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        if (data.success) {
            shareContent.value = currentContent;
            shareContentdiv.style.display = 'block';
            shareContent.style.display = 'block';
            editMode.style.display = 'none';
            editBtn.classList.remove('editing');
            if (editMode.classList.contains('fullscreen')) {
                toggleFullscreen();
            }
            
            // 禁用标题编辑
            filename.readOnly = true;
            // 切换回预览模式
            togglePreviewMode();
            
            showToast('保存成功');
        } else {
            showToast(data.message || '保存失败', 3000);
        }
    } catch (error) {
        console.error('保存失败:', error);
        showToast('保存失败，请稍后重试', 3000);
    }
});

// 全屏编辑
function toggleFullscreen() {
    editMode.classList.toggle('fullscreen');
    const icon = fullscreenBtn.querySelector('i');
    if (editMode.classList.contains('fullscreen')) {
        icon.classList.remove('fa-expand');
        icon.classList.add('fa-compress');
    } else {
        icon.classList.remove('fa-compress');
        icon.classList.add('fa-expand');
    }
}

// 监听ESC键退出全屏
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && editMode.classList.contains('fullscreen')) {
        toggleFullscreen();
    }
});

// 导出功能
document.getElementById('downloadBtn').addEventListener('click', async () => {
    const format = document.getElementById('formatSelect').value;
    const content = document.getElementById('shareContent').value;
    const filename = `cloudpaste_${new Date().toISOString().slice(0,10)}`;

    if (format === 'pdf') {
        try {
            // 创建PDF文档
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            // 设置中文字体
            doc.setFont('chinese', 'normal');
            
            // 分割内容为多行
            const lines = doc.splitTextToSize(content, 180);
            
            // 设置初始y位置
            let y = 20;
            const lineHeight = 7;
            
            // 添加内容到PDF
            doc.setFontSize(12);
            
            // 分页处理
            for (let i = 0; i < lines.length; i++) {
                if (y > 280) {  // 如果即将超出页面
                    doc.addPage();  // 添加新页面
                    y = 20;  // 重置y坐标
                }
                doc.text(15, y, lines[i]);
                y += lineHeight;
            }
            
            // 下载PDF
            doc.save(`${filename}.pdf`);
            showToast('PDF导出成功');
        } catch (error) {
            console.error('导出PDF失败:', error);
            showToast('导出PDF失败，请稍后重试', 3000);
        }
    } else if (format === 'png') {
        try {
            // 创建临时容器
            const container = document.createElement('div');
            container.style.position = 'absolute';
            container.style.left = '-9999px';
            container.style.top = '0';
            container.style.width = '800px';
            container.style.background = 'white';
            container.style.padding = '20px';
            container.style.whiteSpace = 'pre-wrap';
            container.innerHTML = marked.parse(content);
            document.body.appendChild(container);

            // 使用html2canvas转换为图片
            const canvas = await html2canvas(container, {
                scale: 2,
                backgroundColor: 'white'
            });
            
            // 移除临时容器
            document.body.removeChild(container);

            // 创建下载链接
            const link = document.createElement('a');
            link.download = `${filename}.png`;
            link.href = canvas.toDataURL('image/png');
            link.click();
        } catch (error) {
            console.error('导出PNG失败:', error);
            showToast('导出PNG失败，请稍后重试', 3000);
        }
    }
});

// 获取分享统计数据
async function fetchShareStats() {
    try {
        // 获取存储列表数据
        const storageResponse = await fetch('/api/file');
        if (!storageResponse.ok) {
            throw new Error('获取存储列表失败');
        }
        const storageData = await storageResponse.json();
        
        if (storageData.success) {
            const stats = {
                totalShares: 0,
                activeShares: 0,
                usedStorage: 0
            };
            
            // 设置默认总容量为6GB
            const totalStorage = 6 * 1024 * 1024 * 1024; // 6GB in bytes
            
            // 计算总分享数和已用存储空间
            if (storageData.data) {
                // 计算KV存储的文本分享
                if (storageData.data.kv && Array.isArray(storageData.data.kv)) {
                    // 过滤掉系统生成的临时文件
                    const validKvShares = storageData.data.kv.filter(item => {
                        return item && item.type === 'text' && item.name && !item.name.startsWith('temp_');
                    });
                    stats.totalShares += validKvShares.length;
                    stats.activeShares += validKvShares.length;
                    // 估算文本存储大小
                    validKvShares.forEach(item => {
                        if (item && item.content) {
                            stats.usedStorage += item.content.length;
                        }
                    });
                }
                
                // 计算R2存储的文件分享
                if (storageData.data.r2 && Array.isArray(storageData.data.r2)) {
                    // 过滤掉没有原始文件名的文件和系统生成的临时文件
                    const validR2Shares = storageData.data.r2.filter(item => {
                        return item && item.originalname && item.filename && !item.filename.startsWith('temp_');
                    });
                    stats.totalShares += validR2Shares.length;
                    stats.activeShares += validR2Shares.length;
                    // 累加文件大小
                    validR2Shares.forEach(item => {
                        if (item && item.filesize) {
                            stats.usedStorage += item.filesize;
                        }
                    });
                }
            }
            
            // 计算使用百分比
            const usagePercent = (stats.usedStorage / totalStorage * 100).toFixed(1);
            
            // 返回统计结果
            return {
                ...stats,
                totalStorage,
                usagePercent: parseFloat(usagePercent)
            };
        }
    } catch (error) {
        console.error('获取统计数据失败:', error);
        showToast('获取统计数据失败', 3000);
    }
}

// 显示存储列表
function displayStorageList(data, newItem = null) {
    const shareItems = document.getElementById('shareItems');
    
    // 如果是新项插入，直接添加到列表中
    if (newItem) {
        const newItemHtml = createShareItem({
            id: newItem.filename || newItem.id,
            type: newItem.type,
            expiration: newItem.expiresAt,
            size: newItem.filesize || newItem.size || 0,
            filename: newItem.filename,
            originalname: newItem.originalname
        });
        shareItems.insertAdjacentHTML('afterbegin', newItemHtml);
        return;
    }

    // 显示完整列表
    const storageResults = document.createElement('div');
    storageResults.className = 'storage-results';

    // 合并KV和R2的数据为统一的分享列表
    const allShares = [
        ...(data.kv || []).filter(item => item.type === 'text' && !item.name.startsWith('temp_')).map(item => ({
            id: item.name,
            type: 'text',
            expiration: item.expiration * 1000,
            size: item.content ? item.content.length : 0,
            createdAt: item.createdAt
        })),
        ...(data.r2 || []).filter(item => item.originalname && !item.filename.startsWith('temp_')).map(item => ({
            id: item.filename,
            type: 'file',
            size: item.filesize,
            expiration: null,
            filename: item.filename,
            originalname: item.originalname,
            createdAt: item.createdAt
        }))
    ];

    // 按创建时间排序，最新的在前面
    allShares.sort((a, b) => {
        const timeA = a.createdAt || 0;
        const timeB = b.createdAt || 0;
        return timeB - timeA;
    });

    const sharesList = document.createElement('div');
    sharesList.className = 'shares-list';
    sharesList.innerHTML = allShares.map(item => createShareItem(item)).join('');

    storageResults.appendChild(sharesList);
    shareItems.innerHTML = ''; // 清空现有内容
    shareItems.appendChild(storageResults);

    // 添加事件监听器
    addStorageItemEventListeners();
}

// 同步滚动功能
let isEditorScrolling = false;
let isPreviewScrolling = false;

function initSyncScroll() {
    const editContent = document.getElementById('editContent');
    const previewContent = document.querySelector('.preview-pane .preview-content');
    
    if (!editContent || !previewContent) {
        console.error('找不到编辑器或预览区域元素');
        return;
    }
    
    // 计算滚动比例
    function getScrollRatio(element) {
        const scrollHeight = element.scrollHeight - element.clientHeight;
        return scrollHeight <= 0 ? 0 : element.scrollTop / scrollHeight;
    }
    
    // 设置滚动位置
    function setScrollRatio(element, ratio) {
        const scrollHeight = element.scrollHeight - element.clientHeight;
        if (scrollHeight > 0) {
            element.scrollTop = ratio * scrollHeight;
        }
    }
    
    // 防抖函数
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // 编辑器滚动处理
    const handleEditorScroll = debounce(() => {
        if (!isPreviewScrolling) {
            isEditorScrolling = true;
            const ratio = getScrollRatio(editContent);
            setScrollRatio(previewContent, ratio);
            setTimeout(() => {
                isEditorScrolling = false;
            }, 50);
        }
    }, 10);
    
    // 预览区域滚动处理
    const handlePreviewScroll = debounce(() => {
        if (!isEditorScrolling) {
            isPreviewScrolling = true;
            setTimeout(() => {
                isPreviewScrolling = false;
            }, 50);
        }
    }, 10);
    
    // 添加滚动事件监听
    editContent.addEventListener('scroll', handleEditorScroll);
    previewContent.addEventListener('scroll', handlePreviewScroll);
    
    // 窗口大小改变时重新计算滚动位置
    window.addEventListener('resize', debounce(() => {
        if (!isPreviewScrolling) {
            const ratio = getScrollRatio(editContent);
            setScrollRatio(previewContent, ratio);
        }
    }, 100));
}

// 显示密码验证对话框
function showPasswordDialog(shareId) {
    return new Promise((resolve) => {
        // 创建遮罩层
        const overlay = document.createElement('div');
        overlay.className = 'password-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            opacity: 0;
            transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        `;

        const dialog = document.createElement('div');
        dialog.className = 'password-dialog';
        dialog.style.cssText = `
            background: var(--container-bg);
            border-radius: 16px;
            padding: 32px;
            width: 90%;
            max-width: 420px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
            transform: translateY(20px) scale(0.95);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid rgba(255, 255, 255, 0.1);
        `;
        
        dialog.innerHTML = `
            <div class="password-dialog-content">
                <div class="dialog-header" style="text-align: center; margin-bottom: 28px;">
                    <div class="icon-wrapper" style="
                        width: 80px;
                        height: 80px;
                        margin: 0 auto 20px;
                        background: rgba(74, 144, 226, 0.1);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transform: scale(0.8);
                        opacity: 0;
                        transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.2s;
                    ">
                        <i class="fas fa-lock" style="
                            font-size: 32px;
                            color: #4A90E2;
                        "></i>
                    </div>
                    <h3 style="
                        margin: 0;
                        font-size: 24px;
                        color: var(--text-color);
                        font-weight: 600;
                        opacity: 0;
                        transform: translateY(10px);
                        transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.3s;
                    ">需要密码访问</h3>
                    <p style="
                        margin: 8px 0 0;
                        color: var(--text-secondary);
                        font-size: 14px;
                        line-height: 1.6;
                        opacity: 0;
                        transform: translateY(10px);
                        transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.4s;
                    ">此内容已被密码保护，请输入密码继续访问</p>
                </div>
                <div class="password-input-wrapper" style="
                    position: relative;
                    margin: 24px 0;
                    opacity: 0;
                    transform: translateY(10px);
                    transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.5s;
                ">
                    <input type="password" id="sharePassword" placeholder="请输入访问密码" style="
                        width: 80%;
                        padding: 16px 46px 16px 20px;
                        border: 2px solid var(--border-color);
                        border-radius: 12px;
                        font-size: 16px;
                        background: var(--input-bg);
                        color: var(--text-color);
                        transition: all 0.3s ease;
                        outline: none;
                        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
                    ">
                    <button class="toggle-password" style="
                        position: absolute;
                        right: 16px;
                        top: 35%;
                        transform: translateY(-50%);
                        border: none;
                        background: none;
                        cursor: pointer;
                        color: var(--text-secondary);
                        padding: 8px;
                        border-radius: 8px;
                        transition: all 0.2s ease;
                    ">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <div class="dialog-buttons" style="
                    display: flex;
                    gap: 12px;
                    margin-top: 32px;
                    opacity: 0;
                    transform: translateY(10px);
                    transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.6s;
                ">
                    <button class="submit-btn" style="
                        width: 100%;
                        padding: 14px;
                        border: none;
                        border-radius: 12px;
                        background: linear-gradient(135deg, #4A90E2 0%, #357ABD 100%);
                        color: white;
                        font-size: 16px;
                        font-weight: 500;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        box-shadow: 0 4px 12px rgba(74, 144, 226, 0.3);
                    ">确认</button>
                </div>
            </div>
        `;
        
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        
        // 显示动画
        requestAnimationFrame(() => {
            overlay.style.opacity = '1';
            dialog.style.transform = 'translateY(0) scale(1)';
            dialog.style.opacity = '1';
            
            // 依次显示内部元素
            const iconWrapper = dialog.querySelector('.icon-wrapper');
            const title = dialog.querySelector('h3');
            const description = dialog.querySelector('p');
            const inputWrapper = dialog.querySelector('.password-input-wrapper');
            const buttons = dialog.querySelector('.dialog-buttons');
            
            [iconWrapper, title, description, inputWrapper, buttons].forEach(el => {
                if (el) {
                    el.style.transform = 'translateY(0)';
                    el.style.opacity = '1';
                }
            });
        });
        
        const passwordInput = dialog.querySelector('#sharePassword');
        const submitBtn = dialog.querySelector('.submit-btn');
        const togglePasswordBtn = dialog.querySelector('.toggle-password');
        
        // 密码显示切换
        togglePasswordBtn.addEventListener('click', () => {
            const input = passwordInput;
            const icon = togglePasswordBtn.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fas fa-eye';
            }
            togglePasswordBtn.style.background = 'var(--hover-bg)';
            setTimeout(() => {
                togglePasswordBtn.style.background = 'none';
            }, 200);
        });

        // 输入框焦点样式
        passwordInput.addEventListener('focus', () => {
            passwordInput.style.borderColor = '#4A90E2';
            passwordInput.style.boxShadow = '0 2px 8px rgba(74, 144, 226, 0.2)';
        });
        
        passwordInput.addEventListener('blur', () => {
            passwordInput.style.borderColor = 'var(--border-color)';
            passwordInput.style.boxShadow = '0 2px 8px rgba(0, 0, 0, 0.04)';
        });

        // 按钮悬停效果
        submitBtn.addEventListener('mouseover', () => {
            submitBtn.style.transform = 'translateY(-1px)';
            submitBtn.style.boxShadow = '0 6px 16px rgba(74, 144, 226, 0.4)';
        });
        submitBtn.addEventListener('mouseout', () => {
            submitBtn.style.transform = 'translateY(0)';
            submitBtn.style.boxShadow = '0 4px 12px rgba(74, 144, 226, 0.3)';
        });

        // 关闭动画
        function closeDialog(result) {
            if (!result) {
                return; // 如果没有输入密码，不允许关闭
            }
            overlay.style.opacity = '0';
            dialog.style.transform = 'translateY(20px) scale(0.95)';
            dialog.style.opacity = '0';
            setTimeout(() => {
                overlay.remove();
                resolve(result);
            }, 300);
        }
        
        submitBtn.addEventListener('click', () => {
            const password = passwordInput.value.trim();
            if (!password) {
                passwordInput.style.borderColor = '#ff4d4f';
                passwordInput.style.boxShadow = '0 2px 8px rgba(255, 77, 79, 0.2)';
                showToast('请输入密码', 'warning');
                passwordInput.focus();
                return;
            }
            closeDialog(password);
        });
        
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                submitBtn.click();
            }
        });

        // 阻止对话框上的点击事件冒泡到遮罩层
        dialog.addEventListener('click', (e) => {
            e.stopPropagation();
        });
        
        // 自动聚焦密码输入框
        passwordInput.focus();
    });
}


