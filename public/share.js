// 显示Toast提示
function showToast(message = '内容已复制到剪贴板', duration = 2000) {
    const toast = document.getElementById('toast');
    const messageSpan = toast.querySelector('span');
    messageSpan.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
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

// 预览模式状态
let isPreviewMode = true;

// 编辑历史记录
let undoStack = [];
let redoStack = [];

// 初始化预览模式
function initPreviewMode() {
    if (isPreviewMode) {
        previewModeBtn.classList.add('active');
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

// 更新Markdown预览内容
function updateMarkdownPreview(markdown) {
    try {
        const html = marked.parse(markdown);
        previewContent.innerHTML = html;
        // 对新内容应用代码高亮
        previewContent.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightBlock(block);
        });
    } catch (error) {
        console.error('Markdown渲染错误:', error);
        previewContent.innerHTML = '<div class="error">Markdown渲染错误</div>';
    }
}

// 预览模式按钮点击事件
previewModeBtn.addEventListener('click', togglePreviewMode);

// 加载分享内容
async function loadShareContent() {
    try {
        // 从 URL 参数中获取分享 ID
        const urlParams = new URLSearchParams(window.location.search);
        const shareId = urlParams.get('id');
        
        if (!shareId) {
            showToast('无效的分享链接', 3000);
            return;
        }
        
        // 设置请求头，表明这是一个 API 请求
        const response = await fetch(`/s/${shareId}`, {
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            shareContent.value = data.data.content;
            
            // 初始化预览模式
            initPreviewMode();
            
            // 更新信息
            document.getElementById('createTime').textContent = formatDate(data.data.created);
            document.getElementById('viewCount').value = data.data.maxViews || 0;
            
            // 设置过期时间
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
        } else {
            showToast(data.message || '加载分享内容失败', 3000);
        }
    } catch (error) {
        console.error('加载分享内容出错：', error);
        showToast('加载分享内容出错', 3000);
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

// 二维码按钮点击事件
document.querySelector('.qr-btn').addEventListener('click', function() {
    const url = this.dataset.url || window.location.href;
    toggleQRCode(url);
});

// 页面加载时获取内容
loadShareContent();

// 编辑模式相关功能

// 切换到编辑模式
editBtn.addEventListener('click', () => {
    // 关闭预览模式
    isPreviewMode = false;
    previewModeBtn.classList.remove('active');
    
    editContent.value = shareContent.value;
    shareContentdiv.style.display = 'none';    
    shareContent.style.display = 'none';
    editMode.style.display = 'block';
    // 添加编辑状态样式
    editBtn.classList.add('editing');
    // 清空历史记录
    undoStack = [];
    redoStack = [];
    
    // 允许编辑可访问次数和过期时间
    const viewCountInput = document.getElementById('viewCount');
    const expireTimeInput = document.getElementById('expireTime');
    viewCountInput.removeAttribute('readonly');
    expireTimeInput.removeAttribute('readonly');
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
        const viewCount = parseInt(document.getElementById('viewCount').value) || 0;
        const expireTime = document.getElementById('expireTime').value;
        const currentContent = editContent.value;
        
        const requestData = {
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
            
            // 禁用编辑
            const viewCountInput = document.getElementById('viewCount');
            const expireTimeInput = document.getElementById('expireTime');
            viewCountInput.setAttribute('readonly', 'readonly');
            expireTimeInput.setAttribute('readonly', 'readonly');
            
            isPreviewMode = true;
            previewModeBtn.classList.add('active');
            
            showToast('保存成功');
        } else {
            showToast(data.message || '保存失败', 3000);
        }
    } catch (error) {
        console.error('保存失败:', error);
        showToast('保存失败，请稍后重试', 3000);
    }
});

// 配置marked选项
marked.setOptions({
    highlight: function(code, lang) {
        if (lang && hljs.getLanguage(lang)) {
            return hljs.highlight(code, { language: lang }).value;
        }
        return hljs.highlightAuto(code).value;
    },
    breaks: true,
    gfm: true,
    headerIds: true,
    mangle: false
});

// 实时预览
function updatePreview() {
    try {
        const markdown = editContent.value;
        const html = marked.parse(markdown);
        
        // 根据不同模式更新不同的预览区域
        if (editMode.style.display === 'block') {
            // 编辑模式下，更新编辑器内的预览区域
            const editPreview = editMode.querySelector('.preview-content');
            if (editPreview) {
                editPreview.innerHTML = html;
                // 对新内容应用代码高亮
                editPreview.querySelectorAll('pre code').forEach((block) => {
                    hljs.highlightBlock(block);
                });
            }
        } else {
            // 预览模式下，更新主预览区域
            const previewContent = document.getElementById('previewContent');
            if (previewContent) {
                previewContent.innerHTML = html;
                // 对新内容应用代码高亮
                previewContent.querySelectorAll('pre code').forEach((block) => {
                    hljs.highlightBlock(block);
                });
            }
        }
    } catch (error) {
        console.error('Markdown渲染错误:', error);
        const errorMessage = '<div class="error">Markdown渲染错误</div>';
        
        if (editMode.style.display === 'block') {
            const editPreview = editMode.querySelector('.preview-content');
            if (editPreview) {
                editPreview.innerHTML = errorMessage;
            }
        } else {
            const previewContent = document.getElementById('previewContent');
            if (previewContent) {
                previewContent.innerHTML = errorMessage;
            }
        }
    }
}

// 保存编辑历史
function saveHistory() {
    undoStack.push(editContent.value);
    redoStack = [];
    updateUndoRedoButtons();
}

// 更新撤销重做按钮状态
function updateUndoRedoButtons() {
    undoBtn.disabled = undoStack.length === 0;
    redoBtn.disabled = redoStack.length === 0;
}

// 监听编辑内容变化
editContent.addEventListener('input', () => {
    updatePreview();
    saveHistory();
});

// 工具栏功能
document.querySelectorAll('.toolbar-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const command = btn.getAttribute('title');
        const textarea = editContent;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selectedText = textarea.value.substring(start, end);
        
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
                if (confirm('确定要清空所有内容吗？')) {
                    textarea.value = '';
                    updatePreview();
                }
                return;
            case '全屏编辑':
                toggleFullscreen();
                return;
        }
        
        if (newText) {
            textarea.value = textarea.value.substring(0, start) + newText + textarea.value.substring(end);
            updatePreview();
            saveHistory();
            textarea.focus();
            textarea.selectionStart = start;
            textarea.selectionEnd = start + newText.length;
        }
    });
});

// 撤销功能
undoBtn.addEventListener('click', () => {
    if (undoStack.length > 0) {
        redoStack.push(editContent.value);
        editContent.value = undoStack.pop();
        updatePreview();
        updateUndoRedoButtons();
    }
});

// 重做功能
redoBtn.addEventListener('click', () => {
    if (redoStack.length > 0) {
        undoStack.push(editContent.value);
        editContent.value = redoStack.pop();
        updatePreview();
        updateUndoRedoButtons();
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


