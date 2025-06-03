// 全局变量
let selectedFiles = []; // 存储选中的文件

// 添加全局变量来跟踪上传状态
let currentTextUpload = null;
let currentFileUpload = null;

// 初始化所有功能
document.addEventListener('DOMContentLoaded', () => {
    
    // 优先获取统计数据
    fetchShareStats().then(() => {
    }).catch(error => {
        console.error('获取统计数据失败:', error);
    });
    
    // 初始化主题切换
    initThemeToggle();
    
    // 检查当前页面
    const isMainPage = window.location.pathname === '/' || window.location.pathname === '/index.html';
    
    if (isMainPage) {
        // 只在主页面初始化这些功能
        initTabSwitching();
        initFileUpload();
        initAdminPanel();
        initEditor();
        initShareFilters();
        initTextSubmit();
        initUploadToggles();
        initFileSubmit();
        initPasswordToggle();
        initPasswordProtection();
    }
});

// 初始化文本提交功能
function initTextSubmit() {
    const submitTextBtn = document.getElementById('submitText');
    const shareResult = document.getElementById('shareResult');
    const shareLink = document.getElementById('shareLink');
    const copyBtn = document.getElementById('copyShareLink');
    const expiresAtSpan = shareResult.querySelector('.expires-at');
    const maxViewsSpan = shareResult.querySelector('.max-views');

    if (submitTextBtn) {
        submitTextBtn.addEventListener('click', async () => {
            try {
                const textContent = document.getElementById('textContent').value;
                const password = document.getElementById('textPassword').value;
                const duration = document.getElementById('textDuration').value;
                const customUrl = document.getElementById('textCustomUrl').value;
                const filename = customUrl.trim() || 'CloudPaste-Text';
                const maxViews = parseInt(document.getElementById('textMaxViews').value) || 0;

                if (!textContent) {
                    alert('请输入要分享的文本内容');
                    return;
                }

                // 禁用提交按钮
                submitTextBtn.disabled = true;
                submitTextBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 创建中...';

                const response = await fetch('/api/text', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        content: textContent,
                        password: password || undefined,
                        duration,
                        maxViews,
                        filename: filename,
                        isUserUpload: true
                    })
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    const errorData = JSON.parse(errorText);
                    throw new Error(errorData.message || '创建分享失败');
                }

                const result = await response.json();
                
                if (result.success) {
                    // 显示分享结果
                    shareResult.style.display = 'block';
                    shareResult.classList.remove('error');
                    shareResult.classList.add('success');
                    shareLink.value = `${window.location.origin}${result.data.url}`;
                    
                    // 更新字符数显示
                    const charCount = document.getElementById('textContent').value.length;
                    const charCountSpan = shareResult.querySelector('.info-item:nth-child(2)');
                    if (charCountSpan) {
                        charCountSpan.innerHTML = `<i class="fas fa-text-width"></i>${charCount} 字符`;
                    }

                    // 更新过期时间和最大访问次数
                    if (result.data.expiresAt) {
                        const expiresAtSpan = shareResult.querySelector('.expires-at');
                        if (expiresAtSpan) {
                            expiresAtSpan.textContent = new Date(result.data.expiresAt).toLocaleString();
                            expiresAtSpan.style.display = 'inline';
                            expiresAtSpan.style.fontWeight = 'normal';  // 恢复正常字重
                        }
                    } else {
                        const expiresAtSpan = shareResult.querySelector('.expires-at');
                        if (expiresAtSpan) {
                            expiresAtSpan.style.display = 'none';
                        }
                    }
                    
                    if (result.data.maxViews > 0) {
                        const maxViewsSpan = shareResult.querySelector('.max-views');
                        if (maxViewsSpan) {
                            maxViewsSpan.textContent = result.data.maxViews;
                            maxViewsSpan.style.display = 'inline';
                        }
                    } else {
                        const maxViewsSpan = shareResult.querySelector('.max-views');
                        if (maxViewsSpan) {
                            maxViewsSpan.style.display = 'none';
                        }
                    }

                    // 清空表单
                    document.getElementById('textContent').value = '';
                    document.getElementById('textPassword').value = '';
                    document.getElementById('textDuration').value = '1h';
                    document.getElementById('textMaxViews').value = '0';
                    document.getElementById('textCustomUrl').value = '';
                    document.getElementById('charCount').textContent = '0 字符';

                    // 添加到存储列表并更新统计
                    await Promise.all([
                        displayStorageList(null, {
                            type: 'text',
                            id: result.data.id,
                            expiresAt: result.data.expiresAt,
                            content: textContent,
                            isUserUpload: true,
                            filename: filename
                        }),
                        fetchShareStats(),
                        fetchStorageList()
                    ]);
                } else {
                    shareResult.style.display = 'block';
                    shareResult.classList.add('error');
                    shareLink.value = '创建分享失败：' + result.message;
                }
            } catch (error) {
                console.error('创建分享时出错：', error);
                shareResult.style.display = 'block';
                shareResult.classList.add('error');
                
                // 显示错误弹框
                alert(error.message);
                shareLink.value = '创建分享失败';
            } finally {
                // 恢复提交按钮
                submitTextBtn.disabled = false;
                submitTextBtn.innerHTML = '<i class="fas fa-share"></i> 创建文本分享';
            }
        });
    } else {
        console.error('未找到提交按钮');
    }

    // 复制按钮功能
    if (copyBtn) {
        copyBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(shareLink.value);
                const originalTitle = copyBtn.getAttribute('title');
                copyBtn.setAttribute('title', '已复制！');
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    copyBtn.setAttribute('title', originalTitle);
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            } catch (err) {
                console.error('复制失败:', err);
                alert('复制失败，请手动复制');
            }
        });
    }

    // 二维码按钮功能
    const qrBtn = document.getElementById('showQRCode');
    const qrCodeContainer = document.getElementById('qrCodeContainer');
    const closeQRCodeBtn = document.getElementById('closeQRCode');
    const downloadQRCodeBtn = document.getElementById('downloadQRCode');

    function hideQRCode() {
        qrCodeContainer.style.display = 'none';
        qrBtn.innerHTML = '<i class="fas fa-qrcode"></i>';
        qrBtn.setAttribute('title', '显示二维码');
    }

    if (qrBtn) {
        qrBtn.addEventListener('click', () => {
            const qrCodeDiv = document.getElementById('qrCode');
            const qrCodeContainer = document.getElementById('qrCodeContainer');
            const isVisible = qrCodeContainer.style.display === 'flex';
            const modal = qrCodeContainer.querySelector('.qr-code-modal');
            
            if (isVisible) {
                // 添加关闭动画
                modal.style.transform = 'translateY(-20px)';
                modal.style.opacity = '0';
                setTimeout(() => {
                    qrCodeContainer.style.display = 'none';
                }, 300);
                qrBtn.innerHTML = '<i class="fas fa-qrcode"></i>';
                qrBtn.setAttribute('title', '显示二维码');
            } else {
                // 清空之前的二维码
                qrCodeDiv.innerHTML = '';
                
                // 设置初始样式
                qrCodeContainer.style.cssText = 'display: flex; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); justify-content: center; align-items: center; z-index: 1000;';
                modal.style.cssText = 'background: var(--background-color); padding: 24px; border-radius: 8px; text-align: center; max-width: 90%; width: 320px; position: relative; transform: translateY(-20px); opacity: 0; transition: all 0.3s ease; border: 1px solid var(--border-color);';
                
                // 生成新的二维码
                const shareUrl = shareLink.value;
                QRCode.toDataURL(shareUrl, {
                    width: 250,
                    height: 250,
                    margin: 2,
                    color: {
                        dark: '#000000',
                        light: '#ffffff'
                    }
                }, (err, url) => {
                    if (err) {
                        console.error('生成二维码失败:', err);
                        alert('生成二维码失败');
                        return;
                    }
                    // 创建图片元素显示二维码
                    const img = document.createElement('img');
                    img.src = url;
                    img.alt = '分享链接二维码';
                    img.style.maxWidth = '100%';
                    qrCodeDiv.appendChild(img);

                    // 保存数据URL用于下载
                    downloadQRCodeBtn.setAttribute('data-qr-url', url);
                });

                // 添加显示动画
                setTimeout(() => {
                    modal.style.transform = 'translateY(0)';
                    modal.style.opacity = '1';
                }, 10);
                
                qrBtn.innerHTML = '<i class="fas fa-times"></i>';
                qrBtn.setAttribute('title', '关闭二维码');
            }
        });
    }

    // 关闭二维码
    if (closeQRCodeBtn) {
        closeQRCodeBtn.addEventListener('click', () => {
            const qrCodeContainer = document.getElementById('qrCodeContainer');
            const modal = qrCodeContainer.querySelector('.qr-code-modal');
            
            // 添加关闭动画
            modal.style.transform = 'translateY(-20px)';
            modal.style.opacity = '0';
            setTimeout(() => {
                qrCodeContainer.style.display = 'none';
            }, 300);
            qrBtn.innerHTML = '<i class="fas fa-qrcode"></i>';
            qrBtn.setAttribute('title', '显示二维码');
        });
    }

    // 点击遮罩层关闭
    qrCodeContainer.addEventListener('click', (e) => {
        if (e.target === qrCodeContainer) {
            const modal = qrCodeContainer.querySelector('.qr-code-modal');
            
            // 添加关闭动画
            modal.style.transform = 'translateY(-20px)';
            modal.style.opacity = '0';
            setTimeout(() => {
                qrCodeContainer.style.display = 'none';
            }, 300);
            qrBtn.innerHTML = '<i class="fas fa-qrcode"></i>';
            qrBtn.setAttribute('title', '显示二维码');
        }
    });

    // 下载二维码
    if (downloadQRCodeBtn) {
        downloadQRCodeBtn.addEventListener('click', () => {
            const url = downloadQRCodeBtn.getAttribute('data-qr-url');
            if (url) {
                const link = document.createElement('a');
                link.download = '分享链接二维码.png';
                link.href = url;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        });
    }
}

// 初始化上传开关
function initUploadToggles() {
    const textUploadBtn = document.getElementById('textUploadBtn');
    const fileUploadBtn = document.getElementById('fileUploadBtn');
    
    // 从服务器获取初始状态
    fetch('/api/admin/settings')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const { textUploadEnabled, fileUploadEnabled } = data.settings;
                
                // 设置按钮状态
                textUploadBtn.checked = textUploadEnabled;
                fileUploadBtn.checked = fileUploadEnabled;
                
                // 更新UI状态
                updateUploadUI('text', textUploadEnabled);
                updateUploadUI('file', fileUploadEnabled);
            }
        })
        .catch(error => {
            console.error('获取上传设置失败:', error);
            showToast('获取设置失败', 'error');
        });

    // 添加点击事件
    textUploadBtn.addEventListener('change', async () => {
        const isEnabled = textUploadBtn.checked;
        try {
            // 检查是否有正在进行的上传
            if (!isEnabled && currentTextUpload) {
                if (!confirm('当前有正在进行的文本上传，关闭开关将中断上传。是否继续？')) {
                    textUploadBtn.checked = true;
                    return;
                }
                // 中断当前上传
                if (currentTextUpload.abort) {
                    currentTextUpload.abort();
                }
                currentTextUpload = null;
            }

            // 立即更新UI状态
            updateUploadUI('text', isEnabled);
            
            const response = await fetch('/api/admin/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Id': localStorage.getItem('sessionId')
                },
                body: JSON.stringify({
                    textUploadEnabled: isEnabled,
                    fileUploadEnabled: fileUploadBtn.checked
                })
            });
            
            const result = await response.json();
            if (result.success) {
                showToast(isEnabled ? '已开启文本上传' : '已关闭文本上传');
            } else {
                // 如果保存失败，恢复按钮状态和UI
                textUploadBtn.checked = !isEnabled;
                updateUploadUI('text', !isEnabled);
                showToast('保存设置失败', 'error');
            }
        } catch (error) {
            console.error('保存设置失败:', error);
            // 恢复按钮状态和UI
            textUploadBtn.checked = !isEnabled;
            updateUploadUI('text', !isEnabled);
            showToast('保存设置失败', 'error');
        }
    });

    fileUploadBtn.addEventListener('change', async () => {
        const isEnabled = fileUploadBtn.checked;
        try {
            // 检查是否有正在进行的上传
            if (!isEnabled && currentFileUpload) {
                if (!confirm('当前有正在进行的文件上传，关闭开关将中断上传。是否继续？')) {
                    fileUploadBtn.checked = true;
                    return;
                }
                // 中断当前上传
                if (currentFileUpload.abort) {
                    currentFileUpload.abort();
                }
                currentFileUpload = null;
            }

            // 立即更新UI状态
            updateUploadUI('file', isEnabled);
            
            const response = await fetch('/api/admin/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Id': localStorage.getItem('sessionId')
                },
                body: JSON.stringify({
                    textUploadEnabled: textUploadBtn.checked,
                    fileUploadEnabled: isEnabled
                })
            });
            
            const result = await response.json();
            if (result.success) {
                showToast(isEnabled ? '已开启文件上传' : '已关闭文件上传');
            } else {
                // 如果保存失败，恢复按钮状态和UI
                fileUploadBtn.checked = !isEnabled;
                updateUploadUI('file', !isEnabled);
                showToast('保存设置失败', 'error');
            }
        } catch (error) {
            console.error('保存设置失败:', error);
            // 恢复按钮状态和UI
            fileUploadBtn.checked = !isEnabled;
            updateUploadUI('file', !isEnabled);
            showToast('保存设置失败', 'error');
        }
    });
}

// 更新上传UI状态
function updateUploadUI(type, enabled) {
    const textUpload = document.getElementById('textUpload');
    const fileUpload = document.getElementById('fileUpload');
    const textTab = document.querySelector('[data-tab="text"]');
    const fileTab = document.querySelector('[data-tab="file"]');
    const submitText = document.getElementById('submitText');
    const submitFile = document.getElementById('submitFile');

    if (type === 'text') {
        if (textUpload) {
            textUpload.style.opacity = enabled ? '1' : '0.5';
            textUpload.style.pointerEvents = enabled ? 'auto' : 'none';
        }
        if (textTab) {
            textTab.style.opacity = enabled ? '1' : '0.5';
            textTab.style.pointerEvents = enabled ? 'auto' : 'none';
        }
        if (submitText) {
            submitText.disabled = !enabled;
            submitText.title = enabled ? '' : '文本上传功能已关闭';
        }
    } else if (type === 'file') {
        if (fileUpload) {
            fileUpload.style.opacity = enabled ? '1' : '0.5';
            fileUpload.style.pointerEvents = enabled ? 'auto' : 'none';
        }
        if (fileTab) {
            fileTab.style.opacity = enabled ? '1' : '0.5';
            fileTab.style.pointerEvents = enabled ? 'auto' : 'none';
        }
        if (submitFile) {
            submitFile.disabled = !enabled;
            submitFile.title = enabled ? '' : '文件上传功能已关闭';
        }
    }
}

// 主题切换功能
function initThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    const root = document.documentElement;
    const themes = ['light', 'dark', 'auto'];
    
    // 从localStorage读取保存的主题设置，如果没有则默认使用'auto'
    const savedTheme = localStorage.getItem('theme') || 'auto';
    let currentThemeIndex = themes.indexOf(savedTheme);
    
    // 应用主题设置
    root.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);

    function updateThemeIcon(theme) {
        const icons = {
            'light': 'fa-sun',
            'dark': 'fa-moon',
            'auto': 'fa-clock'
        };
        
        const icon = themeToggle.querySelector('i');
        icon.className = `fas ${icons[theme]}`;
    }

    themeToggle.addEventListener('click', () => {
        currentThemeIndex = (currentThemeIndex + 1) % themes.length;
        const newTheme = themes[currentThemeIndex];
        
        // 应用新主题
        root.setAttribute('data-theme', newTheme);
        updateThemeIcon(newTheme);
        
        // 保存用户选择
        localStorage.setItem('theme', newTheme);
    });
}

// 标签页切换功能
function initTabSwitching() {
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');
    const tabsContainer = document.querySelector('.tabs');

    function activateTab(tab) {
        const target = tab.getAttribute('data-tab');
        
        // 移除所有活动状态
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(content => {
            content.style.display = 'none';
            content.classList.remove('active');
        });
        
        // 添加新的活动状态
        tab.classList.add('active');
        const targetContent = document.getElementById(target + 'Upload');
        if (targetContent) {
            targetContent.style.display = 'block';
            targetContent.classList.add('active');
            
            // 如果是文件上传标签，确保上传区域可见
            if (target === 'file') {
                const uploadArea = document.getElementById('uploadArea');
                const fileList = document.getElementById('fileList');
                if (uploadArea) {
                    uploadArea.style.display = 'flex';
                    if (fileList) {
                        fileList.style.display = selectedFiles.length > 0 ? 'block' : 'none';
                    }
                }
            }
        }
        
        // 更新滑块位置
        tabsContainer.setAttribute('data-active-tab', target);
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            activateTab(tab);
        });
    });

    // 初始化时激活第一个标签
    const firstTab = tabs[0];
    if (firstTab) {
        activateTab(firstTab);
    }
}

// 文件上传相关功能
function initFileUpload() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');

    if (!uploadArea || !fileInput || !fileList) {
        console.error('文件上传所需的DOM元素未找到');
        return;
    }


    // 确保上传区域可见
    uploadArea.style.display = 'flex';
    fileList.style.display = 'none';

    // 修改文件输入框为支持多文件
    fileInput.setAttribute('multiple', 'true');

    // 处理文件选择
    fileInput.addEventListener('change', (event) => {
        const files = event.target.files;
        addFilesToList(Array.from(files));
    });

    // 处理拖放
    uploadArea.addEventListener('dragover', (event) => {
        event.preventDefault();
        uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', (event) => {
        event.preventDefault();
        uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (event) => {
        event.preventDefault();
        uploadArea.classList.remove('drag-over');
        const files = event.dataTransfer.files;
        addFilesToList(Array.from(files));
    });

    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });

    function addFilesToList(files) {
        files.forEach(file => {
            // 检查是否已经存在同名文件
            if (!selectedFiles.some(f => f.name === file.name)) {
                selectedFiles.push(file);
                const filePreview = createFilePreview(file);
                fileList.appendChild(filePreview);
            } else {
                console.log('文件已存在:', file.name)
            }
        });
        updateUploadAreaVisibility();
    }
}

// 管理面板功能
function initAdminPanel() {
    const adminBtn = document.querySelector('.header-btn.admin');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const closeSidebarBtn = document.getElementById('closeSidebar');
    const logoutBtn = document.getElementById('logoutBtn');
    const textUploadBtn = document.getElementById('textUploadBtn');
    const fileUploadBtn = document.getElementById('fileUploadBtn');

    // 初始化开关状态
    async function initSwitchStates() {
        try {
            const response = await fetch('/api/admin/settings');
            const data = await response.json();
            if (data.success) {
                textUploadBtn.checked = data.settings.textUploadEnabled;
                fileUploadBtn.checked = data.settings.fileUploadEnabled;
            }
        } catch (error) {
            console.error('获取设置失败:', error);
            showToast('获取设置失败', 'error');
        }
    }

    // 更新开关状态
    async function updateSwitchState(type, enabled) {
        try {
            const response = await fetch('/api/admin/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Id': localStorage.getItem('sessionId')
                },
                body: JSON.stringify({
                    type,
                    enabled
                })
            });
            
            const data = await response.json();
            if (data.success) {
                showToast(`${type === 'text' ? '文本' : '文件'}上传功能已${enabled ? '开启' : '关闭'}`, 'success');
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            console.error('更新设置失败:', error);
            showToast('更新设置失败', 'error');
            // 恢复开关状态
            if (type === 'text') {
                textUploadBtn.checked = !enabled;
            } else {
                fileUploadBtn.checked = !enabled;
            }
        }
    }

    // 监听开关变化
    textUploadBtn.addEventListener('change', () => {
        updateSwitchState('text', textUploadBtn.checked);
    });

    fileUploadBtn.addEventListener('change', () => {
        updateSwitchState('file', fileUploadBtn.checked);
    });

    async function openSidebar() {
        // 先显示登录对话框
        const isLoggedIn = await showLoginDialog();
        if (!isLoggedIn) return;

        // 登录成功后显示侧边栏
        sidebar.classList.add('active');
        sidebarOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';
        
        // 开关状态
        initSwitchStates();
    }

    function closeSidebar() {
        sidebar.classList.remove('active');
        sidebarOverlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    adminBtn.addEventListener('click', (e) => {
        e.preventDefault();
        openSidebar();
    });

    closeSidebarBtn.addEventListener('click', closeSidebar);
    sidebarOverlay.addEventListener('click', closeSidebar);

    // 添加退出登录功能
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            const sessionId = localStorage.getItem('sessionId');
            if (sessionId) {
                try {
                    await fetch('/api/admin/logout', {
                        method: 'POST',
                        headers: {
                            'X-Session-Id': sessionId
                        }
                    });
                    localStorage.removeItem('sessionId');
                    closeSidebar();
                    showToast('已退出登录', 'success');
                } catch (error) {
                    console.error('退出登录失败:', error);
                    showToast('退出登录失败', 'error');
                }
            }
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && sidebar.classList.contains('active')) {
            closeSidebar();
        }
    });
}

// 在提交文本和文件之前验证功能是否开启
async function checkUploadEnabled(type) {
    try {
        const response = await fetch('/api/admin/settings');
        const data = await response.json();
        if (data.success) {
            const enabled = type === 'text' ? data.settings.textUploadEnabled : data.settings.fileUploadEnabled;
            if (!enabled) {
                showToast(`${type === 'text' ? '文本' : '文件'}上传功能已关闭`, 'error');
                return false;
            }
            return true;
        }
        return false;
    } catch (error) {
        console.error('验证上传权限失败:', error);
        showToast('验证上传权限失败', 'error');
        return false;
    }
}

// 修改文本提交处理函数
async function submitTextHandler() {
    // 检查是否已禁用
    const textUploadBtn = document.getElementById('textUploadBtn');
    if (!textUploadBtn.checked) {
        showToast('文本上传功能已关闭', 'error');
        return;
    }

    if (!await checkUploadEnabled('text')) {
        return;
    }

    try {
        // 设置当前上传状态
        currentTextUpload = { abort: null };
        // ... 原有的上传代码 ...
    } catch (error) {
        console.error('上传失败:', error);
        showToast('上传失败: ' + error.message, 'error');
    } finally {
        // 清除当前上传状态
        currentTextUpload = null;
    }
}

// 修改文件提交处理函数
async function submitFileHandler() {
    // 检查是否已禁用
    const fileUploadBtn = document.getElementById('fileUploadBtn');
    if (!fileUploadBtn.checked) {
        showToast('文件上传功能已关闭', 'error');
        return;
    }

    if (!await checkUploadEnabled('file')) {
        return;
    }

    try {
        // 设置当前上传状态
        currentFileUpload = { abort: null };
        // ... 原有的上传代码 ...

        // 在XMLHttpRequest创建后设置abort函数
        const xhr = new XMLHttpRequest();
        currentFileUpload.abort = () => {
            xhr.abort();
            showToast('文件上传已取消', 'warning');
        };
        // ... 原有的XHR配置代码 ...
    } catch (error) {
        console.error('上传失败:', error);
        showToast('上传失败: ' + error.message, 'error');
    } finally {
        // 清除当前上传状态
        currentFileUpload = null;
    }
}

// 编辑器功能初始化
function initEditor() {
    const editor = document.querySelector('.editor-wrapper');
    const toolbar = document.querySelector('.editor-toolbar');
    const toolbarButtons = document.querySelector('.toolbar-buttons');
    const toggleToolbarBtn = document.getElementById('toggleToolbar');
    const fullscreenBtn = document.querySelector('.fullscreen-btn');
    const textContent = document.getElementById('textContent');
    const splitEditor = document.querySelector('.split-editor textarea');
    const splitPreview = document.querySelector('.split-preview .preview-content');
    const charCount = document.getElementById('charCount');
    
    // 添加撤销/重做支持
    [textContent, splitEditor].forEach(textarea => {
        if (textarea) {
            // 确保文本区域可以撤销/重做
            textarea.setAttribute('data-enable-grammarly', 'false');
            
            // 监听按键事件以支持常用的撤销/重做快捷键
            textarea.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
                    if (e.shiftKey) {
                        // Ctrl+Shift+Z 或 Command+Shift+Z 重做
                        e.preventDefault();
                        document.execCommand('redo');
                        updatePreview();
                    } else {
                        // Ctrl+Z 或 Command+Z 撤销
                        e.preventDefault();
                        document.execCommand('undo');
                        updatePreview();
                    }
                } else if ((e.ctrlKey || e.metaKey) && e.key === 'y') {
                    // Ctrl+Y 或 Command+Y 重做
                    e.preventDefault();
                    document.execCommand('redo');
                    updatePreview();
                }
            });
        }
    });

    // 恢复草稿
    const savedDraft = localStorage.getItem('cloudpaste_draft');
    if (savedDraft) {
        textContent.value = savedDraft;
        splitEditor.value = savedDraft;
        updatePreview();
        const count = savedDraft.length;
        charCount.textContent = `${count} 字符`;
    }

    // 自动保存计时器
    let autoSaveTimer;
    
    // 自动保存函数
    function autosave() {
        const content = textContent.value;
        localStorage.setItem('cloudpaste_draft', content);
    }

    // 监听输入事件，延迟保存
    textContent.addEventListener('input', () => {
        clearTimeout(autoSaveTimer);
        autoSaveTimer = setTimeout(autosave, 1000); // 1秒后保存
        syncEditors(textContent, splitEditor);
    });

    // 页面关闭前保存
    window.addEventListener('beforeunload', () => {
        autosave();
    });

    // 成功分享后清除草稿
    document.getElementById('submitText').addEventListener('click', async () => {
        // 等待分享完成
        try {
            await submitTextHandler();
            localStorage.removeItem('cloudpaste_draft');
        } catch (error) {
            console.error('分享失败:', error);
        }
    });
    
    // 同步滚动功能
    let isLeftScrolling = false;
    let isRightScrolling = false;
    
    // 计算滚动比例
    function getScrollRatio(element) {
        const scrollTop = element.scrollTop;
        const scrollHeight = element.scrollHeight - element.clientHeight;
        return scrollHeight > 0 ? scrollTop / scrollHeight : 0;
    }
    
    // 设置滚动位置
    function setScrollRatio(element, ratio) {
        const scrollHeight = element.scrollHeight - element.clientHeight;
        element.scrollTop = scrollHeight * ratio;
    }
    
    // 左侧编辑器滚动事件
    splitEditor.addEventListener('scroll', () => {
        if (!isRightScrolling && document.querySelector('.split-view.active')) {
            isLeftScrolling = true;
            const ratio = getScrollRatio(splitEditor);
            setScrollRatio(splitPreview, ratio);
            setTimeout(() => {
                isLeftScrolling = false;
            }, 50);
        }
    });
    
    // 右侧预览滚动事件
    splitPreview.addEventListener('scroll', () => {
        if (!isLeftScrolling) {
            isRightScrolling = true;
            setTimeout(() => {
                isRightScrolling = false;
            }, 50);
        }
    });
    
    // 同步主编辑器和分屏编辑器的内容
    function syncEditors(source, target) {
        target.value = source.value;
        updatePreview();
        const count = source.value.length;
        charCount.textContent = `${count} 字符`;
    }

    // 监听主编辑器的输入
    textContent.addEventListener('input', () => {
        syncEditors(textContent, splitEditor);
    });

    // 监听分屏编辑器的输入
    splitEditor.addEventListener('input', () => {
        syncEditors(splitEditor, textContent);
    });

    // 工具栏按钮点击处理
    toolbar.addEventListener('click', (e) => {
        const button = e.target.closest('.toolbar-btn');
        if (!button) return;
        
        const action = button.getAttribute('data-action');
        if (!action) return;
        
        e.preventDefault();
        // 根据当前活动的编辑器选择目标
        const activeEditor = document.querySelector('.split-view.active') ? splitEditor : textContent;
        handleToolbarAction(action, activeEditor);
    });

    // 字符计数
    textContent.addEventListener('input', () => {
        const count = textContent.value.length;
        charCount.textContent = `${count} 字符`;
    });

    // 工具栏折叠/展开
    toggleToolbarBtn.addEventListener('click', () => {
        toolbarButtons.classList.toggle('collapsed');
        toggleToolbarBtn.classList.toggle('collapsed');
    });

    // 全屏切换
    fullscreenBtn.addEventListener('click', () => {
        editor.classList.toggle('fullscreen');
        const icon = fullscreenBtn.querySelector('i');
        icon.classList.toggle('fa-expand');
        icon.classList.toggle('fa-compress');
    });

    // 编辑器标签切换
    const editorTabs = document.querySelectorAll('.editor-tab');
    const contentView = document.querySelector('.content-view');
    const previewView = document.querySelector('.preview-view');
    const splitView = document.querySelector('.split-view');

    editorTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.getAttribute('data-editor-tab');
            
            // 移除所有活动状态
            editorTabs.forEach(t => t.classList.remove('active'));
            contentView.classList.remove('active');
            previewView.classList.remove('active');
            splitView.classList.remove('active');
            
            // 添加新的活动状态
            tab.classList.add('active');

            // 显示对应视图
            switch(target) {
                case 'content':
                    contentView.classList.add('active');
                    break;
                case 'preview':
                    previewView.classList.add('active');
                    updatePreview();
                    break;
                case 'split':
                    splitView.classList.add('active');
                    // 同步内容到分屏编辑器
                    splitEditor.value = textContent.value;
                    updatePreview();
                    break;
            }
        });
    });

    // 初始化时同步内容
    splitEditor.value = textContent.value;
}

// 处理工具栏按钮动作
function handleToolbarAction(action, textarea) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;
    const selection = text.substring(start, end);
    
    let replacement = '';
    let cursorOffset = 0;
    
    switch(action) {
        case 'bold':
            replacement = `**${selection || '粗体文本'}**`;
            cursorOffset = selection ? 0 : -2;
            break;
        case 'italic':
            replacement = `*${selection || '斜体文本'}*`;
            cursorOffset = selection ? 0 : -1;
            break;
        case 'strikethrough':
            replacement = `~~${selection || '删除线文本'}~~`;
            cursorOffset = selection ? 0 : -2;
            break;
        case 'heading':
            replacement = `\n### ${selection || '标题'}\n`;
            cursorOffset = selection ? 0 : -1;
            break;
        case 'list-ul':
            replacement = selection ? selection.split('\n').map(line => `- ${line}`).join('\n') : '- 列表项';
            break;
        case 'list-ol':
            replacement = selection ? selection.split('\n').map((line, i) => `${i + 1}. ${line}`).join('\n') : '1. 列表项';
            break;
        case 'quote':
            replacement = selection ? selection.split('\n').map(line => `> ${line}`).join('\n') : '> 引用文本';
            break;
        case 'link':
            replacement = `[${selection || '链接文本'}](url)`;
            cursorOffset = selection ? -1 : -4;
            break;
        case 'image':
            replacement = `![${selection || '图片描述'}](url)`;
            cursorOffset = selection ? -1 : -4;
                break;
        case 'code':
            replacement = selection.includes('\n') ? 
                         `\n\`\`\`\n${selection || '代码块'}\n\`\`\`\n` :
                         `\`${selection || '代码'}\``;
            cursorOffset = selection ? 0 : -1;
                break;
        case 'table':
            replacement = '\n| 列1 | 列2 | 列3 |\n| --- | --- | --- |\n| 内容 | 内容 | 内容 |\n';
                break;
        case 'clear':
            textarea.focus();
            // 保存当前内容到撤销栈
            const oldContent = textarea.value;
            // 使用 execCommand 执行删除操作以支持撤销
            textarea.select();
            document.execCommand('delete', false);
            updatePreview();
            return;
        case 'math':
            if (selection) {
                replacement = `\n\`\`\`math\n${selection}\n\`\`\`\n`;
                cursorOffset = 0;
            } else {
                replacement = `\n\`\`\`math\nE = mc^2\n\`\`\`\n`;
                cursorOffset = -4;
            }
            break;
        case 'inline-math':
            replacement = `$${selection || 'E = mc^2'}$`;
            cursorOffset = selection ? 0 : -1;
            break;
        case 'undo':
            document.execCommand('undo');
            updatePreview();
            return;
        case 'redo':
            document.execCommand('redo');
            updatePreview();
            return;
    }
    
    // 插入文本
    textarea.focus();
    document.execCommand('insertText', false, replacement);
    
    // 更新光标位置
    if (cursorOffset) {
        const newPosition = end + replacement.length + cursorOffset;
        textarea.setSelectionRange(newPosition, newPosition);
    }
    
    // 更新预览
    updatePreview();
}

// 更新预览内容
function updatePreview() {
    const textContent = document.getElementById('textContent');
    const previewContents = document.querySelectorAll('.preview-content');
    
    // 配置marked以支持KaTeX
    const renderer = new marked.Renderer();
    const originalCode = renderer.code.bind(renderer);
    
    renderer.code = (code, language) => {
        if (language === 'math' || language === 'tex') {
            try {
                const tex = code.replace(/\n/g, ' ').trim();
                return katex.renderToString(tex, {
                    displayMode: true,
                    throwOnError: false
                });
            } catch (error) {
                console.error('KaTeX渲染错误:', error);
                return `<pre><code class="error">KaTeX渲染错误: ${error.message}</code></pre>`;
            }
        }
        return originalCode(code, language);
    };

    // 配置marked选项
    marked.setOptions({
        renderer: renderer,
        breaks: true,
        gfm: true
    });

    // 渲染Markdown内容
    const html = marked.parse(textContent.value);
    
    previewContents.forEach(preview => {
        preview.innerHTML = html;
        
        // 渲染行内数学公式
        renderMathInElement(preview, {
            delimiters: [
                {left: '$$', right: '$$', display: true},
                {left: '$', right: '$', display: false},
                {left: '\\(', right: '\\)', display: false},
                {left: '\\[', right: '\\]', display: true}
            ],
            throwOnError: false
        });
    });
}

// 分享列表筛选功能
function initShareFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const shareItems = document.getElementById('shareItems');
    let currentFilter = 'all';

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // 更新按钮状态
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // 获取筛选类型
            currentFilter = btn.getAttribute('data-type');
            
            // 筛选分享项
            const items = shareItems.querySelectorAll('.share-item');
            items.forEach(item => {
                const itemType = item.getAttribute('data-type');
                if (currentFilter === 'all' || itemType === currentFilter) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
}

// 在创建分享项时添加类型标记
function createShareItem(share) {
    const isFile = share.type === 'file';
    const icon = isFile ? getFileIconByName(share.originalname || share.filename || share.id) : 'fa-file-alt';
    const expirationTime = share.expiration ? new Date(share.expiration).toLocaleString() : '永不过期';
    const createdTime = share.createdAt ? new Date(share.createdAt).toLocaleString() : '未知时间';
    const displayId = share.id || '';

    return `
        <div class="share-item" data-id="${share.id}" data-type="${share.type}">
            <div class="share-item-info">
                <div class="share-item-line">ID: <span class="share-id" title="点击查看分享" onclick="window.location.href='/s/${share.id}'">${displayId}</span></div>
                <div class="share-item-line">文件名: ${isFile ? (share.originalname || share.filename) : (share.filename || 'CloudPaste-Text')}</div>
                <div class="share-item-line">创建时间: ${createdTime}</div>
                <div class="share-item-line">过期时间: ${expirationTime}</div>
            </div>
            <div class="share-item-actions">
                <button class="share-item-btn copy" title="复制链接">
                    <i class="fas fa-link"></i>
                </button>
                <button class="share-item-btn delete" title="删除" onclick="deleteStorageItem('${share.id}', '${share.type}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `;
}

function getFileIconByName(fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    const iconMap = {
        pdf: 'fa-file-pdf',
        doc: 'fa-file-word',
        docx: 'fa-file-word',
        xls: 'fa-file-excel',
        xlsx: 'fa-file-excel',
        ppt: 'fa-file-powerpoint',
        pptx: 'fa-file-powerpoint',
        jpg: 'fa-file-image',
        jpeg: 'fa-file-image',
        png: 'fa-file-image',
        gif: 'fa-file-image',
        zip: 'fa-file-archive',
        rar: 'fa-file-archive',
        '7z': 'fa-file-archive',
        txt: 'fa-file-alt',
        mp3: 'fa-file-audio',
        wav: 'fa-file-audio',
        mp4: 'fa-file-video',
        avi: 'fa-file-video'
    };
    return iconMap[ext] || 'fa-file';
}

function createFilePreview(file) {
    const preview = document.createElement('div');
    preview.className = 'file-preview';
    
    const fileIcon = document.createElement('i');
    fileIcon.className = `fas ${getFileIcon(file.type)}`;
    
    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';
    
    const fileName = document.createElement('div');
    fileName.className = 'file-name';
    fileName.textContent = file.name;
    
    const fileSize = document.createElement('div');
    fileSize.className = 'file-size';
    fileSize.textContent = formatFileSize(file.size);
    
    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove-file';
    removeBtn.innerHTML = '<i class="fas fa-times"></i>';
    removeBtn.onclick = () => {
        preview.remove();
        selectedFiles = selectedFiles.filter(f => f !== file);
        updateUploadAreaVisibility();
    };
    
    fileInfo.appendChild(fileName);
    fileInfo.appendChild(fileSize);
    preview.appendChild(fileIcon);
    preview.appendChild(fileInfo);
    preview.appendChild(removeBtn);
    
    return preview;
}

function getFileIcon(mimeType) {
    if (mimeType.startsWith('image/')) return 'fa-file-image';
    if (mimeType.startsWith('video/')) return 'fa-file-video';
    if (mimeType.startsWith('audio/')) return 'fa-file-audio';
    if (mimeType.includes('pdf')) return 'fa-file-pdf';
    if (mimeType.includes('word') || mimeType.includes('document')) return 'fa-file-word';
    if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) return 'fa-file-excel';
    if (mimeType.includes('powerpoint') || mimeType.includes('presentation')) return 'fa-file-powerpoint';
    if (mimeType.includes('zip') || mimeType.includes('compressed')) return 'fa-file-archive';
    if (mimeType.includes('text/')) return 'fa-file-alt';
    return 'fa-file';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function updateUploadAreaVisibility() {
    const uploadArea = document.getElementById('uploadArea');
    const fileList = document.getElementById('fileList');
    
    // 始终显示上传区域和文件列表
    uploadArea.style.display = 'flex';
    fileList.style.display = 'block';
    
    // 如果没有文件，隐藏文件列表
    if (selectedFiles.length === 0) {
        fileList.style.display = 'none';
    }
}

// 初始化文件提交功能
function initFileSubmit() {
    const submitFileBtn = document.getElementById('submitFile');
    const filePassword = document.getElementById('filePassword');
    const fileDuration = document.getElementById('fileDuration');
    const fileCustomUrl = document.getElementById('fileCustomUrl');
    const fileMaxViews = document.getElementById('fileMaxViews');
    const progressContainer = document.getElementById('uploadProgressContainer');
    const progressBar = document.getElementById('uploadProgressBar');
    const progressText = document.getElementById('uploadProgressText');
    const progressPercent = document.getElementById('uploadProgressPercent');

    // 添加速度计算相关变量
    let uploadStartTime;
    let lastUploadedBytes = 0;
    let lastUploadTime = 0;
    let uploadSpeed = 0;
    let speedUpdateInterval;

    // 格式化速度显示
    function formatSpeed(bytesPerSecond) {
        if (bytesPerSecond < 1024) {
            return `${bytesPerSecond.toFixed(1)} B/s`;
        } else if (bytesPerSecond < 1024 * 1024) {
            return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
        } else {
            return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s`;
        }
    }

    // 计算上传速度
    function calculateSpeed(loadedBytes, timestamp) {
        const timeElapsed = timestamp - lastUploadTime;
        if (timeElapsed > 0) {
            const bytesIncrement = loadedBytes - lastUploadedBytes;
            uploadSpeed = (bytesIncrement / timeElapsed) * 1000; // 转换为每秒
        }
        lastUploadedBytes = loadedBytes;
        lastUploadTime = timestamp;
        return uploadSpeed;
    }

    // 添加获取持续时间的毫秒数的函数
    function getDurationInMs(duration) {
        const durations = {
            '1h': 60 * 60 * 1000,
            '1d': 24 * 60 * 60 * 1000,
            '7d': 7 * 24 * 60 * 60 * 1000,
            '30d': 30 * 24 * 60 * 60 * 1000
        };
        return durations[duration] || 0;
    }

    let currentXhr = null; // 用于存储当前的 XMLHttpRequest 对象
    let isUploading = false; // 添加标记表示是否正在上传
    let isCancelled = false; // 添加标记表示是否已取消

    if (submitFileBtn) {
        submitFileBtn.addEventListener('click', async () => {
            if (selectedFiles.length === 0) {
                alert('请先选择要上传的文件');
                return;
            }

            // 重置取消状态
            isCancelled = false;
            isUploading = true;

            // 更新按钮状态
            submitFileBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 正在打包上传...';
            submitFileBtn.disabled = true;
            progressContainer.style.display = 'block';

            try {
                // 检查是否只有一个文件且是压缩文件
                const isCompressedFile = selectedFiles.length === 1 && (
                    selectedFiles[0].type === 'application/zip' ||
                    selectedFiles[0].type === 'application/x-rar-compressed' ||
                    selectedFiles[0].type === 'application/x-7z-compressed' ||
                    selectedFiles[0].name.toLowerCase().endsWith('.zip') ||
                    selectedFiles[0].name.toLowerCase().endsWith('.rar') ||
                    selectedFiles[0].name.toLowerCase().endsWith('.7z')
                );

                let uploadFile;
                let originalFilenames;

                if (isCompressedFile) {
                    // 如果是压缩文件，直接使用
                    uploadFile = selectedFiles[0];
                    originalFilenames = selectedFiles[0].name;
                } else {
                    // 如果不是压缩文件，创建zip
                    const zip = new JSZip();
                    
                    // 将所有文件添加到 zip 中
                    for (const file of selectedFiles) {
                        // 检查是否已取消
                        if (isCancelled) {
                            throw new Error('cancelled');
                        }
                        zip.file(file.name, file);
                    }

                    // 生成 zip 文件
                    const zipBlob = await zip.generateAsync({
                        type: 'blob',
                        compression: 'DEFLATE',
                        compressionOptions: {
                            level: 9
                        }
                    }, (metadata) => {
                        // 检查是否已取消
                        if (isCancelled) {
                            throw new Error('cancelled');
                        }
                        // 更新压缩进度
                        const progress = metadata.percent.toFixed(1);
                        progressBar.style.width = `${progress}%`;
                        progressPercent.textContent = `${progress}%`;
                        progressText.innerHTML = `
                            <i class="fas fa-arrows-alt-v"></i>
                            正在压缩... 
                            <span class="upload-count">${selectedFiles.length}个文件</span>
                        `;
                    });

                    // 创建文件名（使用当前时间戳）
                    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                    originalFilenames = selectedFiles.map(f => f.name).join(', ');
                    uploadFile = new File([zipBlob], `cloudpaste_${timestamp}.zip`, { 
                        type: 'application/zip',
                        lastModified: Date.now()
                    });
                }

                // 检查是否已取消
                if (isCancelled) {
                    throw new Error('cancelled');
                }

                // 准备表单数据
                const formData = new FormData();
                formData.append('file', uploadFile);
                formData.append('originalname', originalFilenames);
                formData.append('password', filePassword.value);
                formData.append('duration', fileDuration.value);
                formData.append('customUrl', fileCustomUrl.value);
                formData.append('maxViews', fileMaxViews.value);
                formData.append('isUserUpload', 'true');  // 添加用户上传标记

                // 重置上传速度计算
                uploadStartTime = Date.now();
                lastUploadedBytes = 0;
                lastUploadTime = uploadStartTime;
                uploadSpeed = 0;

                // 使用 XMLHttpRequest 上传
                const response = await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    currentXhr = xhr; // 保存当前的 xhr 对象
                    
                    xhr.upload.addEventListener('progress', (progressEvent) => {
                        if (progressEvent.lengthComputable) {
                            const currentTime = Date.now();
                            const speed = calculateSpeed(progressEvent.loaded, currentTime);
                            
                            // 计算进度百分比
                            const progress = (progressEvent.loaded / progressEvent.total) * 100;
                            
                            // 计算预计剩余时间
                            const remainingBytes = progressEvent.total - progressEvent.loaded;
                            const estimatedTimeSeconds = speed > 0 ? remainingBytes / speed : 0;
                            
                            // 更新进度显示
                            progressBar.style.width = `${progress}%`;
                            progressPercent.textContent = `${Math.round(progress)}%`;
                            
                            // 更新上传状态显示
                            if (progressEvent.loaded === 0) {
                                progressText.innerHTML = `
                                    <i class="fas fa-cloud-upload-alt"></i>
                                    <span>正在处理文件...</span>
                                    <span class="upload-count">${selectedFiles.length}个文件</span>
                                `;
                            } else {
                                progressText.innerHTML = `
                                    <i class="fas fa-upload"></i>
                                    <span>正在上传...</span>
                                    <span class="upload-count">${selectedFiles.length}个文件</span>
                                    <i class="fas fa-tachometer-alt"></i>
                                    <span class="upload-speed">${formatSpeed(speed)}</span>
                                    ${estimatedTimeSeconds > 0 ? `
                                        <i class="far fa-clock"></i>
                                        <span class="time-remaining">${Math.ceil(estimatedTimeSeconds)}s</span>
                                    ` : ''}
                                `;
                            }
                        }
                    });

                    xhr.addEventListener('load', () => {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            resolve({
                                ok: true,
                                json: () => Promise.resolve(JSON.parse(xhr.responseText))
                            });
                        } else {
                            // 检查是否是网络连接丢失错误
                            const response = JSON.parse(xhr.responseText);
                            if (response && response.error && response.error.includes('Network connection lost')) {
                                resolve({ ok: false, cancelled: true });
                                return;
                            }
                            // 如果是取消上传，不抛出错误
                            if (currentXhr === null) {
                                resolve({ ok: false, cancelled: true });
                                return;
                            }
                            reject(new Error(`HTTP Error: ${xhr.status}`));
                        }
                    });

                    xhr.addEventListener('error', () => {
                        // 检查是否是用户主动取消或网络连接丢失
                        if (currentXhr === null || xhr.status === 0) {
                            resolve({ ok: false, cancelled: true });
                            return;
                        }
                        reject(new Error('Network Error'));
                    });

                    xhr.addEventListener('abort', () => {
                        resolve({ ok: false, cancelled: true });
                    });

                    xhr.open('POST', '/api/file');
                    xhr.send(formData);
                }).catch(error => {
                    // 如果是取消上传或网络连接丢失，不显示错误
                    if (currentXhr === null || (error.message && (error.message.includes('Network') || error.message.includes('connection')))) {
                        return { ok: false, cancelled: true };
                    }
                    throw error;
                });

                // 检查是否是取消上传或网络连接丢失
                if (!response || response.cancelled) {
                    // 重置上传状态
                    submitFileBtn.disabled = false;
                    submitFileBtn.innerHTML = '<i class="fas fa-upload"></i> 创建文件分享';
                    progressContainer.style.display = 'none';
                    progressBar.style.width = '0%';
                    progressPercent.textContent = '0%';
                    progressText.textContent = '正在处理文件...';
                    return;
                }

                if (!response.ok) {
                    // 如果是取消上传或网络连接丢失，不抛出错误
                    if (currentXhr === null || response.cancelled) {
                        return;
                    }
                    throw new Error('上传失败');
                }

                const result = await response.json().catch(error => {
                    // 如果是取消上传或网络连接丢失，不处理错误
                    if (currentXhr === null || (error.message && (error.message.includes('Network') || error.message.includes('connection')))) {
                        return { success: false, cancelled: true };
                    }
                    throw error;
                });

                // 如果是取消上传或网络连接丢失，直接返回
                if (!result || result.cancelled) {
                    return;
                }

                // 重置按钮状态
                submitFileBtn.disabled = false;
                submitFileBtn.innerHTML = '<i class="fas fa-upload"></i> 创建文件分享';
                progressContainer.style.display = 'none';
                progressBar.style.width = '0%';
                progressPercent.textContent = '0%';
                progressText.textContent = '正在处理文件...';

                if (result.success) {
                    // 创建结果显示
                    const fileUploadDiv = document.getElementById('fileUpload');
                    const resultDiv = fileUploadDiv.querySelector('.upload-result') || document.createElement('div');
                    resultDiv.className = 'upload-result';
                    const url = `${window.location.origin}${result.data.url}`;
                    
                    // 创建新的结果元素
                    resultDiv.innerHTML = `
                        <div class="share-result success">
                            <div class="result-header" style="color: var(--text-color); display: flex; align-items: center; gap: 8px;">
                                <i class="fas fa-check-circle" style="color: var(--success-color);"></i>
                                <h3 style="margin: 0;">文件上传成功！</h3>
                            </div>
                            <div class="content-info">
                                <div class="info-item">
                                    <i class="fas fa-file-archive"></i>
                                    压缩包（${selectedFiles.length}个文件）
                                </div>
                                <div class="info-item">
                                    <i class="fas fa-weight"></i>
                                    ${formatFileSize(uploadFile.size)}
                                </div>
                                <div class="info-item time">
                                    <i class="far fa-clock"></i>
                                    ${fileDuration.value === 'never' ? '永久有效' : new Date(Date.now() + getDurationInMs(fileDuration.value)).toLocaleString()}
                                </div>
                            </div>
                            <div class="share-link-container">
                                <input type="text" class="share-link" value="${url}" readonly>
                                <button class="copy-btn" title="复制链接">
                                    <i class="fas fa-copy"></i>
                                </button>
                                <button class="qr-btn" title="显示二维码">
                                    <i class="fas fa-qrcode"></i>
                                </button>
                            </div>
                        </div>
                    `;

                    // 将结果添加到文件上传界面
                    if (!fileUploadDiv.contains(resultDiv)) {
                        fileUploadDiv.appendChild(resultDiv);
                    }

                    // 添加事件监听器
                    const copyBtn = resultDiv.querySelector('.copy-btn');
                    const qrBtn = resultDiv.querySelector('.qr-btn');
                    const shareLinkInput = resultDiv.querySelector('.share-link');

                    copyBtn.addEventListener('click', () => {
                        copyBtn.setAttribute('data-copied', 'true');
                        copyToClipboard(url);
                    });
                    qrBtn.addEventListener('click', () => toggleQRCode(url));

                    // 自动选中分享链接
                    shareLinkInput.select();

                    // 清空已选文件列表
                    selectedFiles = [];
                    const fileList = document.getElementById('fileList');
                    fileList.innerHTML = '';

                    // 添加到存储列表并更新统计
                    await Promise.all([
                        displayStorageList(null, {
                            type: 'file',
                            filename: result.data.filename,
                            mimetype: 'application/zip',
                            filesize: uploadFile.size
                        }),
                        fetchShareStats(),
                        fetchStorageList()
                    ]);
                }

                // 更新上传区域可见性
                updateUploadAreaVisibility();

                // 重置表单但保持上传区域可用
                filePassword.value = '';
                fileCustomUrl.value = '';
                fileMaxViews.value = '0';

            } catch (error) {
                // 检查是否是取消上传导致的错误
                if (currentXhr === null || (error.message && (error.message.includes('Network') || error.message.includes('connection')))) {
                    return;
                }
                console.error('上传文件时出错：', error);
                alert('上传失败：' + error.message);
            } finally {
                // 如果不是取消上传或网络连接丢失，才重置按钮状态
                if (currentXhr !== null) {
                    submitFileBtn.disabled = false;
                    submitFileBtn.innerHTML = '<i class="fas fa-upload"></i> 创建文件分享';
                    progressContainer.style.display = 'none';
                    progressBar.style.width = '0%';
                    progressPercent.textContent = '0%';
                    progressText.textContent = '正在处理文件...';
                }
            }
        });
    }

    // 添加取消上传按钮的事件监听
    const cancelUploadBtn = document.getElementById('cancelUpload');
    if (cancelUploadBtn) {
        cancelUploadBtn.addEventListener('click', () => {
            if (currentXhr || isUploading) {
                // 标记为用户主动取消
                isCancelled = true;
                if (currentXhr) {
                    currentXhr.abort(); // 取消上传
                    currentXhr = null;
                }
                isUploading = false;
                
                // 重置上传状态
                submitFileBtn.disabled = false;
                submitFileBtn.innerHTML = '<i class="fas fa-upload"></i> 创建文件分享';
                progressContainer.style.display = 'none';
                progressBar.style.width = '0%';
                progressPercent.textContent = '0%';
                progressText.textContent = '正在处理文件...';
                
                // 显示取消上传的提示
                const toast = document.createElement('div');
                toast.className = 'toast';
                toast.textContent = '已取消文件上传';
                document.body.appendChild(toast);
                setTimeout(() => {
                    toast.remove();
                }, 3000);
            }
        });
    }
}

// 获取分享统计数据
async function fetchShareStats() {
    try {
        // 获取存储列表数据
        const response = await fetch('/api/share/stats');
        if (!response.ok) {
            throw new Error('获取统计数据失败');
        }
        const data = await response.json();
        
        if (data.success) {
            // 更新统计数据显示
            document.getElementById('totalShares').textContent = data.data.totalShares;
            document.getElementById('activeShares').textContent = data.data.activeShares;
            document.getElementById('usedStorage').textContent = formatFileSize(data.data.usedStorage);
            document.getElementById('totalStorage').textContent = formatFileSize(data.data.totalStorage);
            
            // 计算并更新使用百分比
            const usagePercent = data.data.usagePercent;
            document.getElementById('usagePercent').textContent = `${usagePercent}%`;
            
            // 更新进度条
            const progressBar = document.querySelector('.usage-progress');
            if (progressBar) {
                progressBar.style.width = `${usagePercent}%`;
                
                // 根据使用比例设置状态样式
                progressBar.className = 'usage-progress';
                if (usagePercent >= 90) {
                    progressBar.classList.add('danger');
                } else if (usagePercent >= 70) {
                    progressBar.classList.add('warning');
                }
            }
            
            // 更新存储状态标签
            const storageUsage = document.querySelector('.storage-usage');
            if (storageUsage) {
                storageUsage.className = 'storage-usage';
                if (usagePercent >= 90) {
                    storageUsage.classList.add('danger');
                } else if (usagePercent >= 70) {
                    storageUsage.classList.add('warning');
                }
            }
        }
    } catch (error) {
        console.error('获取统计数据失败:', error);
    }
}

// 获取存储列表
async function fetchStorageList() {
    const shareItems = document.getElementById('shareItems');
    
    try {
        // 添加loading类来触发加载动画
        shareItems.classList.add('loading');

        const response = await fetch('/api/file');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            shareItems.innerHTML = ''; // 清空现有内容
            displayStorageList(data.data);
        } else {
            throw new Error(data.message || '获取存储列表失败');
        }
    } catch (err) {
        console.error('获取存储列表失败:', err);
        shareItems.innerHTML = `
            <div class="error-state">
                <i class="fas fa-exclamation-circle"></i>
                <p>获取存储列表失败: ${err.message}</p>
                <button onclick="fetchStorageList()" class="retry-btn">
                    <i class="fas fa-redo"></i> 重试
                </button>
            </div>
        `;
    } finally {
        // 移除loading类
        shareItems.classList.remove('loading');
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
            originalname: newItem.originalname,
            createdAt: newItem.createdAt || newItem.created || Date.now()
        });
        
        // 创建一个临时容器来包含新的HTML
        const temp = document.createElement('div');
        temp.innerHTML = newItemHtml;
        const newElement = temp.firstElementChild;
        
        // 将新元素插入到列表开头
        if (shareItems.firstChild) {
            shareItems.insertBefore(newElement, shareItems.firstChild);
        } else {
            shareItems.appendChild(newElement);
        }
        
        // 触发动画
        requestAnimationFrame(() => {
            newElement.style.opacity = '1';
            newElement.style.transform = 'translateY(0)';
        });
        
        return;
    }

    // 合并KV和R2的数据为统一的分享列表
    const allShares = [
        // 添加文本分享
        ...(data.kv || []).map(item => ({
            id: item.id,
            type: 'text',
            content: item.content,
            expiration: item.expiration,
            createdAt: item.createdAt,
            filename: item.filename
        })),
        // 添加文件分享
        ...(data.r2 || []).map(item => ({
            id: item.id,
            type: 'file',
            size: item.filesize,
            expiration: item.expiration,
            filename: item.filename,
            originalname: item.originalname,
            createdAt: item.createdAt
        }))
    ];

    // 按创建时间排序，最新的在前面
    allShares.sort((a, b) => {
        const timeA = new Date(a.createdAt).getTime();
        const timeB = new Date(b.createdAt).getTime();
        return timeB - timeA;
    });

    // 生成HTML并添加到容器
    shareItems.innerHTML = allShares.map(item => createShareItem(item)).join('');

    // 触发列表项的动画
    const items = shareItems.children;
    Array.from(items).forEach((item, index) => {
        item.style.animationDelay = `${index * 0.1}s`;
    });

    // 添加事件监听器
    addStorageItemEventListeners();
}

// 修改事件监听器添加函数
function addStorageItemEventListeners(container = document) {
    // 复制按钮事件
    container.querySelectorAll('.share-item-btn.copy').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const item = e.target.closest('.share-item');
            const id = item.getAttribute('data-id');
            const shareUrl = `${window.location.origin}/s/${id}`;
            try {
                await navigator.clipboard.writeText(shareUrl);
                const copyBtn = e.target.closest('.share-item-btn');
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    copyBtn.innerHTML = '<i class="fas fa-link"></i>';
                }, 2000);
                showToast('已复制分享链接', 'success');
            } catch (err) {
                console.error('复制失败:', err);
                showToast('复制失败', 'error');
            }
        });
    });
}

// 在刷新列表时调用
document.getElementById('refreshList').addEventListener('click', async (e) => {
    const refreshBtn = e.currentTarget;
    refreshBtn.classList.add('loading');
    refreshBtn.disabled = true;
    
    try {
        await fetchStorageList();
        await fetchShareStats();
    } finally {
        refreshBtn.classList.remove('loading');
        refreshBtn.disabled = false;
    }
});

// 初始化时调用
document.addEventListener('DOMContentLoaded', () => {
    fetchStorageList();
    initShareFilters();
});

// Toast 通知功能
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `vt-ast vt-ast-${type}`;
    toast.innerHTML = `
        <div class="vt-ast-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    document.body.appendChild(toast);

    // 添加显示类以触发动画
    setTimeout(() => toast.classList.add('show'), 10);

    // 3秒后移除
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// 添加 Toast 样式
const style = document.createElement('style');
style.textContent = `
    .vt-ast {
        position: fixed;
        top: 16px;
        right: 16px;
        padding: 10px 16px;
        border-radius: 4px;
        background: white;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        transform: translateX(120%);
        transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        z-index: 1000;
        min-width: 200px;
        max-width: 320px;
    }

    .vt-ast.show {
        transform: translateX(0);
    }

    .vt-ast-content {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 14px;
    }

    .vt-ast-success {
        background: #f0fdf4;
        border-left: 3px solid #22c55e;
        color: #15803d;
    }

    .vt-ast-error {
        background: #fef2f2;
        border-left: 3px solid #ef4444;
        color: #b91c1c;
    }

    .vt-ast-info {
        background: #eff6ff;
        border-left: 3px solid #3b82f6;
        color: #1d4ed8;
    }

    .vt-ast i {
        font-size: 16px;
    }
`;
document.head.appendChild(style);

// 修改删除按钮的点击处理函数
async function handleDelete(id) {
    try {
        const response = await fetch(`/api/share/${id}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('删除成功', 'success');
            // 重新加载分享列表
            await fetchShareList();
            // 重新加载存储列表
            await fetchStorageList();
            // 重新加载统计数据
            await fetchShareStats();
        } else {
            showToast(data.message || '删除失败', 'error');
        }
    } catch (err) {
        console.error('删除失败:', err);
        showToast('删除失败: ' + err.message, 'error');
    }
}

// 删除存储项
async function deleteStorageItem(id, type) {
    const confirmed = confirm(
        '确定要删除这个分享吗？\n' +
        '此操作不可恢复！'
    );
    
    if (!confirmed) return;

    try {
        // 立即从界面上移除
        const item = document.querySelector(`.share-item[data-id="${id}"]`);
        if (item) {
            item.classList.add('deleting');
        }

        // 发送删除请求，同时删除 KV 和 R2 中的数据
        const response = await fetch(`/api/share/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (data.success) {
            if (item) {
                // 添加淡出动画
                item.style.transition = 'opacity 0.3s ease';
                item.style.opacity = '0';
                setTimeout(() => {
                    item.remove();
                }, 300);
            }
            showToast('删除成功', 'success');
            // 只更新统计数据
            await fetchShareStats();
        } else {
            // 如果删除失败，恢复界面显示并显示错误消息
            if (item) {
                item.classList.remove('deleting');
            }
            // 检查是否是网络连接丢失
            if (data.message && data.message.includes('Network connection lost')) {
                return;
            }
            showToast(data.message || '删除失败', 'error');
            // 删除失败时才重新获取列表
            await fetchStorageList();
        }
    } catch (err) {
        // 检查是否是网络连接丢失
        if (err.message && (err.message.includes('Network') || err.message.includes('connection'))) {
            return;
        }
        console.error('删除失败:', err);
        // 恢复界面显示
        if (item) {
            item.classList.remove('deleting');
        }
        showToast(err.message || '删除失败', 'error');
        // 删除失败时才重新获取列表
        await fetchStorageList();
    }
}

// 添加确认对话框样式
const confirmDialogStyle = document.createElement('style');
confirmDialogStyle.textContent = `
    .confirm-dialog-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }

    .confirm-dialog {
        background: white;
        border-radius: 8px;
        padding: 24px;
        max-width: 400px;
        width: 90%;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }

    .confirm-dialog h3 {
        margin: 0 0 16px 0;
        font-size: 18px;
        color: #333;
    }

    .confirm-dialog p {
        margin: 0 0 20px 0;
        color: #666;
    }

    .confirm-dialog p.warning {
        color: #dc2626;
        font-weight: 500;
    }

    .confirm-dialog-buttons {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
    }

    .confirm-dialog-btn {
        padding: 8px 16px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
        transition: all 0.2s;
    }

    .confirm-dialog-btn.confirm {
        background: #3b82f6;
        color: white;
    }

    .confirm-dialog-btn.confirm:hover {
        background: #2563eb;
    }

    .confirm-dialog-btn.cancel {
        background: #e5e7eb;
        color: #374151;
    }

    .confirm-dialog-btn.cancel:hover {
        background: #d1d5db;
    }
`;
document.head.appendChild(confirmDialogStyle);

// 显示确认对话框
function showConfirmDialog(message, warningText) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'confirm-dialog-overlay';
        
        overlay.innerHTML = `
            <div class="confirm-dialog">
                <h3>确认删除</h3>
                <p>${message}</p>
                ${warningText ? `<p class="warning">${warningText}</p>` : ''}
                <div class="confirm-dialog-buttons">
                    <button class="confirm-dialog-btn confirm">确定删除</button>
                    <button class="confirm-dialog-btn cancel">取消</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        const dialog = overlay.querySelector('.confirm-dialog');
        const confirmBtn = dialog.querySelector('.confirm-dialog-btn.confirm');
        const cancelBtn = dialog.querySelector('.confirm-dialog-btn.cancel');
        
        function close(result) {
            // 添加关闭动画
            dialog.style.transform = 'translateX(100%)';
            dialog.style.opacity = '0';
            
            // 等待动画完成后移除元素
            setTimeout(() => {
                overlay.remove();
                resolve(result);
            }, 300);
        }
        
        confirmBtn.addEventListener('click', () => close(true));
        cancelBtn.addEventListener('click', () => close(false));
        
        // 阻止对话框上的点击事件冒泡到遮罩层
        dialog.addEventListener('click', (e) => {
            e.stopPropagation();
        });
        
        // ESC 键关闭
        document.addEventListener('keydown', function escListener(e) {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escListener);
                close(false);
            }
        });
    });
}

// 添加复制链接函数
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        const copyBtn = document.querySelector('.copy-btn[data-copied="true"]');
        if (copyBtn) {
            const originalTitle = copyBtn.getAttribute('title');
            copyBtn.innerHTML = '<i class="fas fa-check"></i>';
            copyBtn.setAttribute('title', '已复制！');
            setTimeout(() => {
                copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
                copyBtn.setAttribute('title', originalTitle);
                copyBtn.removeAttribute('data-copied');
            }, 2000);
        }
    } catch (err) {
        console.error('复制失败:', err);
        alert('复制失败，请手动复制');
    }
}

// 添加显示二维码函数
function toggleQRCode(url) {
    const qrCodeContainer = document.createElement('div');
    qrCodeContainer.className = 'qr-code-container';
    qrCodeContainer.style.cssText = 'display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); justify-content: center; align-items: center; z-index: 1000;';
    
    qrCodeContainer.innerHTML = `
        <div class="qr-code-modal" style="background: var(--background-color); padding: 24px; border-radius: 8px; text-align: center; max-width: 90%; width: 320px; position: relative; transform: translateY(-20px); opacity: 0; transition: all 0.3s ease; border: 1px solid var(--border-color);">
            <h3 style="margin: 0 0 16px 0; font-size: 18px; color: var(--text-color); font-weight: bold;">扫描二维码访问</h3>
            <div class="qr-code" id="tempQrCode" style="margin-bottom: 16px; background: white; padding: 12px; border-radius: 4px;"></div>
            <div class="qr-code-actions" style="display: flex; gap: 8px; justify-content: center;">
                <button class="qr-download-btn" id="tempDownloadQRCode" style="padding: 8px 16px; background: var(--primary-color); color: white; border: none; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 4px;">
                    <i class="fas fa-download"></i> 下载二维码
                </button>
                <button class="qr-close-btn" style="padding: 8px 16px; background: var(--secondary-color); color: var(--text-color); border: none; border-radius: 4px; cursor: pointer;">
                    关闭
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(qrCodeContainer);
    
    // 生成二维码
    QRCode.toDataURL(url, {
        width: 250,
        height: 250,
        margin: 2,
        color: {
            dark: '#000000',
            light: '#ffffff'
        }
    }, (err, qrUrl) => {
        if (err) {
            console.error('生成二维码失败:', err);
            alert('生成二维码失败');
            return;
        }
        
        const img = document.createElement('img');
        img.src = qrUrl;
        img.alt = '分享链接二维码';
        img.style.maxWidth = '100%';
        document.getElementById('tempQrCode').appendChild(img);
        
        // 下载按钮事件
        document.getElementById('tempDownloadQRCode').addEventListener('click', () => {
            const link = document.createElement('a');
            link.download = '分享链接二维码.png';
            link.href = qrUrl;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    });
    
    // 显示容器并添加动画
    qrCodeContainer.style.display = 'flex';
    setTimeout(() => {
        const modal = qrCodeContainer.querySelector('.qr-code-modal');
        modal.style.transform = 'translateY(0)';
        modal.style.opacity = '1';
    }, 10);
    
    // 关闭按钮事件
    const closeBtn = qrCodeContainer.querySelector('.qr-close-btn');
    closeBtn.addEventListener('click', closeQRCode);
    
    // 点击遮罩层关闭
    qrCodeContainer.addEventListener('click', (e) => {
        if (e.target === qrCodeContainer) {
            closeQRCode();
        }
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

// 显示Toast提示
function showToast(message = '内容已复制到剪贴板', duration = 2000) {
    const toast = document.getElementById('toast');
    const messageSpan = toast.querySelector('span');
    messageSpan.textContent = message;
    
    // 清除之前的定时器
    if (toast.hideTimeout) {
        clearTimeout(toast.hideTimeout);
    }
    
    // 显示 toast
    toast.classList.add('show');
    
    // 设置定时器隐藏 toast
    toast.hideTimeout = setTimeout(() => {
        toast.classList.remove('show');
    }, duration);
}

// 显示登录对话框
function showLoginDialog() {
    return new Promise((resolve) => {
        // 检查是否已经有会话
        const sessionId = localStorage.getItem('sessionId');
        if (sessionId) {
            // 验证会话是否有效
            fetch('/api/admin/session', {
                headers: {
                    'X-Session-Id': sessionId
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    resolve(true);
                    return;
                }
                // 会话无效，删除本地存储的会话ID
                localStorage.removeItem('sessionId');
                showLoginForm();
            })
            .catch(() => {
                localStorage.removeItem('sessionId');
                showLoginForm();
            });
        } else {
            showLoginForm();
        }

        function showLoginForm() {
            const overlay = document.createElement('div');
            overlay.className = 'login-dialog-overlay';
        
        overlay.innerHTML = `
            <div class="login-dialog">
                <h3>管理员登录</h3>
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" id="loginUsername" placeholder="请输入用户名">
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <div class="password-input-container">
                    <input type="password" id="loginPassword" placeholder="请输入密码">
                        <button type="button" class="password-toggle-btn" title="显示/隐藏密码">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                <div class="login-dialog-buttons">
                    <button class="login-dialog-btn login">登录</button>
                    <button class="login-dialog-btn cancel">取消</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        const dialog = overlay.querySelector('.login-dialog');
        const loginBtn = dialog.querySelector('.login-dialog-btn.login');
        const cancelBtn = dialog.querySelector('.login-dialog-btn.cancel');
        const usernameInput = dialog.querySelector('#loginUsername');
        const passwordInput = dialog.querySelector('#loginPassword');
        const toggleBtn = dialog.querySelector('.password-toggle-btn');

        // 定义登录函数
        async function handleLogin() {
            const username = usernameInput.value.trim();
            const password = passwordInput.value.trim();
            
            if (!username || !password) {
                alert('请输入用户名和密码');
                return;
            }
            
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                        // 保存会话ID到本地存储
                        localStorage.setItem('sessionId', data.data.sessionId);
                    close(true);
                } else {
                    alert(data.message || '登录失败');
                }
            } catch (error) {
                alert('登录失败：' + error.message);
            }
        }
        
        function close(result) {
                overlay.remove();
                resolve(result);
        }
        
        // 登录按钮点击事件
        loginBtn.addEventListener('click', handleLogin);
        
        // 添加回车键登录
        function handleKeyPress(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleLogin();
            }
        }
        
        // 为用户名和密码输入框添加回车键事件
        usernameInput.addEventListener('keypress', handleKeyPress);
        passwordInput.addEventListener('keypress', handleKeyPress);
        
        cancelBtn.addEventListener('click', () => close(false));
        
        // ESC 键关闭
        document.addEventListener('keydown', function escListener(e) {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escListener);
                close(false);
            }
        });
        
        // 阻止对话框上的点击事件冒泡到遮罩层
        dialog.addEventListener('click', (e) => {
            e.stopPropagation();
        });
        
        // 自动聚焦用户名输入框
        usernameInput.focus();
        
        toggleBtn.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            
            // 更新图标
            const icon = toggleBtn.querySelector('i');
            icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
            
            // 更新提示文本
            toggleBtn.title = type === 'password' ? '显示密码' : '隐藏密码';
        });
        }
    });
}

// 初始化密码显示/隐藏功能
function initPasswordToggle() {
    const passwordContainers = document.querySelectorAll('.password-input-container');
    
    passwordContainers.forEach(container => {
        const input = container.querySelector('input[type="password"]');
        const toggleBtn = container.querySelector('.password-toggle-btn');
        
        if (input && toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                const type = input.type === 'password' ? 'text' : 'password';
                input.type = type;
                
                // 更新图标
                const icon = toggleBtn.querySelector('i');
                icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
                
                // 更新提示文本
                toggleBtn.title = type === 'password' ? '显示密码' : '隐藏密码';
            });
        }
    });
}

// 显示密码验证对话框
function showPasswordDialog(shareId) {
    return new Promise((resolve) => {
        const dialog = document.createElement('div');
        dialog.className = 'password-dialog';
        dialog.innerHTML = `
            <div class="password-dialog-content">
                <h3>需要密码访问</h3>
                <p>此内容已被密码保护，请输入密码继续访问</p>
                <input type="password" id="sharePassword" placeholder="请输入访问密码" />
                <div class="dialog-buttons">
                    <button class="cancel-btn">取消</button>
                    <button class="submit-btn">确认</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
        
        const passwordInput = dialog.querySelector('#sharePassword');
        const submitBtn = dialog.querySelector('.submit-btn');
        const cancelBtn = dialog.querySelector('.cancel-btn');
        
        submitBtn.addEventListener('click', () => {
            const password = passwordInput.value.trim();
            if (!password) {
                showToast('请输入密码', 'warning');
                return;
            }
            dialog.remove();
            resolve(password);
        });
        
        cancelBtn.addEventListener('click', () => {
            dialog.remove();
            resolve(null);
        });
        
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                submitBtn.click();
            }
        });
        
        // 自动聚焦密码输入框
        passwordInput.focus();
    });
}

// 验证分享密码
async function verifySharePassword(shareId, password) {
    try {
        const response = await fetch(`/api/share/${shareId}/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const result = await response.json();
        return result.success;
    } catch (error) {
        console.error('密码验证失败:', error);
        return false;
    }
}

// 修改获取分享内容的函数
async function fetchShareContent(shareId, type) {
    try {
        // 先尝试获取内容
        const response = await fetch(`/api/share/${shareId}`);
        const data = await response.json();
        
        // 如果需要密码验证
        if (response.status === 403 && data.requirePassword) {
            // 显示密码输入对话框
            const password = await showPasswordDialog(shareId);
            if (!password) {
                return null; // 用户取消输入密码
            }
            
            // 验证密码
            const isValid = await verifySharePassword(shareId, password);
            if (!isValid) {
                showToast('密码错误', 'error');
                return null;
            }
            
            // 密码验证通过，重新获取内容
            const newResponse = await fetch(`/api/share/${shareId}`, {
                headers: {
                    'X-Share-Password': password
                }
            });
            return await newResponse.json();
        }
        
        return data;
    } catch (error) {
        console.error('获取分享内容失败:', error);
        showToast('获取分享内容失败', 'error');
        return null;
    }
}

// 修改查看分享内容的处理函数
async function viewShareContent(shareId, type) {
    const data = await fetchShareContent(shareId, type);
    if (!data) return;
    
    if (data.success) {
        if (type === 'text') {
            displayTextContent(data.data);
        } else {
            window.location.href = data.data.url;
        }
    } else {
        showToast(data.message || '获取内容失败', 'error');
    }
}

// ... existing code ...

// ... existing code ... 

// 初始化密码保护功能
function initPasswordProtection() {
    const passwordToggle = document.getElementById('passwordToggle');
    const passwordInput = document.getElementById('sharePassword');
    const passwordContainer = document.querySelector('.password-container');
    
    if (passwordToggle) {
        passwordToggle.addEventListener('change', () => {
            if (passwordContainer) {
                passwordContainer.style.display = passwordToggle.checked ? 'block' : 'none';
            }
            if (passwordInput) {
                passwordInput.required = passwordToggle.checked;
                if (!passwordToggle.checked) {
                    passwordInput.value = '';
                }
            }
        });
    }
}

// 修改文本提交处理函数
async function submitTextHandler() {
    // ... existing code ...
    
    const password = document.getElementById('textPassword')?.value;
    const usePassword = document.getElementById('passwordToggle')?.checked;
    
    const formData = new FormData();
    formData.append('content', textContent.value);
    formData.append('expiration', document.getElementById('textDuration').value);
    formData.append('maxViews', document.getElementById('textMaxViews').value);
    if (usePassword && password) {
        formData.append('password', password);
    }
    
    try {
        // ... existing code ...
    } catch (error) {
        // ... existing code ...
    }
}

// 修改文件提交处理函数
async function submitFileHandler() {
    // ... existing code ...
    
    const password = document.getElementById('sharePassword')?.value;
    const usePassword = document.getElementById('passwordToggle')?.checked;
    
    const formData = new FormData();
    for (const file of selectedFiles) {
        formData.append('files', file);
    }
    formData.append('expiration', document.getElementById('expiration').value);
    formData.append('maxViews', document.getElementById('maxViews').value);
    if (usePassword && password) {
        formData.append('password', password);
    }
    
    try {
        // ... existing code ...
    } catch (error) {
        // ... existing code ...
    }
}

// 在文档加载完成后初始化密码保护功能
document.addEventListener('DOMContentLoaded', () => {
    // ... existing code ...
    initPasswordProtection();
});

// ... existing code ... 