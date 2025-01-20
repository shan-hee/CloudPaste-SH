import fetch from 'node-fetch';

// 等待开发服务器启动
async function waitForServer(retries = 10) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await fetch('http://localhost:8787/api/init');
            const data = await response.json();
            if (data.success) {
                console.log('数据库初始化成功');
                return true;
            }
        } catch (error) {
            console.log(`等待服务器启动... (${i + 1}/${retries})`);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    throw new Error('服务器启动超时');
}

waitForServer().catch(error => {
    console.error('初始化失败:', error);
    process.exit(1);
}); 