# CloudPaste-SH

CloudPaste-SH 是一个现代化的在线文本分享平台，支持 Markdown 编辑和实时预览功能。它提供了一个简洁优雅的界面，让用户可以轻松地分享和管理文本内容。

## 项目说明

- 项目使用 [Vite](https://vitejs.dev/) 构建，使用纯 JavaScript 开发。
- 后端使用 [Cloudflare Workers](https://workers.cloudflare.com/) 提供服务。
- 项目使用原生 CSS 进行样式设计，简洁优雅。

## ✨ 功能特点

### 编辑器功能
- 📝 强大的 Markdown 编辑器
  - 支持所有常用 Markdown 语法
  - 代码块语法高亮
  - 表格编辑支持
  - 数学公式渲染
  - 图片上传和链接插入
  - 快捷键支持

### 主题与界面
- 🎨 智能主题系统
  - 自动跟随系统主题切换
  - 可手动切换明亮/暗黑主题
  - 平滑过渡动画效果
  - 护眼配色方案
- 📱 全面响应式设计
  - 完美支持移动端浏览
  - 自适应各种屏幕尺寸
  - 触摸屏优化体验

### 分享功能
- 🔗 多样化分享选项
  - 一键生成分享链接
  - 二维码分享支持
  - 社交媒体分享集成
- 👀 隐私保护设置
  - 自定义访问次数限制
  - 内容过期时间设置
  - 密码保护选项
  - 阅后即焚模式

### 导出与备份
- 📤 多格式导出支持
  - 导出为 PDF 文档
  - 导出为 PNG 图片
  - 导出为纯文本文件
  - 保持样式一致性
- 💾 数据安全保障
  - 自动保存功能
  - 历史版本记录
  - 云端同步备份

### 性能优化
- ⚡ 极致性能体验
  - 快速加载和渲染
  - 实时预览无延迟
  - 离线编辑支持
  - CDN 加速分发

## 🚀 快速开始


### 环境要求

- Node.js >= 16
- npm >= 7
- Wrangler CLI (Cloudflare Workers 命令行工具)

## ✨ 功能特点

- 🎨 支持自动/明亮/暗黑主题切换
- 📝 Markdown 编辑器，支持实时预览
- 👀 访问次数限制功能
- ⏰ 内容过期时间设置
- 📱 响应式设计，支持移动端
- 🔗 生成分享链接和二维码
- 📤 导出为 PDF/PNG 格式
- 🛡️ 安全的文本存储

## 📦 部署指南

### 🚀 一键部署 (Cloudflare Worker)

1. 点击下方按钮，将项目一键部署到 Cloudflare Workers：

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/shan-hee/CloudPaste-SH)

2. 登录你的 Cloudflare 账号
3. 选择要部署的组织和项目名称
4. 等待部署完成
5. 部署完成后，你会获得一个 `*.workers.dev` 域名

### 👷 自动部署 (GitHub Actions)

1. Fork 本仓库到你的 GitHub 账号

2. 配置 Cloudflare 凭据：
   - 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
   - 进入 "Workers & Pages" 
   - 创建新的 API Token，确保有 Workers 部署权限
   - 记录你的 Account ID

3. 在 GitHub 仓库设置中添加 Secrets：
   - 进入仓库的 Settings > Secrets and variables > Actions
   - 添加以下 secrets：
     ```
     CLOUDFLARE_API_TOKEN = "你的 API Token"
     CLOUDFLARE_ACCOUNT_ID = "你的 Account ID"
     ```

4. 自动部署触发条件：
   - 推送代码到 `main` 分支
   - 手动在 Actions 页面触发
   - 通过 API 触发部署

### 🔧 手动部署

#### Cloudflare Worker 部署

1. 安装 Wrangler CLI
```bash
npm install -g wrangler
```

2. 登录到 Cloudflare
```bash
wrangler login
```

3. 克隆项目并安装依赖
```bash
git clone https://github.com/shan-hee/CloudPaste-SH.git
cd CloudPaste-SH
npm install
```

4. 修改 `wrangler.toml` 配置
```toml
name = "你的项目名称"
account_id = "你的 ACCOUNT ID"
```

5. 部署到 Cloudflare Workers
```bash
npm run deploy
```

#### Docker 部署 (自托管服务器)

1. 安装 Docker 和 Docker Compose

2. 创建 docker-compose.yml：
```yaml
version: '3'
services:
  cloudpaste:
    image: cloudpaste-sh
    build: .
    ports:
      - "8787:8787"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=sqlite://data/cloudpaste.db
    volumes:
      - ./data:/app/data
```

3. 构建并启动容器：
```bash
docker-compose up -d
```

4. 访问 `http://你的服务器IP:8787` 即可使用

### 🔍 部署后配置

1. 访问 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 "Workers & Pages" 部分
3. 找到你部署的项目
4. 可以在这里进行以下配置：
   - 自定义域名绑定
   - 环境变量设置
   - 访问分析
   - 其他高级设置

## 🔧 配置说明

主要配置项包括：

- `PORT`: 服务器端口号
- `DATABASE_URL`: 数据库连接地址
- `STORAGE_TYPE`: 存储类型（本地/云存储）
- `MAX_FILE_SIZE`: 最大文件大小限制

## 🌟 主要特性说明

### Markdown 编辑器

- 支持常用 Markdown 语法
- 工具栏快捷操作
- 实时预览
- 代码高亮显示

### 主题切换

- 自动跟随系统主题
- 手动切换明亮/暗黑主题
- 平滑过渡动画

### 分享功能

- 生成分享链接
- 二维码分享
- 访问次数限制
- 过期时间设置

### 导出功能

- 支持导出为 PDF
- 支持导出为 PNG 图片
- 保持样式一致性

## 📝 开发说明

### 项目结构

```
CloudPaste-SH/
├── public/          # 静态资源
├── src/             # Worker 源码
├── wrangler.toml    # Cloudflare Workers 配置
├── server/          # 服务端代码
├── src/             # 客户端源码
├── tests/           # 测试文件
└── package.json     # 项目配置
```

### 技术栈

- 前端：HTML5, CSS3, JavaScript (原生)
- 后端：Cloudflare Workers
- 部署：Cloudflare Pages + Workers
- 存储：MongoDB/SQLite

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。在提交 PR 之前，请确保：

1. 代码风格符合项目规范
2. 添加必要的测试用例
3. 更新相关文档

## 📄 许可证

本项目采用 [MIT](LICENSE) 许可证。

## 🙏 致谢

感谢所有为这个项目做出贡献的开发者。

## 感谢原作者

感谢原作者 [ling-drag0n](https://github.com/ling-drag0n) 的贡献。

