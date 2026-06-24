# probe

轻量级 Linux 系统资源监控面板，单文件 Go 二进制，端口 8082，SQLite 存储，内置登录认证。

## 功能

- **CPU 使用率** — `/proc/stat` 差值计算，每 10 秒刷新
- **内存使用** — `/proc/meminfo`，available 算法
- **磁盘使用** — 根分区容量
- **网络流量**（高精度）
  - 读取 `/proc/net/dev`，逐字节累计 delta
  - 10 秒采样粒度，按天 / 按月聚合
  - 计数器回绕检测（重启不丢不错）
  - 每月 1 号自动清零，每日自动清零
  - 自动过滤虚拟网卡（docker、libvirt、隧道等）
- **Web 面板** — 内嵌 HTML + Chart.js 图表
- **登录认证** — bcrypt 密码哈希，Session Token（24h 过期）
- **在线修改密码** — 面板顶部入口或 API 调用
- **零外部依赖** — CGO_ENABLED=0 纯静态编译，scp 上去就能跑

## 截图

```
┌─────────┬─────────┬─────────┬─────────┐
│  CPU    │  内存   │  磁盘   │ 本月流量 │
└─────────┴─────────┴─────────┴─────────┘

┌──────────────────┐ ┌──────────────────┐
│  本月每日流量     │ │  历史月度流量     │
│  (柱状图)        │ │  (柱状图)        │
└──────────────────┘ └──────────────────┘

┌──────────────────┐ ┌──────────────────┐
│  每日流量明细     │ │  月度流量统计     │
│  表格            │ │  表格            │
└──────────────────┘ └──────────────────┘
```

## 快速开始

### 下载二进制

从 [Releases](../../releases) 下载对应架构的 `probe` 二进制：

```bash
# amd64
wget https://github.com/xxx/probe/releases/latest/download/probe-linux-amd64 -O /root/probe/probe
chmod +x /root/probe/probe

# arm64
wget https://github.com/xxx/probe/releases/latest/download/probe-linux-arm64 -O /root/probe/probe
chmod +x /root/probe/probe
```

### 手动编译

```bash
git clone https://github.com/xxx/probe.git
cd probe
CGO_ENABLED=0 go build -ldflags="-s" -o probe main.go
```

### 运行

```bash
# 直接运行
./probe

# systemd 开机自启（推荐）
cat > /etc/systemd/system/probe.service << 'EOF'
[Unit]
Description=Probe System Monitor
After=network.target

[Service]
Type=simple
ExecStart=/root/probe/probe
WorkingDirectory=/root/probe
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now probe
```

访问 `http://<服务器IP>:8082`，默认账号 `admin` / `admin`。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PROBE_LISTEN` | `:8082` | 监听地址 |
| `PROBE_PASSWORD` | `admin` | 默认管理员密码 |
| `PROBE_DB` | `/root/probe/probe.db` | SQLite 数据库路径 |

## API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/status` | GET | CPU / 内存 / 磁盘 / 本月流量 |
| `/api/traffic/daily` | GET | 当月每日流量 (`?month=YYYY-MM`) |
| `/api/traffic/history` | GET | 最近 12 个月流量汇总 |
| `/api/change-password` | POST | 修改密码 (`{"old_password":"...","new_password":"..."}`) |

## 技术栈

- Go 1.24+
- SQLite (pure-Go via modernc.org/sqlite)
- bcrypt (golang.org/x/crypto)
- Chart.js 4 (CDN，前端图表)

## License

MIT
