# 服务器运行目录约定

推荐把源码仓库和运行目录分开，但如果希望在仓库根目录内直接管理运行产物，可以使用 `server/` 目录承载所有运行时文件。

## 目录约定

在仓库根目录下使用如下结构：

```text
rust_waf/
  target/
  server/
    waf
    data/
    logs/
```

其中：

- `server/waf` 是编译后的可执行文件
- `server/data/` 存放 SQLite、HTTP/3 托管证书等运行时数据
- `server/logs/` 可选，用于存放重定向日志

`server/` 已加入 Git 忽略列表，不会被 `git pull`、`git status` 跟踪。

## 关键注意事项

程序当前默认使用相对路径：

- SQLite 默认路径：`data/waf.db`
- HTTP/3 托管证书默认路径：`data/http3/managed/`

因此必须在 `server/` 目录内启动程序：

```bash
cd /path/to/rust_waf/server
./waf
```

如果在仓库根目录执行 `./server/waf`，数据会落到仓库根目录的 `data/`，而不是 `server/data/`。

## 推荐更新流程

```bash
cd /path/to/rust_waf
git pull
cargo build --release
mkdir -p server/data server/logs
install -m 755 target/release/waf server/waf
cd server
./waf
```

如果使用 systemd，请确保配置：

- `WorkingDirectory=/path/to/rust_waf/server`
- `ExecStart=/path/to/rust_waf/server/waf`

这样数据库、证书、缓存等文件都会稳定落在 `server/` 目录下。
