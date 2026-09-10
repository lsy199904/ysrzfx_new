# SIEM Agent 容器化部署指南

## 一、部署架构

```
本地主机 → 跳板机 (203.85.9.162:58001) → 目标主机 (192.168.101.110)
```

## 二、容器配置信息

| 项目 | 配置 |
|------|------|
| 容器名称 | `siem` |
| Python 版本 | 3.11.14 |

## 三、端口映射配置（宿主机:容器）

| 宿主机端口 | 容器端口 | 说明 |
|-----------|---------|------|
| 5050 | 8000 | Agent Chat 服务 |
| 5051 | 8001 | 预留服务端口 1 |
| 5052 | 8002 | 预留服务端口 2 |
| 5053 | 8003 | 预留服务端口 3 |
| 5054 | 8004 | 预留服务端口 4 |
| 6379 | 6379 | Redis 服务 |

## 四、目录挂载

| 宿主机目录 | 容器目录 | 说明 |
|-----------|---------|------|
| /data1/sylvanli/ysrzfx | /app | 代码和项目目录 |

## 五、部署步骤

### 步骤 1：在目标主机打包 Docker 镜像

```bash
# 进入项目目录
cd /data1/sylvanli/ysrzfx

#创建打包目录
mkdir -p enviroment

#1. 保存容器为镜像
docker commit siem siem-python311-full:latest

#2. 导出镜像并压缩
docker save siem-python311-full:latest > enviroment/siem-python311-full.tar.gz
gzip -f enviroment/siem-python311-full.tar

#3. 打包代码目录（包含虚拟环境、数据、模型等）
tar -czf enviroment/ysrzfx-full.tar.gz code/ data/ hf_cache/ dump.rdb ysrzfx_new/ run.sh Dockerfile README.md

#查看打包结果
ls -lh enviroment/
```

**打包内容说明：**

| 文件 | 大小 | 内容 |
|------|------|------|
| `siem-python311-full.tar.gz` | 约 11GB | Docker 镜像（系统环境、Python、Redis等） |
| `ysrzfx-full.tar.gz` | 视内容而定 | 代码、数据、模型缓存、虚拟环境等 |

### 步骤 2：传输打包文件到跳板机

#在本地主机执行：

```bash
```

### 步骤 2：传输镜像到跳板机

在本地主机执行：

```bash
# 传输镜像到跳板机
# 本地直接拖拉拽

```

### 步骤 3：从跳板机传输到目标主机

登录跳板机后执行：

```bash
# 从跳板机传输到目标主机 (192.168.101.110)
scp -P 22 /home/sylvanli/ysrzfx/enviroment/siem-python311-full.tar.gz sylvanli@192.168.101.110:/data1/sylvanli/ysrzfx/

scp -P 22 /home/sylvanli/ysrzfx/enviroment/ysrzfx-full.tar.gz sylvanli@192.168.101.110:/data1/sylvanli/ysrzfx/
```

### 步骤 4：验证文件完整性

在目标主机执行：

```bash
# 计算 SHA256 校验和
sha256sum siem-python311.tar.gz

# 预期值（与本地一致表示文件未损坏）：
# 203b6cae528b66e95560a68e3a54f62de5041b3b372cae50d5ef0b85d8ca7cdf
```

### 步骤 5：加载 Docker 镜像

在目标主机执行：

```bash
# 加载镜像
docker load < siem-python311-full.tar.gz

# 验证镜像

docker images | grep siem-python311-full
```

### 步骤 6：启动容器

```bash
# 停止并删除已存在的容器（如果有）
docker rm -f siem 2>/dev/null

# 启动容器
docker run -d \
  --name siem \
  --network siem-network \
  --ip 172.30.0.10 \
  -p 5050:8000 \
  -p 5051:8001 \
  -p 5052:8002 \
  -p 5053:8003 \
  -p 5054:8004 \
  -p 6379:6379 \
  -v /data1/sylvanli/ysrzfx:/app \
  -w /app \
  siem-python311:latest \
  bash -c "
    # 安装 Python 依赖到容器虚拟环境
    echo '安装 Python 依赖...'
    source /opt/venv/bin/activate
    pip install --upgrade pip
    pip install -r /app/requirements.txt
    echo '依赖安装完成'
    
    # 启动 Redis 服务
    redis-server --daemonize yes
    sleep 1
    echo 'Redis 服务已启动'
    
    # 保持容器运行
    tail -f /dev/null
  "
```

### 步骤 7：验证服务

```bash
# 检查容器状态
docker ps | grep siem

# 查看日志
docker logs -f siem

# 测试接口
curl http://localhost:5050/docs
```

## 六、常用管理命令

```bash
# 进入容器
docker exec -it siem bash

# 查看所有容器
docker ps -a | grep siem

# 停止容器
docker stop siem

# 启动容器
docker start siem

# 重启容器
docker restart siem

# 删除容器
docker rm -f siem

# 查看容器日志
docker logs siem

# 实时查看日志
docker logs -f siem

# 查看容器 IP
docker inspect siem --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

## 七、常见问题

### Q1: 权限问题

```bash
# 如果遇到 permission denied 错误，使用 sudo
sudo docker load < siem-python311.tar.gz
sudo docker run ...
```

### Q2: 端口被占用

```bash
# 检查端口占用
netstat -tlnp | grep 5050

# 修改映射端口
docker run -d -p 5060:8000 ...  # 使用其他宿主机端口
```

### Q3: 文件校验失败

如果 SHA256 校验和不匹配，说明文件在传输过程中损坏，需要重新传输。

### Q4: 虚拟环境路径

```bash
# 如果提示虚拟环境不存在，检查路径
ls -la /app/ysrzfx_new/

# 如果虚拟环境损坏，重新创建
docker exec -it siem-agent bash -c "
  cd /app
  python3 -m venv ysrzfx_new
  source ysrzfx_new/bin/activate
  pip install -r core_files/requirements_working.txt
"
```

## 八、镜像信息

| 项目 | 值 |
|------|-----|
| 镜像名称 | siem-python311:latest |
| 镜像大小 | 585MB（解压后）|
| 压缩后大小 | 193MB |
| SHA256 校验和 | `203b6cae528b66e95560a68e3a54f62de5041b3b372cae50d5ef0b85d8ca7cdf` |
| Python 版本 | 3.11.14 |
| 架构 | amd64 |
| 包含组件 | Python 3.11.14, Redis, 所有依赖包，BERT 模型 |