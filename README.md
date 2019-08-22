# Encrypted-chat-room

## 服务器-客户端
RSA + DH + AES-GCM

## 客户端-客户端

DH + AES-CBC

### 更多细节待补充

## 运行
安装依赖
```sh
python -m pip install -r requirements.txt
```

运行服务器
```sh
python server_main.py
```

运行客户端 (因为 quamash 对 Windows 兼容性不好, 所以只能在 Linux/MacOS 上运行)
```sh
python client_main.py
```
