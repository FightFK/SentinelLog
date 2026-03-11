# 🔄 Auto-Processing Workflow with Admin Learning

## Flow การทำงาน:

```
Nginx Server → Webhook → Auto Processing → Decision Flow
                             ↓
                   1. สร้าง Log + Embedding
                             ↓
                   2. หา Similar Logs
                             ↓
                ┌────────────┴────────────┐
                │                         │
           ใกล้เคียง                  ไม่ใกล้เคียง
          (≥ 85%)                    (< 85%)
                │                         │
                ↓                         ↓
        มี Admin Rule?           วิเคราะห์ด้วย AI
                │                         │
           ใช่  │  ไม่ใช่                 ↓
                │                   อันตรายสูง?
                ↓                         │
        ทำตาม Rule             ใช่  │      │  ไม่ใช่
        อัตโนมัติ                   │      │
                                    ↓      ↓
                              แจ้ง Admin   แค่บันทึก
                                    │
                              Admin ตัดสินใจ
                              (block/monitor/ignore)
                                    │
                              บันทึกเป็น Rule
                                    │
                              ครั้งถัดไปใช้อัตโนมัติ
```

## 🚀 API Endpoints:

### 1. Webhook - รับ Nginx Logs

```bash
# รับ log เดียว
POST /api/webhook/nginx
Content-Type: application/json

{
  "remote_addr": "192.168.1.100",
  "time_local": "22/Jan/2026:10:30:15 +0000",
  "request": "GET /admin/login?user=admin' OR '1'='1 HTTP/1.1",
  "status": 403,
  "body_bytes_sent": 162,
  "http_referer": "-",
  "http_user_agent": "Mozilla/5.0",
  "request_time": 0.123
}

# รับหลาย logs พร้อมกัน
POST /api/webhook/nginx/batch
Content-Type: application/json

{
  "logs": [
    { "remote_addr": "...", ... },
    { "remote_addr": "...", ... }
  ]
}
```

### 2. Admin Dashboard - ดูรายการรอตัดสินใจ

```bash
# ดูรายการที่รอ Admin ตัดสินใจ
GET /api/admin/pending?limit=50

Response:
{
  "success": true,
  "data": [
    {
      "id": 1,
      "log_id": 123,
      "threat_level": "HIGH",
      "analysis": {
        "threat_level": "HIGH",
        "attack_type": "SQL Injection",
        "summary": "Detected SQL injection attempt...",
        "recommendations": ["Block IP", "Review logs"]
      },
      "status": "pending",
      "created_at": "2026-01-22T10:30:00Z",
      "log": {
        "ip_address": "192.168.1.100",
        "description": "SQL injection attempt"
      }
    }
  ]
}
```

### 3. Admin Decision - ตัดสินใจ

```bash
# Admin เลือกว่าจะทำอะไร
POST /api/admin/decide/:alert_id
Content-Type: application/json

{
  "action": "block",          # block, monitor, alert, ignore
  "reason": "SQL injection confirmed",
  "duration": 3600            # seconds (สำหรับ block)
}

Response:
{
  "success": true,
  "data": {
    "decision": { ... },
    "execution": {
      "action": "block_ip",
      "status": "success",
      "target": "192.168.1.100",
      "expires_at": "2026-01-22T11:30:00Z"
    },
    "message": "Action 'block' executed successfully. System will learn from this decision."
  }
}
```

### 4. ดูประวัติการตัดสินใจ

```bash
# ดู admin decisions ทั้งหมด
GET /api/admin/decisions?limit=100

# ดูสถิติ learned rules
GET /api/admin/learned-rules

Response:
{
  "success": true,
  "data": {
    "statistics": [
      { "action": "block", "count": 45 },
      { "action": "monitor", "count": 23 },
      { "action": "ignore", "count": 12 }
    ],
    "recent_applications": [...]
  }
}
```

## 📝 ตัวอย่างการใช้งาน:

### Scenario 1: Log ใหม่ที่ไม่เคยเจอ (อันตราย)

```bash
# 1. Nginx ส่ง log มา
curl -X POST http://localhost:3000/api/webhook/nginx \
  -H "Content-Type: application/json" \
  -d '{
    "remote_addr": "192.168.1.100",
    "request": "GET /admin?id=1 OR 1=1",
    "status": 403
  }'

# Response: รอ admin ตัดสินใจ
{
  "status": "pending_admin_decision",
  "alert_id": 1,
  "threat_level": "HIGH",
  "message": "High risk detected. Waiting for admin decision."
}

# 2. Admin ตรวจสอบและตัดสินใจ
curl -X POST http://localhost:3000/api/admin/decide/1 \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "reason": "Confirmed SQL injection attack",
    "duration": 7200
  }'

# 3. ระบบ block IP และบันทึกเป็น rule
```

### Scenario 2: Log ที่เคยเจอ (มี rule แล้ว)

```bash
# Nginx ส่ง log ที่คล้ายกับที่เคยเจอ
curl -X POST http://localhost:3000/api/webhook/nginx \
  -H "Content-Type: application/json" \
  -d '{
    "remote_addr": "192.168.1.200",
    "request": "GET /admin?id=2 OR 2=2",
    "status": 403
  }'

# Response: ทำตาม rule อัตโนมัติทันที
{
  "status": "auto_processed",
  "action": "block",
  "similarity": 0.92,
  "learned_from": 123,
  "message": "IP blocked automatically based on learned rule"
}
```

## 🔧 การตั้งค่า Nginx ให้ส่ง Logs:

### ใน nginx.conf:

```nginx
http {
    log_format json_combined escape=json
    '{'
        '"remote_addr":"$remote_addr",'
        '"time_local":"$time_local",'
        '"request":"$request",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent",'
        '"request_time":$request_time'
    '}';

    server {
        access_log /var/log/nginx/access.log json_combined;
        
        # ส่ง logs ไป SentinelLog (ใช้ log processor)
    }
}
```

### ใช้ Filebeat หรือ Logstash ส่ง logs:

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
  json.keys_under_root: true

output.http:
  hosts: ["http://localhost:3000"]
  path: "/api/webhook/nginx/batch"
  method: "POST"
```

## 📊 Admin Actions:

1. **block** - แบน IP ตามระยะเวลาที่กำหนด
2. **monitor** - เพิ่มการเฝ้าระวัง ไม่แบน
3. **alert** - แค่แจ้งเตือน ไม่ทำอะไร
4. **ignore** - เป็น false positive ไม่ต้องสนใจ

## 🧠 ระบบเรียนรู้:

- ระบบจะจำการตัดสินใจของ Admin
- เมื่อเจอ pattern คล้ายกัน (similarity ≥ 85%)
- จะทำตาม action ที่ Admin เคยเลือกไว้อัตโนมัติ
- ลดภาระการตัดสินใจซ้ำๆ ของ Admin

## 🎯 Benefits:

✅ ประมวลผล logs อัตโนมัติแบบ real-time  
✅ ตรวจจับภัยคุกคามใหม่ด้วย AI  
✅ Admin ตัดสินใจเฉพาะกรณีใหม่  
✅ ระบบเรียนรู้และทำงานอัตโนมัติมากขึ้นเรื่อยๆ  
✅ ลด false positives จากการเรียนรู้  

---

**ขั้นตอนการใช้งาน:**

```bash
# 1. Update database schema
npm run prisma:generate
npm run prisma:migrate

# 2. เริ่มใช้งาน
npm run dev

# 3. ตั้งค่า Nginx ให้ส่ง logs มาที่
POST http://localhost:3000/api/webhook/nginx
```
