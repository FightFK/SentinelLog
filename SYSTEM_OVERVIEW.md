# 🎯 SentinelLog - Revamped System

## ✨ Simple & Clean Architecture

### **Core Concept**
```
Raw NGINX Log → Parse → Embedding → Vector Search
    ↓
Found Similar? 
    YES → Auto-apply previous action ✅
    NO  → LLM Analysis → Admin Decision ⏳
```

---

## 📊 Database Models (6 Tables Only)

### **1. SecurityLog** - Main log storage
```
- id, timestamp, source, severity, eventType
- description, ipAddress, userAgent, rawLog
- metadata (JSON), embedding (Vector)
```

### **2. AnalysisResult** - LLM analysis results
```
- id, logId, result (JSON), confidence
- threatLevel, analyzedAt
```

### **3. PendingAdminDecision** - Awaiting admin (PATH B)
```
- id, logId, analysisId, threatLevel
- analysis (JSON), status, createdAt, resolvedAt
```

### **4. AdminDecision** - Admin's choices (Learning source)
```
- id, logId, pendingId, action
- reason, duration, threatLevel
- analysisData (JSON), decidedAt
```

### **5. AutoAppliedRule** - Auto-applied actions (PATH A)
```
- id, logId, sourceDecisionId, sourceLogId
- similarity, actionTaken, executedAt
```

### **6. BlockedIP** - IP blocking management
```
- id, ipAddress, blockedAt, expiresAt
- reason, active
```

---

## 🔄 Processing Flow

### **Input Format**
```json
POST /api/webhook/nginx
{
  "raw_log": "192.168.1.100 - - [31/Jan/2026:10:30:45 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 403 1234 \"-\" \"Mozilla/5.0\""
}
```

### **STEP 1: Parse & Enrich**
- Parse NGINX format
- Detect attack patterns (SQL injection, XSS, Path Traversal, etc.)
- Assign severity & event_type
- Detect brute force (5 attempts in 5 mins)

### **STEP 2: Save & Embed**
- Save to `SecurityLog`
- Generate text embedding (OpenAI/OpenRouter)
- Store embedding for vector search

### **STEP 3: Vector Search**
- Find similar logs using cosine similarity
- Threshold: 85% (configurable)

### **STEP 4: Decision Path**

#### **PATH A: Auto-Apply (Similarity ≥ 85%)**
```
1. Find AdminDecision from similar log
2. Execute same action (block/monitor/alert/ignore)
3. Save to AutoAppliedRule
4. Done ✅
```

**Response:**
```json
{
  "status": "auto_applied",
  "log_id": 123,
  "action": "block",
  "similarity": 0.92,
  "message": "✅ 'block' auto-applied (92.0% match)"
}
```

#### **PATH B: Admin Decision (Similarity < 85%)**
```
1. Run LLM analysis (threat level, attack type, recommendations)
2. Save to AnalysisResult
3. Create PendingAdminDecision
4. Notify admin (console/email/Slack)
5. Wait for admin ⏳
```

**Response:**
```json
{
  "status": "pending_admin_decision",
  "log_id": 124,
  "pending_decision_id": 50,
  "threat_level": "MEDIUM",
  "llm_analysis": { ... },
  "admin_url": "/api/admin/decide/50"
}
```

---

## 🔌 API Endpoints

### **Webhook (Receive Logs)**
```
POST /api/webhook/nginx           - Single raw log
POST /api/webhook/nginx/batch     - Multiple raw logs
```

### **Admin (Decision Making)**
```
GET  /api/admin/pending           - Get pending decisions
POST /api/admin/decide/:id        - Make decision
GET  /api/admin/decisions         - Decision history
GET  /api/admin/learned-rules     - Auto-applied rules stats
```

### **Logs (Management)**
```
GET    /api/logs                  - List logs (with filters)
GET    /api/logs/:id              - Get specific log
POST   /api/logs                  - Create log manually
DELETE /api/logs/:id              - Delete log
GET    /api/logs/stats            - Log statistics
```

### **Analysis (AI)**
```
POST /api/analysis/analyze        - Analyze single log
POST /api/analysis/batch          - Batch analyze
GET  /api/analysis/similar/:id    - Find similar logs
GET  /api/analysis/results/:id    - Get analysis results
GET  /api/analysis/threats        - Threat summary
```

---

## 🎮 Admin Decision Flow

### **1. Get Pending Decisions**
```bash
GET /api/admin/pending
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": 50,
      "logId": 124,
      "threatLevel": "MEDIUM",
      "analysis": {
        "threat_level": "MEDIUM",
        "attack_type": "Brute Force",
        "confidence": 75.5,
        "recommendations": ["Monitor", "Consider blocking"]
      },
      "log": {
        "ipAddress": "192.168.1.100",
        "eventType": "brute_force",
        "rawLog": "..."
      }
    }
  ]
}
```

### **2. Make Decision**
```bash
POST /api/admin/decide/50
{
  "action": "block",
  "reason": "Multiple failed login attempts",
  "duration": 3600
}
```

**Actions:**
- `block` - Block IP (requires duration in seconds)
- `monitor` - Increase monitoring
- `alert` - Alert only
- `ignore` - Mark as safe

### **3. System Learns**
- Decision saved to `AdminDecision`
- Future similar logs → Auto-apply same action

---

## 🧠 Attack Detection Patterns

### **SQL Injection**
```
union select, or '1'='1, drop table, insert into, etc.
```

### **XSS**
```
<script>, javascript:, onerror=, onload=, <iframe>
```

### **Path Traversal**
```
../, ..\, %2e%2e/, etc.
```

### **Command Injection**
```
; ls, | cat, `command`, $(command)
```

### **Brute Force**
```
5+ failed auth attempts within 5 minutes (same IP)
```

---

## 📦 Services

### **1. logParserService.js**
- Parse NGINX raw log format
- Detect attack patterns
- Assign severity & event_type

### **2. autoProcessingService.js**
- Main processing flow
- Vector search & decision logic
- Brute force detection

### **3. aiAnalysisService.js**
- LLM analysis (OpenRouter/OpenAI)
- Generate embeddings
- Find similar logs (vector search)

### **4. securityResponseService.js**
- Execute actions (block, monitor, alert)
- Manage BlockedIP table

---

## 🚀 Quick Start

### **1. Send a raw log**
```bash
curl -X POST http://localhost:3000/api/webhook/nginx \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log": "192.168.1.100 - - [31/Jan/2026:10:30:45 +0000] \"GET /api/users?id=1' OR '\''1'\''='\''1 HTTP/1.1\" 403"
  }'
```

### **2. Check pending decisions**
```bash
curl http://localhost:3000/api/admin/pending
```

### **3. Make a decision**
```bash
curl -X POST http://localhost:3000/api/admin/decide/50 \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "duration": 3600,
    "reason": "SQL injection attempt"
  }'
```

### **4. Next similar log → Auto-blocked!** ✅

---

## 🎯 Key Features

✅ **Automatic Pattern Detection** - Parse raw logs & detect attacks
✅ **Vector Similarity Search** - Find similar past incidents  
✅ **AI-Powered Analysis** - LLM analyzes new patterns
✅ **Learning System** - Auto-apply past admin decisions
✅ **Brute Force Detection** - Track failed auth attempts
✅ **Simple Architecture** - Only 6 database tables
✅ **Clean API** - RESTful endpoints
✅ **Production Ready** - PostgreSQL + pgvector

---

## 🔧 Configuration

### **Similarity Threshold**
```javascript
// autoProcessingService.js
this.similarityThreshold = 0.85; // 85% similarity
```

### **Brute Force Settings**
```javascript
this.bruteForceThreshold = 5;      // 5 attempts
this.bruteForceWindow = 300000;    // 5 minutes
```

### **LLM Provider**
```env
# .env
OPENROUTER_API_KEY=your_key
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
```

---

## 📝 TODO for Production

- [ ] Real admin notifications (Email, Slack, SMS)
- [ ] IP whitelist management
- [ ] Metrics & dashboards
- [ ] Rate limiting per endpoint
- [ ] Audit logging
- [ ] API authentication
- [ ] Docker deployment
- [ ] CI/CD pipeline

---

## 💡 System Benefits

1. **Fast Response** - Auto-apply known actions instantly
2. **Learning** - Gets smarter with each admin decision
3. **Simple** - Only 6 tables, clean code
4. **Scalable** - Vector search for millions of logs
5. **Accurate** - AI-powered threat analysis
6. **Maintainable** - Clear separation of concerns

---

Built with ❤️ using Express.js, PostgreSQL, pgvector, and OpenRouter/OpenAI
