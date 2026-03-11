#!/bin/sh
# ──────────────────────────────────────────────────────────────────
# Docker Entrypoint สำหรับ SentinelLog Agent
#
# Logic:
#   - ถ้า AGENT_ID ว่าง → รัน --register ก่อน แล้ว start agent
#   - ถ้า AGENT_ID มีค่าแล้ว → start agent เลย
# ──────────────────────────────────────────────────────────────────
set -e

# รอ backend พร้อม (retry ทุก 5s สูงสุด 60 ครั้ง = 5 นาที)
echo "⏳ Waiting for backend at $BACKEND_URL ..."
RETRIES=60
while [ $RETRIES -gt 0 ]; do
  if wget -q --spider "$BACKEND_URL/health" 2>/dev/null; then
    echo "✅ Backend is ready"
    break
  fi
  RETRIES=$((RETRIES - 1))
  echo "   Not ready yet ($RETRIES retries left)..."
  sleep 5
done

if [ $RETRIES -eq 0 ]; then
  echo "❌ Backend did not become ready in time. Exiting."
  exit 1
fi

# ถ้ายังไม่มี AGENT_ID → register ก่อน
if [ -z "$AGENT_ID" ]; then
  echo "📝 No AGENT_ID found — registering agent..."
  python sentinel_agent.py --register
  # โหลด .env ใหม่หลัง register
  export $(grep -v '^#' .env | xargs)
  echo "✅ Registration complete. AGENT_ID=$AGENT_ID"
fi

echo "🚀 Starting SentinelLog Agent..."
exec python -u sentinel_agent.py
