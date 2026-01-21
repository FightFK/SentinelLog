"# SentinelLog

AI-powered Security Log Analysis System using Express.js, PostgreSQL with pgvector, and OpenAI.

## Features

- 📝 Security log management (CRUD operations)
- 🤖 AI-powered log analysis using OpenAI GPT-4
- 🔍 Vector similarity search for finding related security incidents
- 📊 Real-time threat assessment and statistics
- 🛡️ Rate limiting and security headers
- 📈 Comprehensive logging with Winston
- 🐳 Docker support with PostgreSQL + pgvector

## Tech Stack

- **Backend**: Express.js 5.x
- **Database**: PostgreSQL with pgvector extension
- **ORM**: Prisma 5.x
- **AI/ML**: OpenAI GPT-4, text-embedding-ada-002
- **Security**: Helmet, CORS, express-rate-limit
- **Logging**: Winston
- **Development**: Nodemon

## Prerequisites

- Node.js (v18 or higher)
- Docker and Docker Compose
- OpenAI API Key

## Installation

1. Clone the repository:
```bash
git clone git@github.com:FightFK/SentinelLog.git
cd SentinelLog
```

2. Install dependencies:
```bash
npm install
# or
yarn install
```

3. Configure environment variables:
```bash
cp .envsample .env
```

Edit `.env` file with your configurations:
```env
PORT=3000
DATABASE_URL=postgres://chinnapong_admin:admin1234@localhost:5432/security_logs_db
OPENAI_API_KEY=your_openai_api_key_here

DB_USER=chinnapong_admin
DB_PASSWORD=admin1234
DB_NAME=security_logs_db
```

4. Start PostgreSQL with pgvector using Docker:
```bash
npm run docker:up
# or
docker-compose up -d
```

5. Generate Prisma Client and run migrations:
```bash
npm run prisma:generate
npm run prisma:migrate
# or use the combined command
npm run init-db
```

6. (Optional) Seed the database with sample data:
```bash
npm run prisma:seed
```

7. Start the development server:
```bash
npm run dev
```

The server will start on `http://localhost:3000`

## API Endpoints

### Health Check
- `GET /health` - Check API health status

### Security Logs
- `POST /api/logs` - Create a new security log
- `GET /api/logs` - Get all logs (with filtering and pagination)
- `GET /api/logs/:id` - Get a specific log by ID
- `GET /api/logs/stats` - Get log statistics
- `DELETE /api/logs/:id` - Delete a log

### AI Analysis
- `POST /api/analysis/analyze` - Analyze a single log
- `POST /api/analysis/batch` - Batch analyze multiple logs
- `GET /api/analysis/similar/:log_id` - Find similar logs using vector search
- `GET /api/analysis/results/:log_id` - Get analysis results for a log
- `GET /api/analysis/threats` - Get threat summary
- `POST /api/analysis/embedding` - Update log embedding

## API Usage Examples

### Create a Security Log
```bash
curl -X POST http://localhost:3000/api/logs \
  -H "Content-Type: application/json" \
  -d '{
    "source": "firewall",
    "severity": "HIGH",
    "event_type": "unauthorized_access",
    "description": "Multiple failed login attempts detected",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "raw_log": "Failed login attempt from 192.168.1.100",
    "metadata": {
      "attempts": 5,
      "username": "admin"
    }
  }'
```

### Analyze a Log
```bash
curl -X POST http://localhost:3000/api/analysis/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_id": 1
  }'
```

### Get Log Statistics
```bash
curl "http://localhost:3000/api/logs/stats?start_date=2026-01-01&end_date=2026-01-31"
```

### Find Similar Logs
```bash
curl "http://localhost:3000/api/analysis/similar/1?limit=5"
```

## Project Structure

```
SentinelLog/
├── config/
│   └── database.js          # Database configuration and initialization
├── controllers/
│   ├── logController.js     # Security logs CRUD operations
│   └── analysisController.js # AI analysis operations
├── middleware/
│   ├── errorHandler.js      # Error handling middleware
│   ├── logger.js            # Winston logger configuration
│   └── rateLimiter.js       # Rate limiting middleware
├── routes/
│   ├── logs.js              # Security logs routes
│   └── analysis.js          # Analysis routes
├── services/
│   └── aiAnalysisService.js # AI analysis service with OpenAI
├── scripts/
│   └── initDatabase.js      # Database initialization script
├── logs/                     # Application logs directory
├── .env                      # Environment variables
├── .envsample               # Environment variables template
├── docker-compose.yml       # Docker compose configuration
├── index.js                 # Main application entry point
└── package.json             # Project dependencies
```

## Database Schema

### security_logs
- `id`: Serial primary key
- `timestamp`: Log timestamp
- `source`: Log source (firewall, IDS, etc.)
- `severity`: Severity level (HIGH, MEDIUM, LOW)
- `event_type`: Type of security event
- `description`: Event description
- `ip_address`: Source IP address
- `user_agent`: User agent string
- `raw_log`: Raw log data
- `metadata`: Additional metadata (JSONB)
- `embedding`: Vector embedding (vector(1536))
- `created_at`: Record creation timestamp

### analysis_results
- `id`: Serial primary key
- `log_id`: Foreign key to security_logs
- `analysis_type`: Type of analysis performed
- `result`: Analysis result (JSONB)
- `confidence`: Confidence score (0-100)
- `threat_level`: Assessed threat level
- `recommendations`: Recommended actions
- `analyzed_at`: Analysis timestamp

## Docker Commands

```bash
# Start containers
npm run docker:up

# Stop containers
npm run docker:down

# View logs
npm run docker:logs

# Access PostgreSQL
docker exec -it agentic_db psql -U chinnapong_admin -d security_logs_db
```

## Development

```bash
# Install dependencies
npm install

# Generate Prisma Client
npm run prisma:generate

# Create and apply migrations
npm run prisma:migrate

# Open Prisma Studio (Database GUI)
npm run prisma:studio

# Seed database with sample data
npm run prisma:seed

# Run in development mode with auto-reload
npm run dev

# Initialize/reset database
npm run init-db
```

## Security Features

- Helmet.js for security headers
- CORS configuration
- Rate limiting on all endpoints
- Input validation
- SQL injection prevention (parameterized queries)
- Error handling without exposing sensitive information

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Author

FightFK <151952442+FightFK@users.noreply.github.com>

## Support

For issues and questions, please open an issue on GitHub.
" 
