const { PrismaClient } = require('@prisma/client');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Create Prisma Client instance
const prisma = new PrismaClient({
  log: [
    {
      emit: 'event',
      level: 'query',
    },
    {
      emit: 'event',
      level: 'error',
    },
    {
      emit: 'event',
      level: 'info',
    },
    {
      emit: 'event',
      level: 'warn',
    },
  ],
});

// Log Prisma queries in development
if (process.env.NODE_ENV !== 'production') {
  prisma.$on('query', (e) => {
    logger.debug(`Query: ${e.query}`);
    logger.debug(`Duration: ${e.duration}ms`);
  });
}

// Log Prisma errors
prisma.$on('error', (e) => {
  logger.error('Prisma Error:', e);
});

// Test connection
prisma.$connect()
  .then(() => {
    logger.info('Database connection established successfully with Prisma');
  })
  .catch((err) => {
    logger.error('Error connecting to database:', err);
    process.exit(1);
  });

// Handle shutdown gracefully
process.on('beforeExit', async () => {
  await prisma.$disconnect();
  logger.info('Database connection closed');
});

// Initialize database with pgvector extension
const initDatabase = async () => {
  try {
    // Enable pgvector extension using raw SQL
    await prisma.$executeRaw`CREATE EXTENSION IF NOT EXISTS vector;`;
    
    // Create vector index if not exists (using raw SQL since Prisma doesn't fully support pgvector yet)
    await prisma.$executeRaw`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_indexes 
          WHERE indexname = 'idx_security_logs_embedding'
        ) THEN
          CREATE INDEX idx_security_logs_embedding 
          ON security_logs USING ivfflat (embedding::vector(1536) vector_cosine_ops);
        END IF;
      END $$;
    `;

    logger.info('Database extensions and indexes initialized successfully');
  } catch (err) {
    logger.error('Error initializing database:', err);
    throw err;
  }
};

module.exports = {
  prisma,
  initDatabase
};
