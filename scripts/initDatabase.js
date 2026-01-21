const { initDatabase, prisma } = require('../config/database');
const logger = require('../middleware/logger');

async function init() {
  try {
    logger.info('Initializing database with Prisma...');
    await initDatabase();
    logger.info('Database initialized successfully!');
    await prisma.$disconnect();
    process.exit(0);
  } catch (error) {
    logger.error('Failed to initialize database:', error);
    await prisma.$disconnect();
    process.exit(1);
  }
}

init();
