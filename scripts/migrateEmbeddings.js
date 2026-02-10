/**
 * Script to migrate existing text embeddings to vector format
 * Run this AFTER applying the schema migration
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function migrateExistingEmbeddings() {
  console.log('🔄 Starting embedding migration...');
  
  try {
    // Get all logs with old-format embeddings (stored as JSON strings in other columns)
    // Since we dropped the column, this will find logs without embeddings
    const logsWithoutEmbedding = await prisma.securityLog.findMany({
      where: {
        embedding: null,
        // Only process logs that have content to generate embeddings from
        OR: [
          { rawLog: { not: null } },
          { description: { not: null } }
        ]
      },
      select: {
        id: true,
        eventType: true,
        description: true,
        rawLog: true
      },
      take: 1000 // Process in batches
    });

    console.log(`📊 Found ${logsWithoutEmbedding.length} logs without embeddings`);

    if (logsWithoutEmbedding.length === 0) {
      console.log('✅ No logs to migrate');
      return;
    }

    // Import AI service after Prisma is initialized
    const aiAnalysisService = require('./services/aiAnalysisService');

    let processed = 0;
    let failed = 0;

    for (const log of logsWithoutEmbedding) {
      try {
        const text = `${log.eventType} ${log.description || ''} ${log.rawLog || ''}`;
        const embedding = await aiAnalysisService.generateEmbedding(text);
        
        // Store in vector format
        const embeddingStr = `[${embedding.join(',')}]`;
        await prisma.$executeRaw`
          UPDATE security_logs 
          SET embedding = ${embeddingStr}::vector 
          WHERE id = ${log.id}
        `;
        
        processed++;
        if (processed % 10 === 0) {
          console.log(`✅ Processed ${processed}/${logsWithoutEmbedding.length}`);
        }
      } catch (error) {
        console.error(`❌ Failed to process log ${log.id}:`, error.message);
        failed++;
      }
    }

    console.log('\n='.repeat(60));
    console.log('✅ Migration completed!');
    console.log(`📊 Processed: ${processed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run migration
if (require.main === module) {
  migrateExistingEmbeddings()
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = migrateExistingEmbeddings;
