const { ChatOpenAI } = require('@langchain/openai');
const { OpenAIEmbeddings } = require('@langchain/openai');
const { PromptTemplate } = require('@langchain/core/prompts');
const { StringOutputParser } = require('@langchain/core/output_parsers');
const { prisma } = require('../config/database');

class AIAnalysisService {
  constructor() {
    // Initialize OpenAI LLM
    this.llm = new ChatOpenAI({
      modelName: process.env.OPENAI_MODEL || 'gpt-4',
      temperature: 0.3,
      openAIApiKey: process.env.OPENAI_API_KEY,
    });

    // Initialize OpenAI Embeddings
    this.embeddings = new OpenAIEmbeddings({
      modelName: process.env.OPENAI_EMBEDDING_MODEL || 'text-embedding-ada-002',
      openAIApiKey: process.env.OPENAI_API_KEY,
    });

    // Create analysis prompt template
    this.analysisPromptTemplate = PromptTemplate.fromTemplate(`
You are a cybersecurity expert analyzing security logs. Analyze the following log entry and provide:
1. Threat assessment (HIGH, MEDIUM, LOW, NONE)
2. Potential attack type or security concern
3. Recommended actions
4. Confidence level (0-100%)

Log Details:
- Source: {source}
- Severity: {severity}
- Event Type: {eventType}
- Description: {description}
- IP Address: {ipAddress}
- Raw Log: {rawLog}

Provide your analysis in JSON format with the following structure:
{{
  "threat_level": "HIGH|MEDIUM|LOW|NONE",
  "attack_type": "string",
  "summary": "string",
  "indicators": ["string"],
  "recommendations": ["string"],
  "confidence": number
}}
`);
  }

  // Analyze a security log using AI
  async analyzeLog(logId) {
    try {
      // Get the log from database
      const log = await prisma.securityLog.findUnique({
        where: { id: parseInt(logId) }
      });

      if (!log) {
        throw new Error('Log not found');
      }

      // Create analysis chain
      const chain = this.analysisPromptTemplate.pipe(this.llm).pipe(new StringOutputParser());

      // Execute the chain
      const result = await chain.invoke({
        source: log.source,
        severity: log.severity,
        eventType: log.eventType,
        description: log.description || 'N/A',
        ipAddress: log.ipAddress || 'N/A',
        rawLog: log.rawLog || 'N/A'
      });

      // Parse the JSON response
      let analysis;
      try {
        // Try to parse as JSON
        analysis = JSON.parse(result);
      } catch (e) {
        // If parsing fails, extract JSON from markdown code blocks
        const jsonMatch = result.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/);
        if (jsonMatch) {
          analysis = JSON.parse(jsonMatch[1]);
        } else {
          throw new Error('Failed to parse AI response as JSON');
        }
      }

      // Store analysis result in database
      const analysisResult = await prisma.analysisResult.create({
        data: {
          logId: parseInt(logId),
          result: analysis,
          confidence: analysis.confidence || 0,
          threatLevel: analysis.threat_level
        }
      });

      return {
        id: analysisResult.id,
        logId: parseInt(logId),
        result: analysis,
        confidence: analysis.confidence || 0,
        threatLevel: analysis.threat_level || 'MEDIUM'
      };
    } catch (error) {
      console.error('Error in AI analysis:', error);
      throw error;
    }
  }

  // Batch analyze multiple logs
  async batchAnalyze(logIds) {
    const results = [];
    const errors = [];

    for (const logId of logIds) {
      try {
        const result = await this.analyzeLog(logId);
        results.push(result);
      } catch (error) {
        errors.push({
          log_id: logId,
          error: error.message
        });
      }
    }

    return {
      successful: results,
      failed: errors,
      total: logIds.length,
      success_count: results.length,
      error_count: errors.length
    };
  }

  // Search similar logs using vector similarity
  async findSimilarLogs(logId, limit = 5) {
    try {
      // Use raw SQL and cast vector to text (Prisma can't deserialize vector type)
      const [log] = await prisma.$queryRaw`
        SELECT embedding::text as embedding 
        FROM security_logs 
        WHERE id = ${parseInt(logId)}
      `;

      if (!log || !log.embedding) {
        throw new Error('Log not found or embedding not available');
      }

      // Parse embedding based on its type
      let embeddingArray;
      
      if (Array.isArray(log.embedding)) {
        // Already an array
        embeddingArray = log.embedding;
      } else if (typeof log.embedding === 'string') {
        // String format: "[0.1,0.2,...]" or "0.1,0.2,..."
        const cleaned = log.embedding.replace(/^\[|\]$/g, '');
        embeddingArray = cleaned.split(',').map(Number);
      } else if (Buffer.isBuffer(log.embedding)) {
        // Buffer from database - parse as JSON
        const parsed = JSON.parse(log.embedding.toString());
        embeddingArray = Array.isArray(parsed) ? parsed : Object.values(parsed);
      } else if (typeof log.embedding === 'object') {
        // Object format: {0: 0.1, 1: 0.2, ...}
        embeddingArray = Object.values(log.embedding).map(Number);
      } else {
        throw new Error(`Unsupported embedding format: ${typeof log.embedding}`);
      }

      // Validate embedding
      if (!embeddingArray || embeddingArray.length !== 1536) {
        throw new Error(`Invalid embedding dimension: ${embeddingArray?.length}`);
      }

      // Format for pgvector
      const embeddingStr = `[${embeddingArray.join(',')}]`;

      // Try vector search - fallback if embedding column is still TEXT
      let similarLogs;
      try {
        // Attempt pgvector cosine distance operator
        similarLogs = await prisma.$queryRaw`
          SELECT 
            id, 
            timestamp, 
            source, 
            severity, 
            event_type as "eventType", 
            description,
            ip_address as "ipAddress",
            1 - (embedding <=> ${embeddingStr}::vector) as similarity
          FROM security_logs
          WHERE id != ${parseInt(logId)} 
            AND embedding IS NOT NULL
          ORDER BY embedding <=> ${embeddingStr}::vector
          LIMIT ${limit}
        `;
      } catch (vectorError) {
        // Fallback: Database not migrated yet, return empty
        console.warn('⚠️ Vector search failed. Database needs migration. Run: npx prisma migrate dev');
        console.warn('Error:', vectorError.message);
        return [];
      }

      return similarLogs;
    } catch (error) {
      console.error('Error finding similar logs:', error);
      throw error;
    }
  }

  // Generate embedding for a log
  async generateEmbedding(text) {
    try {
      // Use LangChain embeddings
      const embedding = await this.embeddings.embedQuery(text);
      return embedding;
    } catch (error) {
      console.error('Error generating embedding:', error);
      throw error;
    }
  }

  // Update log with embedding
  async updateLogEmbedding(logId) {
    try {
      const log = await prisma.securityLog.findUnique({
        where: { id: parseInt(logId) }
      });

      if (!log) {
        throw new Error('Log not found');
      }

      const text = `${log.eventType} ${log.description || ''} ${log.rawLog || ''}`;
      
      const embedding = await this.generateEmbedding(text);

      // Store embedding in pgvector format using raw SQL
      const embeddingStr = `[${embedding.join(',')}]`;
      
      await prisma.$executeRaw`
        UPDATE security_logs 
        SET embedding = ${embeddingStr}::vector 
        WHERE id = ${parseInt(logId)}
      `;

      return { id: parseInt(logId), embedding_updated: true };
    } catch (error) {
      console.error('Error updating log embedding:', error);
      throw error;
    }
  }
}

module.exports = new AIAnalysisService();
