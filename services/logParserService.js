const logger = require('../middleware/logger');

class LogParserService {
  constructor() {
    // NGINX log patterns
    this.nginxPattern = /^(\S+) - (\S+) \[([^\]]+)\] "(\S+) ([^"]+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/;
    
    // Attack patterns for detection
    this.attackPatterns = {
      sql_injection: [
        /(\bor\b|\band\b).*?['"]?\s*=\s*['"]?/gi,
        /union.*select/gi,
        /select.*from/gi,
        /insert.*into/gi,
        /delete.*from/gi,
        /drop.*table/gi,
        /exec(\s|\+)+(s|x)p\w+/gi,
        /[\w\s]+'\s*(or|and)\s*'?\d+/gi,
        /--|\#|\/\*/gi
      ],
      xss: [
        /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
        /<iframe/gi,
        /javascript:/gi,
        /onerror\s*=/gi,
        /onload\s*=/gi,
        /<img[\s\S]*?src/gi
      ],
      path_traversal: [
        /\.\.[\/\\]/g,
        /\.\.%2f/gi,
        /\.\.%5c/gi,
        /%2e%2e[\/\\]/gi
      ],
      command_injection: [
        /;\s*(ls|cat|wget|curl|nc|bash|sh|cmd)/gi,
        /\|\s*(ls|cat|wget|curl|nc|bash|sh|cmd)/gi,
        /`.*`/g,
        /\$\(.*\)/g
      ],
      brute_force: [
        // Detected by frequency analysis in autoProcessingService
      ],
      sensitive_data_exposure: [
        /api[_-]?key/gi,
        /password/gi,
        /secret/gi,
        /token/gi,
        /admin/gi
      ]
    };

    // Status code severity mapping
    this.statusCodeSeverity = {
      '400-499': 'MEDIUM',  // Client errors
      '500-599': 'HIGH',     // Server errors
      '200-299': 'LOW',      // Success
      '300-399': 'LOW'       // Redirects
    };
  }

  /**
   * Parse NGINX raw log line
   */
  parseNginxLog(rawLog) {
    try {
      const match = rawLog.match(this.nginxPattern);
      
      if (!match) {
        // If pattern doesn't match, return basic structure
        return {
          ipAddress: null,
          timestamp: new Date(),
          method: null,
          uri: null,
          protocol: null,
          statusCode: null,
          bodySize: null,
          referer: null,
          userAgent: null,
          rawLog: rawLog
        };
      }

      return {
        ipAddress: match[1],
        remoteUser: match[2] !== '-' ? match[2] : null,
        timestamp: this.parseNginxTimestamp(match[3]),
        method: match[4],
        uri: match[5],
        protocol: match[6],
        statusCode: parseInt(match[7]),
        bodySize: parseInt(match[8]),
        referer: match[9] !== '-' ? match[9] : null,
        userAgent: match[10],
        rawLog: rawLog
      };
    } catch (error) {
      logger.error(`Failed to parse NGINX log: ${error.message}`);
      return {
        rawLog: rawLog,
        ipAddress: null,
        timestamp: new Date()
      };
    }
  }

  /**
   * Parse NGINX timestamp format
   */
  parseNginxTimestamp(timestamp) {
    try {
      // Format: 31/Jan/2026:10:30:45 +0000
      const parts = timestamp.match(/(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+)\s+([\+\-]\d+)/);
      if (!parts) return new Date();

      const months = {
        'Jan': 0, 'Feb': 1, 'Mar': 2, 'Apr': 3, 'May': 4, 'Jun': 5,
        'Jul': 6, 'Aug': 7, 'Sep': 8, 'Oct': 9, 'Nov': 10, 'Dec': 11
      };

      return new Date(
        parseInt(parts[3]),  // year
        months[parts[2]],    // month
        parseInt(parts[1]),  // day
        parseInt(parts[4]),  // hour
        parseInt(parts[5]),  // minute
        parseInt(parts[6])   // second
      );
    } catch (error) {
      return new Date();
    }
  }

  /**
   * Detect attack type from parsed log
   */
  detectAttackType(parsedLog) {
    const detections = [];
    const fullRequest = `${parsedLog.method} ${parsedLog.uri} ${parsedLog.userAgent || ''}`;

    // Check each attack pattern
    for (const [attackType, patterns] of Object.entries(this.attackPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(fullRequest)) {
          detections.push(attackType);
          break; // Found this attack type, move to next
        }
      }
    }

    return detections.length > 0 ? detections : ['normal_traffic'];
  }

  /**
   * Determine severity based on status code and attack detection
   */
  determineSeverity(parsedLog, detectedAttacks) {
    // High severity attacks
    const highSeverityAttacks = ['sql_injection', 'command_injection', 'path_traversal'];
    if (detectedAttacks.some(attack => highSeverityAttacks.includes(attack))) {
      return 'HIGH';
    }

    // Medium severity attacks
    const mediumSeverityAttacks = ['xss', 'sensitive_data_exposure', 'brute_force'];
    if (detectedAttacks.some(attack => mediumSeverityAttacks.includes(attack))) {
      return 'MEDIUM';
    }

    // Check status code
    const statusCode = parsedLog.statusCode;
    if (statusCode >= 500) return 'HIGH';
    if (statusCode >= 400) return 'MEDIUM';
    
    return 'LOW';
  }

  /**
   * Generate description based on detection
   */
  generateDescription(detectedAttacks, parsedLog) {
    if (detectedAttacks.includes('normal_traffic')) {
      return `Normal HTTP ${parsedLog.method} request to ${parsedLog.uri}`;
    }

    const descriptions = {
      sql_injection: 'SQL injection attempt detected in request',
      xss: 'Cross-site scripting (XSS) attempt detected',
      path_traversal: 'Path traversal attempt detected',
      command_injection: 'Command injection attempt detected',
      brute_force: 'Multiple failed authentication attempts',
      sensitive_data_exposure: 'Potential sensitive data exposure in request'
    };

    const detected = detectedAttacks
      .map(attack => descriptions[attack] || attack)
      .join(', ');

    return `${detected} from ${parsedLog.ipAddress || 'unknown IP'}`;
  }

  /**
   * Process raw NGINX log and enrich with analysis
   */
  processRawLog(rawLog, metadata = {}) {
    // Parse the log
    const parsed = this.parseNginxLog(rawLog);

    // Detect attack types
    const detectedAttacks = this.detectAttackType(parsed);

    // Determine severity
    const severity = this.determineSeverity(parsed, detectedAttacks);

    // Primary event type (first detected attack or normal)
    const eventType = detectedAttacks[0];

    // Generate description
    const description = this.generateDescription(detectedAttacks, parsed);

    // Combine with additional metadata
    const enrichedMetadata = {
      ...metadata,
      detected_attacks: detectedAttacks,
      status_code: parsed.statusCode,
      request_method: parsed.method,
      request_uri: parsed.uri,
      referer: parsed.referer,
      body_size: parsed.bodySize,
      parsed_at: new Date()
    };

    return {
      source: metadata.source || 'nginx',
      severity: severity,
      eventType: eventType,
      description: description,
      ipAddress: parsed.ipAddress,
      userAgent: parsed.userAgent,
      rawLog: rawLog,
      metadata: enrichedMetadata,
      timestamp: parsed.timestamp
    };
  }

  /**
   * Batch process multiple raw logs
   */
  processBatchLogs(rawLogs, metadata = {}) {
    return rawLogs.map(rawLog => {
      if (typeof rawLog === 'string') {
        return this.processRawLog(rawLog, metadata);
      } else if (rawLog.raw_log) {
        return this.processRawLog(rawLog.raw_log, { ...metadata, ...rawLog });
      } else {
        return rawLog; // Already processed
      }
    });
  }
}

module.exports = new LogParserService();
