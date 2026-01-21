const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  console.log('Start seeding...');

  // Create sample security logs
  const log1 = await prisma.securityLog.create({
    data: {
      source: 'firewall',
      severity: 'HIGH',
      eventType: 'unauthorized_access',
      description: 'Multiple failed login attempts detected',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      rawLog: 'Failed login attempt from 192.168.1.100',
      metadata: {
        attempts: 5,
        username: 'admin'
      }
    }
  });

  const log2 = await prisma.securityLog.create({
    data: {
      source: 'ids',
      severity: 'MEDIUM',
      eventType: 'port_scan',
      description: 'Port scanning activity detected',
      ipAddress: '10.0.0.50',
      rawLog: 'Port scan detected from 10.0.0.50',
      metadata: {
        ports: [22, 80, 443, 3306, 5432],
        duration: '30s'
      }
    }
  });

  const log3 = await prisma.securityLog.create({
    data: {
      source: 'web_server',
      severity: 'LOW',
      eventType: 'suspicious_request',
      description: 'SQL injection attempt in query parameter',
      ipAddress: '172.16.0.25',
      userAgent: 'curl/7.68.0',
      rawLog: 'GET /api/users?id=1 OR 1=1',
      metadata: {
        endpoint: '/api/users',
        method: 'GET'
      }
    }
  });

  console.log('Created security logs:', { log1, log2, log3 });

  console.log('Seeding finished.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
