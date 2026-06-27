/**
 * Smart Link Interceptor — Cluster Mode Entry Point
 * 
 * Uses Node.js cluster module to fork multiple worker processes,
 * one per CPU core. Each worker runs an independent Express server
 * sharing the same port via the OS kernel's SO_REUSEPORT.
 * 
 * This is the single-machine equivalent of a distributed system:
 * 
 *   Master Process (coordinator)
 *     ├── Worker 1 (Express server on port 3001)
 *     ├── Worker 2 (Express server on port 3001)
 *     ├── Worker 3 (Express server on port 3001)
 *     └── Worker N (Express server on port 3001)
 * 
 * All workers share the Redis cache for consistency.
 * If a worker dies, the master restarts it automatically.
 * 
 * Usage: node cluster.js
 */

import cluster from 'cluster';
import os from 'os';
import 'dotenv/config';

const NUM_WORKERS = parseInt(process.env.CLUSTER_WORKERS || '0', 10) || os.cpus().length;

if (cluster.isPrimary) {
  console.log('');
  console.log('🛡️  Smart Link Interceptor — Cluster Mode');
  console.log('═'.repeat(56));
  console.log(`👑 Master process PID: ${process.pid}`);
  console.log(`🖥️  CPU cores available: ${os.cpus().length}`);
  console.log(`🔀 Spawning ${NUM_WORKERS} worker processes...`);
  console.log('─'.repeat(56));

  // Fork workers
  for (let i = 0; i < NUM_WORKERS; i++) {
    const worker = cluster.fork({
      INSTANCE_ID: `worker-${i + 1}`,
    });
    console.log(`   ├── Worker ${i + 1} spawned (PID: ${worker.process.pid})`);
  }

  console.log('─'.repeat(56));

  // Monitor worker health — auto-restart on crash
  cluster.on('exit', (worker, code, signal) => {
    console.error(`⚠️  Worker ${worker.process.pid} died (code: ${code}, signal: ${signal})`);
    console.log('   ↻  Spawning replacement worker...');
    const replacement = cluster.fork({
      INSTANCE_ID: `worker-replacement-${Date.now()}`,
    });
    console.log(`   └── Replacement worker spawned (PID: ${replacement.process.pid})`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('\n🛑 Master received SIGTERM — shutting down all workers...');
    for (const id in cluster.workers) {
      cluster.workers[id].kill('SIGTERM');
    }
    setTimeout(() => process.exit(0), 5000);
  });

  process.on('SIGINT', () => {
    console.log('\n🛑 Master received SIGINT — shutting down all workers...');
    for (const id in cluster.workers) {
      cluster.workers[id].kill('SIGTERM');
    }
    setTimeout(() => process.exit(0), 3000);
  });

} else {
  // Worker process — import and run the Express server
  await import('./server.js');
}
