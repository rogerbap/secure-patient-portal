
const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, '../database/development.db');
const dbDir = path.join(__dirname, '../database');

console.log('🔄 Resetting database...');

try {
  // Create database directory if it doesn't exist
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log('📁 Created database directory');
  }

  // Remove existing database file if it exists
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
    console.log('🗑️  Removed existing database file');
  }

  console.log('✅ Database reset complete');
  console.log('🚀 You can now start the server with: npm run dev:server');

} catch (error) {
  console.error(' Error resetting database:', error.message);
  process.exit(1);
}