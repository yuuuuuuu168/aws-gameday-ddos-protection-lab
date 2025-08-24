const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

/**
 * GameDay Vulnerable Application Database Initialization
 * 意図的にセキュリティ脆弱性を含むデータベース初期化スクリプト
 */

class VulnerableDatabase {
  constructor(dbPath = './gameday.db') {
    this.dbPath = dbPath;
    this.db = null;
  }

  /**
   * データベース接続を開く（意図的に脆弱な設定）
   */
  connect() {
    return new Promise((resolve, reject) => {
      // 意図的に脆弱な設定：WALモード無効、同期無効
      this.db = new sqlite3.Database(this.dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
        if (err) {
          console.error('Database connection error:', err.message);
          reject(err);
        } else {
          console.log('Connected to SQLite database:', this.dbPath);
          
          // 意図的に危険な設定
          this.db.run('PRAGMA synchronous = OFF'); // データ整合性リスク
          this.db.run('PRAGMA journal_mode = DELETE'); // パフォーマンス低下
          this.db.run('PRAGMA foreign_keys = OFF'); // 参照整合性無効
          
          resolve();
        }
      });
    });
  }

  /**
   * SQLファイルを実行（意図的にSQLインジェクション脆弱性あり）
   */
  executeSqlFile(filePath) {
    return new Promise((resolve, reject) => {
      const sql = fs.readFileSync(filePath, 'utf8');
      
      // 意図的に危険：SQLを直接実行（パラメータ化なし）
      this.db.exec(sql, (err) => {
        if (err) {
          console.error(`Error executing ${filePath}:`, err.message);
          reject(err);
        } else {
          console.log(`Successfully executed ${filePath}`);
          resolve();
        }
      });
    });
  }

  /**
   * 脆弱なクエリ実行メソッド（SQLインジェクション脆弱性）
   */
  executeVulnerableQuery(query, params = []) {
    return new Promise((resolve, reject) => {
      // 意図的に脆弱：パラメータを直接文字列に埋め込み
      let vulnerableQuery = query;
      params.forEach((param, index) => {
        vulnerableQuery = vulnerableQuery.replace(`$${index + 1}`, `'${param}'`);
      });
      
      console.log('Executing vulnerable query:', vulnerableQuery);
      
      this.db.all(vulnerableQuery, (err, rows) => {
        if (err) {
          console.error('Query error:', err.message);
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  /**
   * ユーザー認証（意図的に脆弱な実装）
   */
  authenticateUser(username, password) {
    // 意図的なSQLインジェクション脆弱性
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    return new Promise((resolve, reject) => {
      console.log('Authentication query:', query);
      
      this.db.get(query, (err, row) => {
        if (err) {
          console.error('Authentication error:', err.message);
          reject(err);
        } else {
          if (row) {
            console.log('Authentication successful for user:', row.username);
            // 意図的に機密情報を含むレスポンス
            resolve({
              success: true,
              user: {
                id: row.id,
                username: row.username,
                email: row.email,
                role: row.role,
                password: row.password, // 平文パスワードを返す（脆弱性）
                api_key: row.api_key,
                credit_card: row.credit_card, // 機密情報を返す（脆弱性）
                ssn: row.ssn
              }
            });
          } else {
            resolve({ success: false, message: 'Invalid credentials' });
          }
        }
      });
    });
  }

  /**
   * 検索機能（XSS脆弱性を含む）
   */
  searchPosts(searchTerm, userId = null) {
    // 意図的なSQLインジェクション脆弱性
    const query = `SELECT * FROM posts WHERE title LIKE '%${searchTerm}%' OR content LIKE '%${searchTerm}%'`;
    
    return new Promise((resolve, reject) => {
      console.log('Search query:', query);
      
      // 検索ログを記録（SQLインジェクション脆弱性あり）
      const logQuery = `INSERT INTO search_logs (user_id, search_query, search_date) VALUES (${userId || 'NULL'}, '${searchTerm}', datetime('now'))`;
      this.db.run(logQuery);
      
      this.db.all(query, (err, rows) => {
        if (err) {
          console.error('Search error:', err.message);
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  /**
   * ファイル情報の保存（パストラバーサル脆弱性）
   */
  saveFileInfo(userId, originalFilename, storedFilename, filePath, fileSize, mimeType) {
    // 意図的に危険：ファイルパスの検証なし
    const query = `INSERT INTO uploaded_files (user_id, original_filename, stored_filename, file_path, file_size, mime_type) 
                   VALUES (${userId}, '${originalFilename}', '${storedFilename}', '${filePath}', ${fileSize}, '${mimeType}')`;
    
    return new Promise((resolve, reject) => {
      console.log('File save query:', query);
      
      this.db.run(query, function(err) {
        if (err) {
          console.error('File save error:', err.message);
          reject(err);
        } else {
          resolve({ id: this.lastID });
        }
      });
    });
  }

  /**
   * 管理者権限チェック（権限昇格脆弱性）
   */
  checkAdminAccess(userId) {
    // 意図的に脆弱：ユーザーIDを直接クエリに埋め込み
    const query = `SELECT role FROM users WHERE id = ${userId}`;
    
    return new Promise((resolve, reject) => {
      this.db.get(query, (err, row) => {
        if (err) {
          reject(err);
        } else {
          // 意図的に脆弱：role文字列の単純比較
          const isAdmin = row && (row.role === 'admin' || row.role.includes('admin'));
          resolve(isAdmin);
        }
      });
    });
  }

  /**
   * データベース初期化
   */
  async initialize() {
    try {
      await this.connect();
      
      const schemaPath = path.join(__dirname, 'schema.sql');
      const seedDataPath = path.join(__dirname, 'seed_data.sql');
      
      console.log('Initializing database schema...');
      await this.executeSqlFile(schemaPath);
      
      console.log('Loading seed data...');
      await this.executeSqlFile(seedDataPath);
      
      console.log('Database initialization completed successfully!');
      console.log('⚠️  WARNING: This database contains intentional security vulnerabilities!');
      
    } catch (error) {
      console.error('Database initialization failed:', error);
      throw error;
    }
  }

  /**
   * データベース接続を閉じる
   */
  close() {
    return new Promise((resolve) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            console.error('Error closing database:', err.message);
          } else {
            console.log('Database connection closed');
          }
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * データベースの完全リセット（テスト用）
   */
  async reset() {
    try {
      if (fs.existsSync(this.dbPath)) {
        fs.unlinkSync(this.dbPath);
        console.log('Existing database file deleted');
      }
      
      await this.initialize();
      console.log('Database reset completed');
      
    } catch (error) {
      console.error('Database reset failed:', error);
      throw error;
    }
  }
}

// スタンドアロン実行時の処理
if (require.main === module) {
  const db = new VulnerableDatabase();
  
  db.initialize()
    .then(() => {
      console.log('Database setup completed successfully!');
      return db.close();
    })
    .catch((error) => {
      console.error('Database setup failed:', error);
      process.exit(1);
    });
}

module.exports = VulnerableDatabase;