/**
 * GameDay Vulnerable Database Queries
 * 意図的にセキュリティ脆弱性を含むデータベースクエリ集
 */

const VulnerableDatabase = require('./db_init');

class VulnerableQueries extends VulnerableDatabase {
  constructor(dbPath) {
    super(dbPath);
  }

  /**
   * SQLインジェクション脆弱性 - ユーザー検索
   */
  async searchUsers(searchTerm) {
    // 意図的なSQLインジェクション脆弱性
    const query = `SELECT id, username, email, role FROM users WHERE username LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`User search failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - 投稿取得
   */
  async getPostsByUser(userId) {
    // 意図的なSQLインジェクション脆弱性
    const query = `SELECT * FROM posts WHERE user_id = ${userId} ORDER BY created_at DESC`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`Posts retrieval failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - 動的ORDER BY
   */
  async getUsersOrderedBy(orderBy = 'id', direction = 'ASC') {
    // 意図的なSQLインジェクション脆弱性 - ORDER BY句
    const query = `SELECT id, username, email, role, created_at FROM users ORDER BY ${orderBy} ${direction}`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`Ordered users retrieval failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - UNION攻撃対応
   */
  async getPostDetails(postId) {
    // 意図的なSQLインジェクション脆弱性 - UNION攻撃可能
    const query = `SELECT title, content, created_at FROM posts WHERE id = ${postId}`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result[0] || null;
    } catch (error) {
      throw new Error(`Post details retrieval failed: ${error.message}`);
    }
  }

  /**
   * 権限昇格脆弱性 - 管理者機能
   */
  async updateUserRole(userId, newRole, adminUserId) {
    // 意図的に脆弱：管理者権限の適切な検証なし
    const updateQuery = `UPDATE users SET role = '${newRole}' WHERE id = ${userId}`;
    const logQuery = `INSERT INTO admin_actions (user_id, action, target_user_id, details) 
                      VALUES (${adminUserId}, 'USER_ROLE_CHANGE', ${userId}, 'Changed role to ${newRole}')`;
    
    try {
      await this.executeVulnerableQuery(updateQuery);
      await this.executeVulnerableQuery(logQuery);
      return { success: true, message: 'User role updated successfully' };
    } catch (error) {
      throw new Error(`Role update failed: ${error.message}`);
    }
  }

  /**
   * 情報漏洩脆弱性 - 機密データ取得
   */
  async getUserSensitiveData(userId) {
    // 意図的に機密情報を返す
    const query = `SELECT username, password, api_key, credit_card, ssn FROM users WHERE id = ${userId}`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result[0] || null;
    } catch (error) {
      throw new Error(`Sensitive data retrieval failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - 複数テーブル結合
   */
  async getUserActivityReport(userId, startDate, endDate) {
    // 意図的なSQLインジェクション脆弱性 - 複雑なクエリ
    const query = `
      SELECT 
        u.username,
        p.title as post_title,
        p.created_at as post_date,
        s.search_query,
        s.search_date,
        f.original_filename,
        f.upload_date
      FROM users u
      LEFT JOIN posts p ON u.id = p.user_id
      LEFT JOIN search_logs s ON u.id = s.user_id
      LEFT JOIN uploaded_files f ON u.id = f.user_id
      WHERE u.id = ${userId}
        AND (p.created_at BETWEEN '${startDate}' AND '${endDate}'
             OR s.search_date BETWEEN '${startDate}' AND '${endDate}'
             OR f.upload_date BETWEEN '${startDate}' AND '${endDate}')
      ORDER BY COALESCE(p.created_at, s.search_date, f.upload_date) DESC
    `;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`Activity report generation failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - 設定値更新
   */
  async updateAppSetting(settingKey, settingValue, userId) {
    // 意図的なSQLインジェクション脆弱性
    const query = `UPDATE app_settings SET setting_value = '${settingValue}', updated_by = ${userId}, updated_at = datetime('now') WHERE setting_key = '${settingKey}'`;
    
    try {
      await this.executeVulnerableQuery(query);
      return { success: true, message: 'Setting updated successfully' };
    } catch (error) {
      throw new Error(`Setting update failed: ${error.message}`);
    }
  }

  /**
   * 情報漏洩脆弱性 - 全設定値取得
   */
  async getAllSettings() {
    // 意図的に機密設定も含めて全て返す
    const query = `SELECT setting_key, setting_value, description, is_public FROM app_settings ORDER BY setting_key`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`Settings retrieval failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - ファイル検索
   */
  async searchFiles(filename, userId = null) {
    // 意図的なSQLインジェクション脆弱性
    let query = `SELECT * FROM uploaded_files WHERE original_filename LIKE '%${filename}%'`;
    
    if (userId) {
      query += ` AND user_id = ${userId}`;
    }
    
    try {
      const result = await this.executeVulnerableQuery(query);
      return result;
    } catch (error) {
      throw new Error(`File search failed: ${error.message}`);
    }
  }

  /**
   * 認証バイパス脆弱性 - セッション検証
   */
  async validateSession(sessionId) {
    // 意図的に脆弱なセッション検証
    const query = `SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.session_id = '${sessionId}' AND s.is_active = 1`;
    
    try {
      const result = await this.executeVulnerableQuery(query);
      const session = result[0];
      
      if (session) {
        // 意図的に期限切れチェックを省略（脆弱性）
        return {
          valid: true,
          userId: session.user_id,
          username: session.username,
          role: session.role,
          sessionData: session
        };
      } else {
        return { valid: false };
      }
    } catch (error) {
      throw new Error(`Session validation failed: ${error.message}`);
    }
  }

  /**
   * SQLインジェクション脆弱性 - 統計情報取得
   */
  async getStatistics(dateRange = '30 days') {
    // 意図的なSQLインジェクション脆弱性
    const queries = {
      userCount: `SELECT COUNT(*) as count FROM users WHERE created_at >= datetime('now', '-${dateRange}')`,
      postCount: `SELECT COUNT(*) as count FROM posts WHERE created_at >= datetime('now', '-${dateRange}')`,
      searchCount: `SELECT COUNT(*) as count FROM search_logs WHERE search_date >= datetime('now', '-${dateRange}')`,
      fileCount: `SELECT COUNT(*) as count FROM uploaded_files WHERE upload_date >= datetime('now', '-${dateRange}')`
    };
    
    try {
      const results = {};
      
      for (const [key, query] of Object.entries(queries)) {
        const result = await this.executeVulnerableQuery(query);
        results[key] = result[0].count;
      }
      
      return results;
    } catch (error) {
      throw new Error(`Statistics retrieval failed: ${error.message}`);
    }
  }
}

module.exports = VulnerableQueries;