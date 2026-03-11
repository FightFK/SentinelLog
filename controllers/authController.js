const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { prisma } = require('../config/database');

const SALT_ROUNDS = 12;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

/**
 * ==================== AUTH CONTROLLER ====================
 *
 * POST /api/auth/register  — สร้าง user ใหม่ (admin only หลัง user แรก)
 * POST /api/auth/login     — login รับ JWT
 * GET  /api/auth/me        — ดูข้อมูล user ตัวเอง
 * PUT  /api/auth/me        — แก้ชื่อ / password
 */
class AuthController {
  /**
   * POST /api/auth/register
   * สมัคร user ใหม่
   *
   * - ถ้าไม่มี user เลยในระบบ → คนแรกจะได้ role "admin" อัตโนมัติ
   * - ถ้ามี user แล้ว → ต้องใช้ admin token (ป้องกันใน routes ด้วย requireRole)
   *
   * Body: { email, password, name, role? }
   */
  async register(req, res, next) {
    try {
      const { email, password, name, role } = req.body;

      if (!email || !password || !name) {
        return res.status(400).json({
          error: 'email, password, and name are required'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error: 'password must be at least 8 characters'
        });
      }

      // เช็ค email ซ้ำ
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) {
        return res.status(409).json({ error: 'Email already in use' });
      }

      // ถ้าไม่มี user เลยในระบบ → คนแรกเป็น admin
      const userCount = await prisma.user.count();
      const assignedRole = userCount === 0 ? 'admin' : (role || 'viewer');

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      const user = await prisma.user.create({
        data: { email, passwordHash, name, role: assignedRole }
      });

      // Log activity
      await prisma.activityLog.create({
        data: {
          userId: user.id,
          action: 'register',
          details: { email: user.email, role: user.role },
          ipAddress: req.ip || null
        }
      });

      res.status(201).json({
        success: true,
        data: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          createdAt: user.createdAt
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/auth/login
   * Body: { email, password }
   * Response: { token, user }
   */
  async login(req, res, next) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'email and password are required' });
      }

      const user = await prisma.user.findUnique({ where: { email } });

      if (!user || !user.active) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // อัปเดต lastLogin
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLogin: new Date() }
      });

      // Log activity
      await prisma.activityLog.create({
        data: {
          userId: user.id,
          action: 'login',
          details: { email: user.email },
          ipAddress: req.ip || null
        }
      });

      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      res.json({
        success: true,
        data: {
          token,
          expires_in: JWT_EXPIRES_IN,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            lastLogin: user.lastLogin
          }
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/auth/me
   * ดูข้อมูล user ตัวเอง (ต้อง login)
   */
  async getMe(req, res, next) {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          active: true,
          createdAt: true,
          lastLogin: true
        }
      });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ success: true, data: user });
    } catch (error) {
      next(error);
    }
  }

  /**
   * PUT /api/auth/me
   * แก้ไขข้อมูลตัวเอง: name, current_password + new_password
   * Body: { name?, current_password?, new_password? }
   */
  async updateMe(req, res, next) {
    try {
      const { name, current_password, new_password } = req.body;
      const updateData = {};

      if (name) updateData.name = name;

      if (new_password) {
        if (!current_password) {
          return res.status(400).json({ error: 'current_password is required to change password' });
        }
        if (new_password.length < 8) {
          return res.status(400).json({ error: 'new_password must be at least 8 characters' });
        }
        const user = await prisma.user.findUnique({ where: { id: req.user.id } });
        const valid = await bcrypt.compare(current_password, user.passwordHash);
        if (!valid) {
          return res.status(401).json({ error: 'current_password is incorrect' });
        }
        updateData.passwordHash = await bcrypt.hash(new_password, SALT_ROUNDS);
      }

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
      }

      const updated = await prisma.user.update({
        where: { id: req.user.id },
        data: updateData,
        select: { id: true, email: true, name: true, role: true, lastLogin: true }
      });

      res.json({ success: true, data: updated });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/auth/users  (admin only)
   * ดูรายชื่อ user ทั้งหมด
   */
  async listUsers(req, res, next) {
    try {
      const users = await prisma.user.findMany({
        select: {
          id: true, email: true, name: true,
          role: true, active: true, createdAt: true, lastLogin: true
        },
        orderBy: { createdAt: 'desc' }
      });
      res.json({ success: true, data: users });
    } catch (error) {
      next(error);
    }
  }

  /**
   * PATCH /api/auth/users/:id  (admin only)
   * แก้ role หรือ active status ของ user คนอื่น
   * Body: { role?, active? }
   */
  async updateUser(req, res, next) {
    try {
      const { id } = req.params;
      const { role, active } = req.body;

      if (parseInt(id) === req.user.id) {
        return res.status(400).json({ error: 'Use PUT /api/auth/me to update your own account' });
      }

      const updateData = {};
      if (role) {
        const VALID_ROLES = ['admin', 'analyst', 'viewer'];
        if (!VALID_ROLES.includes(role)) {
          return res.status(400).json({ error: `Invalid role. Valid: ${VALID_ROLES.join(', ')}` });
        }
        updateData.role = role;
      }
      if (typeof active === 'boolean') updateData.active = active;

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
      }

      const updated = await prisma.user.update({
        where: { id: parseInt(id) },
        data: updateData,
        select: { id: true, email: true, name: true, role: true, active: true }
      });

      res.json({ success: true, data: updated });
    } catch (error) {
      if (error.code === 'P2025') {
        return res.status(404).json({ error: 'User not found' });
      }
      next(error);
    }
  }

 async deleteUser(req, res, next) {
    try {
      const { id } = req.params;
      const targetId = parseInt(id);

      if (targetId === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
      }

      // ป้องกันลบ admin คนสุดท้าย
      const target = await prisma.user.findUnique({ where: { id: targetId } });
      if (!target) {
        return res.status(404).json({ error: 'User not found' });
      }
      if (target.role === 'admin') {
        const adminCount = await prisma.user.count({ where: { role: 'admin' } });
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'Cannot delete the last admin account' });
        }
      }

      await prisma.user.delete({ where: { id: targetId } });
      res.json({ success: true, message: 'User deleted' });
    } catch (error) {
      if (error.code === 'P2025') {
        return res.status(404).json({ error: 'User not found' });
      }
      next(error);
    }
  }

}

module.exports = new AuthController();
