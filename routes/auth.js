const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authMiddleware, requireRole } = require('../middleware/auth');

// ─── Public (ไม่ต้อง token) ──────────────────────────────────────

// POST /api/auth/login
router.post('/login', authController.login.bind(authController));

// POST /api/auth/register
// - user แรกในระบบ: ไม่ต้อง token (จะได้ role admin อัตโนมัติ)
// - user ถัดไป: ต้องเป็น admin
router.post(
  '/register',
  (req, res, next) => {
    // ถ้ามี Authorization header → บังคับ auth + role admin
    // ถ้าไม่มี → ตรวจสอบว่าเป็น user แรกหรือเปล่าใน controller
    if (req.headers['authorization']) {
      return authMiddleware(req, res, () =>
        requireRole(['admin'])(req, res, next)
      );
    }
    next();
  },
  authController.register.bind(authController)
);

// ─── Protected (ต้อง token) ──────────────────────────────────────

// GET  /api/auth/me    — ดูข้อมูลตัวเอง
router.get('/me', authMiddleware, authController.getMe.bind(authController));

// PUT  /api/auth/me    — แก้ชื่อ / เปลี่ยน password ตัวเอง
router.put('/me', authMiddleware, authController.updateMe.bind(authController));

// ─── Admin Only ──────────────────────────────────────────────────

// GET   /api/auth/users       — รายชื่อ user ทั้งหมด
router.get(
  '/users',
  authMiddleware,
  requireRole(['admin']),
  authController.listUsers.bind(authController)
);

// PATCH /api/auth/users/:id   — แก้ role / active ของ user อื่น
router.patch(
  '/users/:id',
  authMiddleware,
  requireRole(['admin']),
  authController.updateUser.bind(authController)
);

router.delete(
  '/users/:id',
  authMiddleware,
  requireRole(['admin']),
  authController.deleteUser.bind(authController)
);

module.exports = router;
