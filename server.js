const express = require('express');
const pool = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');  // สำหรับอัปโหลดไฟล์
const path = require('path');  // สำหรับจัดการเส้นทางไฟล์
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const port = 4000;

// กำหนดโฟลเดอร์สำหรับเก็บรูปโปรไฟล์
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// เปิดให้เข้าถึงไฟล์จากโฟลเดอร์ 'uploads'
app.use('/uploads', express.static('uploads'));

// ฟังก์ชันสำหรับตรวจสอบ token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // รับ token จาก header

    if (!token) return res.sendStatus(401); // ถ้าไม่มี token ส่ง status 401

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // ถ้า token ไม่ถูกต้อง ส่ง status 403

        req.user = user; // เก็บข้อมูล user ไว้ใน req
        next(); // ดำเนินการต่อไป
    });
};

// ฟังก์ชันสำหรับการลงทะเบียนผู้ใช้ใหม่
app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;

    try {
        const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email นี้ถูกใช้ไปแล้ว' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', [email, hashedPassword, name]);
        res.status(201).json({ message: 'ลงทะเบียนผู้ใช้สำเร็จ' });
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลงทะเบียน' });
    }
});

// ฟังก์ชันสำหรับการเข้าสู่ระบบ
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = results[0];
        
        if (!user) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '20h' }
        );
        res.json({ token: accessToken });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
    }
});

// เส้นทางสำหรับอัปเดตโปรไฟล์ผู้ใช้ (ต้องยืนยันตัวตน)
app.post('/updateProfile', authenticateToken, upload.single('profilePicture'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email, number } = req.body; // ดึงข้อมูลจาก form

        // ตรวจสอบข้อมูลที่รับเข้ามา
        if (!name || !email) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อและอีเมลให้ครบถ้วน' });
        }

        let profilePicturePath = '';
        if (req.file) {
            profilePicturePath = `/uploads/${req.file.filename}`;
        }

        // สร้างคำสั่ง SQL เพื่ออัปเดตข้อมูล
        let updateQuery = 'UPDATE users SET name = ?, email = ?';
        const queryParams = [name, email];

        // ถ้ามีเบอร์โทรศัพท์ให้เพิ่มเข้าไปในคำสั่งอัปเดต
        if (number) {
            updateQuery += ', number = ?';
            queryParams.push(number);
        }

        // ถ้ามีรูปโปรไฟล์ให้เพิ่มเข้าไปในคำสั่งอัปเดต
        if (profilePicturePath) {
            updateQuery += ', picture = ?';
            queryParams.push(profilePicturePath);
        }

        updateQuery += ' WHERE id = ?';
        queryParams.push(userId);

        // อัปเดตข้อมูลผู้ใช้
        await pool.query(updateQuery, queryParams);

        res.status(200).json({ message: 'อัปเดตข้อมูลสำเร็จ' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตโปรไฟล์' });
    }
});

// เส้นทางสำหรับดึงข้อมูลผู้ใช้งานที่เข้าสู่ระบบ (ต้องยืนยันตัวตน)
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // ดึงข้อมูลผู้ใช้จากฐานข้อมูลโดยใช้ userId จาก token
        const [results] = await pool.query("SELECT email, name, picture, number FROM users WHERE id = ?", [userId]);

        if (results.length === 0) {
            return res.status(404).json({ error: "ไม่พบผู้ใช้" });
        }

        res.json(results[0]); // ส่งข้อมูลผู้ใช้กลับไปยัง client
    } catch (err) {
        console.log('Error fetching user account:', err);
        res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้" });
    }
});

// เริ่มเซิร์ฟเวอร์
app.listen(port, () => {
    console.log(`เซิร์ฟเวอร์กำลังทำงานที่พอร์ต ${port}`);
});
