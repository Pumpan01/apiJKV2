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

app.post('/register', async (req, res) => {
    const { email, password, name, age, gender } = req.body;

    console.log(req.body); // ดูค่าที่ส่งมาว่าถูกต้องหรือไม่

    try {
        const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email นี้ถูกใช้ไปแล้ว' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (email, password, name, age, gender) VALUES (?, ?, ?, ?, ?)', [email, hashedPassword, name, age, gender]);
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

// ฟังก์ชันสำหรับการเพิ่มโพสต์
app.post('/posts', authenticateToken, upload.single('image'), async (req, res) => {
    const { namepost, description } = req.body;
    const userId = req.user.id;

    try {
        if (!namepost || !description) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อโพสต์และรายละเอียดให้ครบถ้วน' });
        }

        let imagePath = '';
        if (req.file) {
            imagePath = `/uploads/${req.file.filename}`;
        }

        // เพิ่มข้อมูลลงในตาราง posts
        const [result] = await pool.query('INSERT INTO posts (namepost, description, userId, image) VALUES (?, ?, ?, ?)', [namepost, description, userId, imagePath]);

        res.status(201).json({ message: 'โพสต์ถูกเพิ่มเรียบร้อยแล้ว', postId: result.insertId });
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเพิ่มโพสต์' });
    }
});

// เส้นทางสำหรับดึงข้อมูลโพสต์ทั้งหมดของผู้ใช้ที่ล็อกอินอยู่
app.get('/posts', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // ดึง ID ของผู้ใช้จาก token
        const [results] = await pool.query('SELECT * FROM posts WHERE userId = ?', [userId]); // ดึงโพสต์เฉพาะของผู้ใช้
        res.json(results); // ส่งข้อมูลโพสต์ทั้งหมดกลับไปยัง client
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลโพสต์' });
    }
});

// เส้นทางสำหรับลบโพสต์ตาม ID
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query('DELETE FROM posts WHERE IDPOST = ? AND userId = ?', [id, req.user.id]); // ลบโพสต์เฉพาะของผู้ใช้
        res.status(204).json(); // ลบโพสต์สำเร็จ
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลบโพสต์' });
    }
});

// เส้นทางสำหรับอัปเดตโพสต์
app.put('/posts/:id', authenticateToken, upload.single('image'), async (req, res) => {
    const { id } = req.params; // ดึง ID ของโพสต์ที่ต้องการอัปเดต
    const { namepost, description } = req.body; // ดึงข้อมูลจาก body
    const userId = req.user.id; // ดึง ID ของผู้ใช้จาก token

    try {
        // ตรวจสอบข้อมูลที่รับเข้ามา
        if (!namepost || !description) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อโพสต์และรายละเอียดให้ครบถ้วน' });
        }

        let imagePath = '';
        if (req.file) {
            imagePath = `/uploads/${req.file.filename}`; // เก็บเส้นทางของรูปภาพ
        }

        // อัปเดตข้อมูลลงในตาราง posts
        await pool.query(
            'UPDATE posts SET namepost = ?, description = ?, image = ? WHERE IDPOST = ? AND userId = ?', // ต้องแน่ใจว่าผู้ใช้เป็นเจ้าของโพสต์
            [namepost, description, imagePath || null, id, userId]
        );

        res.status(200).json({ message: 'โพสต์ถูกอัปเดตเรียบร้อยแล้ว' });
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตโพสต์' });
    }
});
// เส้นทางสำหรับดึงข้อมูลผู้ใช้งานที่เข้าสู่ระบบ (ต้องยืนยันตัวตน)
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // ดึง ID ของผู้ใช้จาก token
        const [results] = await pool.query("SELECT email, name, picture, number, age, gender FROM users WHERE id = ?", [userId]);

        if (results.length === 0) {
            return res.status(404).json({ error: "ไม่พบผู้ใช้" });
        }

        res.json(results[0]); // ส่งข้อมูลผู้ใช้กลับไปยัง client
    } catch (err) {
        console.log('Error fetching user account:', err);
        res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้" });
    }
});
// เส้นทางสำหรับดึงข้อมูลโพสต์ทั้งหมด (ไม่ต้องการการตรวจสอบสิทธิ์)
app.get('/shirts', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM posts'); // ดึงโพสต์ทั้งหมด
        res.json(results); // ส่งข้อมูลโพสต์ทั้งหมดกลับไปยัง client
    } catch (error) {
        console.error('Error fetching shirts:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลเสื้อ' });
    }
});

// เส้นทางสำหรับอัปเดตโปรไฟล์ผู้ใช้
app.post('/updateProfile', authenticateToken, upload.single('profilePicture'), async (req, res) => {
    const userId = req.user.id;
    const { name, email, number, age, gender } = req.body; // ดึงข้อมูลจาก body

    try {
        // ตรวจสอบข้อมูลที่รับเข้ามา
        if (!name || !email || age === undefined || !gender) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อ, อีเมล, อายุ และเพศให้ครบถ้วน' });
        }

        let profilePicturePath = '';
        if (req.file) {
            profilePicturePath = `/uploads/${req.file.filename}`;
        }

        // สร้างคำสั่ง SQL เพื่ออัปเดตข้อมูล
        let updateQuery = 'UPDATE users SET name = ?, email = ?, age = ?, gender = ?';
        const queryParams = [name, email, age, gender];

        if (number) {
            updateQuery += ', number = ?';
            queryParams.push(number);
        }

        if (profilePicturePath) {
            updateQuery += ', picture = ?';
            queryParams.push(profilePicturePath);
        }

        updateQuery += ' WHERE id = ?';
        queryParams.push(userId);

        await pool.query(updateQuery, queryParams);
        res.status(200).json({ message: 'อัปเดตข้อมูลสำเร็จ' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตโปรไฟล์' });
    }
});
// เส้นทางสำหรับเพิ่มสินค้าลงตะกร้า
app.post('/cart', authenticateToken, async (req, res) => {
    const { shirtId } = req.body; // รับ shirtId จาก body ของคำขอ
    const userId = req.user.id; // รับ userId จาก token

    try {
        if (!shirtId) {
            return res.status(400).json({ message: 'shirtId is required' });
        }

        // ตรวจสอบว่า shirtId มีอยู่ในตาราง posts หรือไม่
        const [shirtExists] = await pool.query('SELECT * FROM posts WHERE IDPOST = ?', [shirtId]);
        if (shirtExists.length === 0) {
            return res.status(404).json({ message: 'Shirt not found' });
        }

        // เพิ่มข้อมูลลงในตาราง cart โดยใช้ userId
        await pool.query('INSERT INTO cart (userId, shirtId) VALUES (?, ?)', [userId, shirtId]);
        res.status(201).json({ message: 'Shirt added to cart' });
    } catch (error) {
        console.error('Error adding to cart:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// เส้นทางสำหรับดึงข้อมูลตะกร้าของผู้ใช้
app.get('/cart', authenticateToken, async (req, res) => {
    const userId = req.user.id; // รับ userId จาก token
    try {
        const [results] = await pool.query('SELECT * FROM cart WHERE userId = ?', [userId]); // ดึงตะกร้าของผู้ใช้
        res.json(results);
    } catch (error) {
        console.error('Error fetching cart items:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// เส้นทางสำหรับลบสินค้าจากตะกร้า
app.delete('/cart/:shirtId', authenticateToken, async (req, res) => {
    const { shirtId } = req.params; // รับ shirtId ที่ต้องการลบ

    try {
        await pool.query('DELETE FROM cart WHERE shirtId = ? AND userId = ?', [shirtId, req.user.id]); // ลบเฉพาะสินค้าของผู้ใช้
        res.status(204).send(); // ส่งสถานะ 204 (No Content)
    } catch (error) {
        console.error('Error removing from cart:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// เริ่มเซิร์ฟเวอร์
app.listen(port, () => {
    console.log(`เซิร์ฟเวอร์กำลังทำงานที่พอร์ต ${port}`);
});
