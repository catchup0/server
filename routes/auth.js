const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/user');


// 중복 확인 엔드포인트
router.post('/checkDuplicate', async (req, res) => {
  try {
    // 클라이언트로부터 전달받은 아이디
    const { id } = req.body;

    // 중복 확인
    const existingUser = await User.findOne({ where: { id } });
    // 중복된 아이디인 경우
    if (existingUser) {
      return res.status(200).json({ isDuplicate: true });
    }

    // 중복되지 않은 아이디인 경우
    res.status(200).json({ isDuplicate: false });
  } catch (error) {
    console.error('중복 확인 오류:', error);
    // 서버 오류 시 클라이언트에게 오류 응답 전송
    res.status(500).json({ error: error.message });
  }
});

// 회원가입 엔드포인트
router.post('/signup', async (req, res) => {
  try {
    // 클라이언트로부터 전달받은 아이디와 비밀번호
    const { id, pw } = req.body;

    // 중복 확인
    const existingUser = await User.findOne({ where: { id } });
    if (existingUser) {
      return res.status(400).json({ error: '이미 사용 중인 아이디입니다' });
    }

    // 비밀번호 암호화
    const hashedPassword = await bcrypt.hash(pw, 10);

    // 사용자 생성
    await User.create({ id, pw: hashedPassword });

    // 회원가입 성공 응답 전송
    res.status(201).json({ message: '회원가입 성공' });
  } catch (error) {
    console.error('회원가입 오류:', error);
    // 서버 오류 시 클라이언트에게 오류 응답 전송
    let errorMessage = '서버 오류';
    if (error.name === 'SequelizeUniqueConstraintError') {
      errorMessage = '이미 존재하는 사용자 이름입니다.';
    }
    res.status(500).json({ error: errorMessage });
  }
});

// 로그인 엔드포인트
router.post('/login', async (req, res) => {
  try {
    // 클라이언트로부터 전달받은 아이디와 비밀번호
    const { id, pw } = req.body;

    // 해당 아이디로 사용자 조회
    const user = await User.findOne({ where: { id } });
    // 사용자가 존재하지 않는 경우
    if (!user) {
      return res.status(404).json({ error: '사용자를 찾을 수 없음' });
    }

    // 비밀번호 확인
    const isPasswordValid = await bcrypt.compare(pw, user.pw);
    // 비밀번호가 일치하지 않는 경우
    if (!isPasswordValid) {
      return res.status(401).json({ error: '잘못된 비밀번호' });
    }

    // 로그인 성공, JWT 토큰 생성
    const token = jwt.sign(
      { id: user.id }, // 토큰에 포함될 사용자 정보
      process.env.JWT_SECRET, // 비밀키
      { expiresIn: '90d' } // 토큰 만료 시간
    );

    // 쿠키에 JWT 토큰 저장
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // HTTPS를 사용할 경우 true로 설정
      maxAge: 90 * 24 * 60 * 60 * 1000 // 90일
    });

    // 로그인 성공 응답 전송
    res.status(200).json({ message: '로그인 성공', user });
  } catch (error) {
    console.error('로그인 오류:', error);
    // 서버 오류 시 클라이언트에게 오류 응답 전송
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
