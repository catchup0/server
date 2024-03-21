const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const path = require('path');
const session = require('express-session');
const nunjucks = require('nunjucks');
const dotenv = require('dotenv');
const passport = require('passport');
const { Sequelize } = require('sequelize');
const sequelize = new Sequelize('smartguide', 'admin', 'kduCE2024', { host: 'database-1.cds8kiksuoav.ap-northeast-2.rds.amazonaws.com', dialect: 'mysql' });
const helmet = require('helmet');
const hpp = require('hpp');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models');


dotenv.config();
const pageRouter = require('./routes/page');
const authRouter = require('./routes/auth');
const { sequelize: db } = require('./models');
const passportConfig = require('./passport');

const app = express();
//passportConfig(); // 패스포트 설정
app.use(express.json());
app.set('port', process.env.PORT||3000);
app.set('view engine', 'html');
nunjucks.configure('views',{
    express: app,
    watch: true,
});
sequelize.sync({ force: false })
  .then(() => {
    console.log('데이터베이스 연결 성공');
  })
  .catch((err) => {
    console.error(err);
});

// 중복 확인 엔드포인트
app.post('/checkDuplicate', async (req, res) => {
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
app.post('/signup', async (req, res) => {
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
app.post('/login', async (req, res) => {
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

// if(process.env.NODE_ENV === 'production'){
//     app.use(helmet({
//         contentSecurityPolicy: false,
//         crossOriginEmbedderPolicy: false,
//         crossOriginResourcePolicy: false,
//     }));
//     app.use(hpp());
//     app.use(morgan('combined'));
//     app.enable('trust proxy');
// }else{
    
// }
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(session({
    resave: false,
    saveUninitialized: false,
    secret: process.env.COOKIE_SECRET,
    cookie:{
        httpOnly: true,
        secure: false,
    }
}));

// JWT 토큰 검증 미들웨어
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401); // 토큰이 없는 경우
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); // 토큰이 유효하지 않은 경우
      req.user = user;
      next();
    });
  };
  
  // 전역적으로 토큰 검증 미들웨어 적용
  app.use(authenticateToken);

app.use('/auth', authRouter);
app.use(passport.initialize());
app.use(passport.session());

app.use('/',pageRouter);

app.get('/favicon.ico', (req, res)=>{
    res.status(204).end();
});

app.use((req, res, next) =>{
    const error = new Error(`${req.method} ${req.url} 라우터가 없습니다.`);
    error.status=404;
    next(error);
});

app.use((error, req, res, next)=>{
    res.locals.message = error.message;
    res.locals.error = process.env.NODE_ENV !== 'production' ? error: {};
    res.status(error.status || 500);
    res.render('error');
});

app.listen(app.get('port'),()=>{
    console.log(app.get('port'), '번 포트에서 대기중');
});