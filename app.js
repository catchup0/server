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