const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const morgan = require('morgan');
const path = require('path');
const nunjucks = require('nunjucks');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const multer = require('multer');
const archiver = require('archiver');
const fs = require('fs');

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // URL 인코딩된 데이터 파싱
app.use(cors());
app.set('port', process.env.PORT||3000);
app.set('view engine', 'html');
nunjucks.configure('views',{
    express: app,
    watch: true,
});
// MySQL 데이터베이스 연결 설정
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.error('데이터베이스 연결 실패:', err);
    return;
  }
  console.log('데이터베이스 연결 성공');
});

// 개발 환경에 따른 설정
// if (process.env.NODE_ENV === 'production') {
//   app.use(helmet({
//     contentSecurityPolicy: false,
//     crossOriginEmbedderPolicy: false,
//     crossOriginResourcePolicy: false,
//   }));
//   app.use(hpp());
//   app.use(morgan('combined'));
//   app.enable('trust proxy');
// } else {
//   app.use(morgan('dev'));
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
app.use('/logos', (req, res, next) => {
  next();
}, express.static(path.join(__dirname, 'logos')));
app.use(helmet({
  contentSecurityPolicy: {
      directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "*.amazonaws.com"]
      }
  },
  crossOriginEmbedderPolicy: false
}));

// MySQL 연결 설정
const pool = mysql.createPool({
  host: process.env.DB_HOST, // 데이터베이스 서버의 주소
  user: process.env.DB_USER, // 데이터베이스 사용자 이름
  password: process.env.DB_PASSWORD, // 해당 사용자의 비밀번호
  database: process.env.DB_NAME, // 사용할 데이터베이스 이름
  waitForConnections: true, // 연결이 없을 때 대기할지 여부
  connectionLimit: 10, // 동시에 처리할 수 있는 최대 연결 수
  queueLimit: 0 // 연결 요청 대기열의 최대 크기, 0은 무제한을 의미
});

// 로고 이미지를 저장할 디렉터리 생성
const logosDirectory = path.join(__dirname, 'logos');
if (!fs.existsSync(logosDirectory)){
    fs.mkdirSync(logosDirectory, { recursive: true });
}

// 가이드 파일 저장을 위한 설정
const guideFolderPath = path.join(__dirname, 'guide');
if (!fs.existsSync(guideFolderPath)) {
    fs.mkdirSync(guideFolderPath, { recursive: true });
}

// multer 설정
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, logosDirectory);
    },
    filename: function (req, file, cb) {
      const decodedAppName = decodeURIComponent(req.body.app_name);
      cb(null, `${decodedAppName}.jpg`); // 디코딩된 이름으로 저장
    }
});

const guideStorage = multer.diskStorage({
  destination: function (req, file, cb) {
      const folderName = req.body.encodedFolderName;
      const foldername = decodeURIComponent(req.body.encodedFolderName);
      if (!folderName) {
        console.error('folderName is undefined');
        cb(new Error('folderName is undefined'), false); // 적절한 에러 처리
        return;
    }
      const fullFolderPath = path.join(guideFolderPath, foldername);
      
      if (!fs.existsSync(fullFolderPath)) {
          fs.mkdirSync(fullFolderPath, { recursive: true });
      }
      cb(null, fullFolderPath);
  },
  filename: function (req, file, cb) {
      cb(null, file.originalname); // 원본 파일 이름으로 저장
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 300 * 1024 * 1024 // 최대 파일 크기를 10MB로 설정합니다.
  }
});

const guideUpload = multer({ storage: guideStorage });

// 중복 확인 엔드포인트
app.post('/checkDuplicate', (req, res) => {
  const { id } = req.body; // 클라이언트로부터 받은 id 값을 변수에 저장
  pool.getConnection((err, connection) => { // 데이터베이스 연결 풀에서 연결을 가져옴
    if (err) { // 연결 중 에러가 발생하면
      console.error('DB 연결 오류:', err);
      return res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답을 클라이언트에 전송
    }
    connection.query('SELECT * FROM users WHERE id = ?', [id], (error, results) => { // id를 사용하여 users 테이블에서 검색
      connection.release(); // 데이터베이스 연결을 풀로 반환
      if (error) { // 쿼리 실행 중 에러가 발생하면
        console.error('쿼리 실행 오류:', error);
        return res.status(500).json({ error: '서버 오류' }); // 서버 오류 응답을 클라이언트에 전송
      }
      if (results.length > 0) { // 결과가 존재하면 중복임
        return res.status(203).json({ available: true }); // 중복 응답 전송
      }
      res.status(200).json({ available: false }); // 중복이 아닌 경우 응답 전송
    });
  });
});

// 회원가입 엔드포인트
app.post('/signup', async (req, res) => {
  const { id, password, name, phoneNumber, email } = req.body;

  try {
    let hashedPassword;
    try {
      hashedPassword = await bcrypt.hash(password, 10);
    } catch (hashError) {
      console.error('비밀번호 해싱 오류:', hashError);
      return res.status(500).json({ error: '비밀번호 해싱 중 오류 발생' });
    }

    pool.getConnection(async (err, connection) => {
      if (err) {
        console.error('데이터베이스 연결 오류:', err);
        return res.status(500).json({ error: '데이터베이스 연결 오류' });
      }

      try {
        const token = jwt.sign({ id, name, email }, process.env.JWT_SECRET, { expiresIn: '90d' });
        await new Promise((resolve, reject) => {
          connection.query('INSERT INTO users (id, password, name, phoneNumber, email, token, lastLoginTime) VALUES (?, ?, ?, ?, ?, ?, NOW())', 
          [id, hashedPassword, name, phoneNumber, email, token], (queryError) => {
            if (queryError) {
              reject(queryError);
            } else {
              resolve();
            }
          });
        });

        res.status(201).json({ success: true, message: '회원가입 성공', token });
      } catch (queryError) {
        console.error('회원가입 쿼리 실행 오류:', queryError);
        res.status(500).json({ error: '회원가입 쿼리 실행 오류' });
      } finally {
        connection.release();
      }
    });
  } catch (error) {
    console.error('회원가입 처리 오류:', error);
    res.status(500).json({ error: '회원가입 처리 중 예기치 않은 오류 발생' });
  }
});

// 회원탈퇴 엔드포인트
app.post('/deleteAccount', async (req, res) => {
  const userId = req.body.userId;

  if (!userId) {
    return res.status(400).send({ error: true, message: '아이디 제공 요청' });
  }

  const deleteQuery = 'DELETE FROM users WHERE id = ?';

  pool.query(deleteQuery , [userId],(err, results) => {
    if (err) {
      console.error('DB 쿼리 실행 중 오류 발생:', err);
      return res.status(500).send('삭제하는데 오류 생김');
    }
    res.status(200).json({ success: true, message: '정상적으로 삭제됨', guides: results });
  }
);


});


// 로그인 엔드포인트
app.post('/login', async (req, res) => {
  const { id, password } = req.body; // 클라이언트로부터 받은 id, password 값을 변수에 저장

  pool.getConnection(async (err, connection) => { // 데이터베이스 연결 풀에서 연결을 가져옴
    if (err) { // 연결 중 에러가 발생하면
      console.error('DB 연결 오류:', err);
      return res.status(500).json({ error: 'DB 연결 오류' }); // 서버 오류 응답을 클라이언트에 전송
    }
    connection.query('SELECT * FROM users WHERE id = ?', [id], async (error, results) => { // id를 사용하여 users 테이블에서 검색
      if (error || results.length === 0) { // 쿼리 실행 중 에러가 발생하거나 결과가 없으면
        connection.release(); // 쿼리 실행 후 데이터베이스 연결 해제
        return res.status(404).json({ error: '사용자를 찾을 수 없음' }); // 사용자를 찾을 수 없음 응답 전송
      }

      const user = results[0]; // 검색된 첫 번째 사용자
      // 마지막 로그인 시간 검증 로직 추가
      const lastLoginTime = new Date(user.lastLoginTime);
      const currentTime = new Date();
      const threeMonthsAgo = new Date(currentTime.setMonth(currentTime.getMonth() - 3));

      if (lastLoginTime < threeMonthsAgo) {
          // 마지막 로그인 시간이 3개월 이전인 경우, 사용자를 로그아웃 상태로 만들고 로그인을 거부합니다.
          connection.release();
          return res.status(401).json({ error: '3개월 이상 미접속으로 인해 로그아웃 되었습니다. 다시 로그인해 주세요.' });
      }
      
      // 비밀번호 검증
      const isPasswordValid = await bcrypt.compare(password, user.password); // 입력된 비밀번호와 해싱된 비밀번호 비교
      if (!isPasswordValid) { // 비밀번호가 일치하지 않으면
        connection.release(); // 쿼리 실행 후 데이터베이스 연결 해제
        return res.status(401).json({ error: '잘못된 비밀번호' }); // 잘못된 비밀번호 응답 전송
      }

      // 로그인 시각 업데이트 및 기존 토큰 반환
      connection.query('UPDATE users SET lastLoginTime = NOW() WHERE id = ?', [id], (updateError) => { // 로그인 시각을 현재 시각으로 업데이트
        connection.release(); // 쿼리 실행 후 데이터베이스 연결 해제
        if (updateError) { // 쿼리 실행 중 에러가 발생하면
          console.error('로그인 시각 업데이트 오류:', updateError);
          return res.status(500).json({ error: '로그인 시각 업데이트 오류' }); // 서버 오류 응답을 클라이언트에 전송
        }
        res.status(200).json({ success: true, message: '로그인 성공', token: user.token }); // 로그인 성공 응답 전송
      });
    });
  });
});

// 사용자 토큰 및 마지막 로그인 시간 업데이트 엔드포인트
app.post('/updateTokenAndLastLogin', async (req, res) => {
  const { userId } = req.body;
  
  // 데이터베이스 연결 및 쿼리 실행
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('DB 연결 오류:', err);
      return res.status(500).json({ success: false, message: 'DB 연결 오류' });
    }

    // 새로운 토큰 생성
    const newToken = jwt.sign({ userId }, 'your_jwt_secret', { expiresIn: '90d' });

    // 사용자의 토큰 및 마지막 로그인 시간 업데이트
    connection.query('UPDATE users SET token = ?, lastLoginTime = NOW() WHERE id = ?', [newToken, userId], (error, results) => {
      connection.release();
      if (error) {
        console.error('쿼리 실행 오류:', error);
        return res.status(500).json({ success: false, message: '쿼리 실행 오류' });
      }

      if (results.affectedRows > 0) {
        res.json({ success: true, token: newToken });
      } else {
        res.status(404).json({ success: false, message: '사용자를 찾을 수 없음' });
      }
    });
  });
});

// '/fetchAppList' 경로에서 GET 요청 처리
app.get('/fetchAppList', (req, res) => {
  pool.query('SELECT * FROM appNameList', (err, results) => {
    if (err) {
      console.error('DB 쿼리 실행 중 오류 발생:', err);
      res.status(500).send('Server error');
      return;
    }
    res.json({ success: true, apps: results });
  });
});

// 앱 추가 엔드포인트
app.post('/uploadFileAndData', upload.single('uploaded_file'), (req, res) => {
  const appName = decodeURIComponent(req.body.app_name);
  if (!appName) {
    return res.status(400).send('앱 이름이 필요합니다.');
  }
  const logoPath = req.file.path;
  const logoUrl = `${req.protocol}://${req.get('host')}/logos/${path.basename(logoPath)}`;
  
  // DB에 앱 이름과 로고 URL 저장
  const query = 'INSERT INTO appNameList (name, logoUrl) VALUES (?, ?)';
  pool.query(query, [appName, logoUrl], (err, result) => {
    if (err) {
        console.error('DB 쿼리 실행 중 오류 발생:', err);
        return res.status(500).send('DB 쿼리 실행 중 오류 발생');
    }


    // 앱 로고 업로드 및 저장 성공 후 appNameList 테이블 전체 내용 조회
    pool.query('SELECT * FROM appNameList', (err, results) => {
      if (err) {
        console.error('DB 쿼리 실행 중 오류 발생:', err);
        return res.status(500).send('Server error');
      }
      // appNameList 테이블의 전체 내용을 함께 응답으로 보냄
      res.status(200).json({ success: true, message: '앱 로고 업로드 및 저장 성공', apps: results });
    });
  });
});

// 파일 업로드 및 데이터베이스 저장
app.post('/uploadGuide', guideUpload.array('files'), (req, res) => {
  const folderName = req.body.encodedFolderName;
  if (!folderName) {
    return res.status(400).send('No folder name provided');
}
  const foldername = decodeURIComponent(folderName);
  const folderPath = `${req.protocol}://${req.get('host')}/guide/${foldername}`;

  // 폴더 이름을 '-'를 기준으로 나누어 각 변수에 할당합니다.
  const [appname, userid, guidename, privacySetting] = folderName.split('-');
  const appName = decodeURIComponent(appname);
  const userId = decodeURIComponent(userid);
  const guideName = decodeURIComponent(guidename);

  const logoUrl = `${req.protocol}://${req.get('host')}/logos/${appName}.jpg`;


  // 데이터베이스에 저장할 쿼리를 작성합니다.
  const query = 'INSERT INTO guideList (appName, userId, guideName, privacySetting, folderPath, logoPath) VALUES (?, ?, ?, ?, ?, ?)';
  pool.query(query, [appName, userId, guideName, privacySetting, folderPath, logoUrl], (err, result) => {
      if (err) {
          console.error('DB 쿼리 실행 중 오류 발생:', err);
          return res.status(500).send('DB 쿼리 실행 중 오류 발생');
      }
      // 성공적으로 파일을 저장하고 데이터베이스에 정보를 저장했을 때 응답을 보냅니다.
      res.status(200).json({ success: true, message: '폴더 및 파일 업로드 및 데이터 저장 성공', folderPath: folderPath });
  });
});

// 앱 가이드 리스트를 가져오는 API
app.get('/appGuideList', (req, res) => {
  const appName = req.query.appName; // 쿼리 파라미터에서 앱 이름 추출
  const userId = req.query.userId; // 사용자 ID도 쿼리 파라미터로 받습니다.
  if (!appName) {
    return res.status(400).json({ error: 'appName parameter is required' });
  }
  if (!userId) {
    return res.status(400).json({ error: 'userId parameter is required' });
  }
  // guideList와 favoriteGuideList를 결합하여 쿼리 실행
  const query = `
    SELECT g.*, 
    CASE WHEN f.userId IS NOT NULL THEN true ELSE false END AS isFavorite
    FROM guideList g
    LEFT JOIN favoriteGuideList f ON g.id = f.guideId AND f.userId = ?
    WHERE g.appName = ? AND g.privacySetting = 'public';
  `;

  pool.query(query , [userId, appName],(err, results) => {
      if (err) {
        console.error('DB 쿼리 실행 중 오류 발생:', err);
        return res.status(500).send('Server error');
      }
      // 결과가 비어있지 않은 경우, 가이드 리스트 정보 전송
      if (results.length > 0) {
        res.status(200).json({ success: true, message: '가이드 리스트 존재', guides: results });
      } else {
        res.status(404).json({ success: false, message: '가이드 리스트가 존재하지 않음' });
      }
    }
  );
});

// 즐겨찾기 목록 데이터베이스 저장 및 삭제
app.post('/updateFavorite', guideUpload.array('files'), (req, res) => {
  const guideId = req.body.id;
  const appName = decodeURIComponent(req.body.appName);
  const guideName = decodeURIComponent(req.body.guideName);
  const userId = req.body.userId;
  const isFavorite = req.body.isFavorite;
  const logoUrl = `${req.protocol}://${req.get('host')}/logos/${appName}.jpg`;

  console.log(userId)

  if(isFavorite === 'true'){
    const insertQuery = 'INSERT INTO favoriteGuideList (guideId, guideName, appName, userId, logoPath) VALUES (?, ?, ?, ?, ?)';
    pool.query(insertQuery, [guideId, guideName, appName, userId, logoUrl], (err, result) => {
      if (err) {
          console.error('DB 쿼리 실행 중 오류 발생:', err);
          return res.status(500).send('DB 쿼리 실행 중 오류 발생');
      }
      // 성공적으로 파일을 저장하고 데이터베이스에 정보를 저장했을 때 응답을 보냅니다.
      res.status(200).json({ success: true, message: '즐겨찾기 데이터베이스 추가 성공'});
   });
  }else{
    const deleteQuery = 'DELETE FROM favoriteGuideList WHERE guideId = ? AND userId = ?';
    pool.query(deleteQuery, [guideId, userId], (err, result) => {
      if (err) {
          console.error('DB 쿼리 실행 중 오류 발생:', err);
          return res.status(500).send('DB 쿼리 실행 중 오류 발생');
      }
      // 성공적으로 파일을 저장하고 데이터베이스에 정보를 저장했을 때 응답을 보냅니다.
      res.status(200).json({ success: true, message: '즐겨찾기 데이터베이스 삭제 성공'});
   });
  }
});

// 공개 비공개 여부 데이터베이스 저장 및 삭제
app.post('/updatePrivacySetting', guideUpload.array('files'), (req, res) => {
  const guideId = req.body.id;
  const appName = decodeURIComponent(req.body.appName);
  const guideName = decodeURIComponent(req.body.guideName);
  const userId = req.body.userId;
  const isPrivacySetting = req.body.isPrivacySetting;
  const logoUrl = `${req.protocol}://${req.get('host')}/logos/${appName}.jpg`;

  if(isPrivacySetting === "public"){
    const query = 'UPDATE guideList SET privacySetting = ? WHERE id = ? AND userId = ?';
    pool.query(query, [isPrivacySetting, guideId, userId], (err, result) => {
      if (err) {
          console.error('DB 쿼리 실행 중 오류 발생:', err);
          return res.status(500).send('DB 쿼리 실행 중 오류 발생');
      }
      // 성공적으로 파일을 저장하고 데이터베이스에 정보를 저장했을 때 응답을 보냅니다.
      res.status(200).json({ success: true, message: '공개 여부 데이터베이스 업데이트 성공'});
   });
  }else if(isPrivacySetting === "private"){
    const query = 'UPDATE guideList SET privacySetting = ? WHERE id = ? AND userId = ?';
    pool.query(query, [isPrivacySetting, guideId, userId], (err, result) => {
      if (err) {
          console.error('DB 쿼리 실행 중 오류 발생:', err);
          return res.status(500).send('DB 쿼리 실행 중 오류 발생');
      }
      // 성공적으로 파일을 저장하고 데이터베이스에 정보를 저장했을 때 응답을 보냅니다.
      res.status(200).json({ success: true, message: '비공개 여부 데이터베이스 업데이트 성공'});
   });
  }
});


// 즐겨찾기 리스트 출력
app.get('/favoriteGuideList', (req, res) => {
  const userId = req.query.userId; // 사용자 ID도 쿼리 파라미터로 받습니다.
  if (!userId) {
    return res.status(400).json({ error: 'userId parameter is required' });
  }
  // guideList와 favoriteGuideList를 결합하여 쿼리 실행
  const query = `
    SELECT * FROM favoriteGuideList WHERE userId = ?;
  `;
  pool.query(query , [userId],(err, results) => {
      if (err) {
        console.error('DB 쿼리 실행 중 오류 발생:', err);
        return res.status(500).send('Server error');
      }
      // 결과가 비어있지 않은 경우, 가이드 리스트 정보 전송
      if (results.length > 0) {
        res.status(200).json({ success: true, message: '가이드 리스트 존재', guides: results });
      } else {
        res.status(404).json({ success: false, message: '가이드 리스트가 존재하지 않음' });
      }
    }
  );
});

// 즐겨찾기 리스트 출력
app.get('/myGuideList', (req, res) => {
  const userId = req.query.userId; // 사용자 ID도 쿼리 파라미터로 받습니다.
  if (!userId) {
    return res.status(400).json({ error: 'userId parameter is required' });
  }
  // guideList와 favoriteGuideList를 결합하여 쿼리 실행
  const query = `
    SELECT * FROM guideList WHERE userId = ?;
  `;
  pool.query(query , [userId],(err, results) => {
      if (err) {
        console.error('DB 쿼리 실행 중 오류 발생:', err);
        return res.status(500).send('Server error');
      }
      // 결과가 비어있지 않은 경우, 가이드 리스트 정보 전송
      if (results.length > 0) {
        res.status(200).json({ success: true, message: '가이드 리스트 존재', guides: results });
      } else {
        res.status(404).json({ success: false, message: '가이드 리스트가 존재하지 않음' });
      }
    }
  );
});

app.post('/downloadFolder', (req, res) => {
  const foldername = req.body.foldername;

  // 디버깅을 위한 로그 추가
  console.log('Received foldername:', foldername);

  // foldername이 정의되지 않았을 경우에 대한 처리
  if (!foldername) {
      return res.status(400).send('foldername is required');
  }

  const folderPath = path.join(__dirname, 'guide', foldername);

  if (fs.existsSync(folderPath) && fs.lstatSync(folderPath).isDirectory()) {
      res.setHeader('Content-Type', 'application/zip');
      
      // 파일 이름을 안전하게 인코딩하여 설정
      const encodedFilename = encodeURIComponent(`${foldername}.zip`);
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodedFilename}`);

      const archive = archiver('zip', {
          zlib: { level: 9 }
      });

      archive.on('error', (err) => {
          throw err;
      });

      archive.pipe(res);

      archive.directory(folderPath, false);
      archive.finalize();
  } else {
      res.status(404).send('Folder not found');
  }
});


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
app.use('/api', authenticateToken);

app.get('/favicon.ico', (req, res)=>{
    res.status(204).end();
});

app.use((req, res, next) =>{
    const error = new Error(`${req.method} ${req.url} 라우터가 없습니다.`);
    error.status=404;
    next(error);
});

app.use((error, req, res, next)=>{
    // 로컬 환경 변수에 오류 메시지와 오류 객체 저장
  res.locals.message = error.message;
  res.locals.error = process.env.NODE_ENV !== 'production' ? error : {};

  // 오류 상태 코드 설정 (기본값은 500)
  const statusCode = error.status || 500;
  
  // HTTP 상태 코드를 설정하고 클라이언트에 오류 메시지를 전달
  res.status(statusCode);

  // 오류 로깅을 위해 콘솔에 출력
  console.error(`[${new Date().toUTCString()}] Error (${statusCode}): ${error.message}`);
  console.error(error.stack);
});

app.listen(app.get('port'),()=>{
    console.log(app.get('port'), '번 포트에서 대기중');
});