const express = require('express');
const morgan = require('morgan');
const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('smartguide', 'admin', 'kduCE2024', { host: 'database-1.cds8kiksuoav.ap-northeast-2.rds.amazonaws.com', dialect: 'mysql' });
const dotenv = require('dotenv');
const nunjucks = require('nunjucks');
const helmet = require('helmet');
const hpp = require('hpp');

dotenv.config();
const pageRouter = require('./routes/page.js');

const app = express();
app.use(express.json());
app.set('port', process.env.PORT||3000);
app.set('view engine', 'html');
nunjucks.configure('views',{
    express: app,
    watch: true,
});

if(process.env.NODE_ENV === 'production'){
    app.use(helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        crossOriginResourcePolicy: false,
    }));
    app.use(hpp());
    app.use(morgan('combined'));
    app.enable('trust proxy');
}else{
    app.use(morgan('dev'));
}
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.use('/',pageRouter);

// Beacons 테이블을 정의합니다.
const usertable = sequelize.define('usertable', {
    userID: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    userPW: DataTypes.STRING,
    : DataTypes.STRING

}, {
    freezeTableName: true,
    timestamps: false
});

app.get('/checkBeaconId', async (req, res) => {
    const beaconId = req.query.beaconId;
    console.log(beaconId)

    try {
        // 비콘 ID를 검색합니다.
        if (typeof beaconId === 'undefined') {
            throw new Error('beaconId is undefined');
        }
          
        // 이제 안전하게 쿼리를 실행할 수 있습니다.
        Beacon.findOne({ where: { BeaconID: beaconId }});

        // 비콘 ID가 데이터베이스에 존재하지 않으면 에러 메시지를 반환합니다.
        if (!beaconId) {
            res.status(400).send('비콘 아이디가 데이터베이스에 존재하지 않습니다.');
            return;
        }
        res.status(200).send("비콘 아이디가 데이터베이스에 존재합니다.");
    } catch (error) {
        console.error(error);
        res.status(500).send(`요청하는데 에러가 발생했습니다: ${error.message}`);
    }
});

app.get('/beacon', async (req, res) => {
    const { beaconId, token } = req.query;
    console.log(beaconId)
    console.log(token)

    try {
        // 비콘 ID를 검색합니다.
        const beacon = await Beacon.findOne({ where: { beaconId } });

        // 비콘 ID가 데이터베이스에 존재하지 않으면 에러 메시지를 반환합니다.
        if (!beacon) {
            res.status(400).send('비콘 아이디가 데이터베이스에 존재하지 않습니다.');
            return;
        }

        // 비콘 ID가 데이터베이스에 존재하면 토큰을 업데이트합니다.
        beacon.FCMtoken = token;
        await beacon.save();

        res.status(200).send('토큰이 성공적으로 업데이트 되었습니다.');
    } catch (error) {
        console.error(error);
        res.status(500).send(`요청하는데 에러가 발생했습니다: ${error.message}`);
    }
});


app.get('/favicon.ico', (req, res)=>{
    res.status(204).end();
});

app.use((req, res, next) =>{
    const error = new Error(`${req.method} ${req.url} 라우터가 없습니다.`);
    error.status=404;
    next(error);
});

app.use((error, req, res, next)=>{
    console.error(error);
    res.status(500).send(error.message);
});

app.listen(app.get('port'),()=>{
    console.log(app.get('port'));
});