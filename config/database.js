// config/database.js
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('smartguide', 'admin', 'kduCE2024', {
  host: 'database-1.cds8kiksuoav.ap-northeast-2.rds.amazonaws.com',
  dialect: 'mysql'
});

module.exports = sequelize;
