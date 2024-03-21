const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING(100),
    allowNull: false
  }
}, {
  timestamps: false,
  underscored: false,
  modelName: 'User',
  tableName: 'users',
  paranoid: false,
  charset: 'utf8',
  collate: 'utf8_general_ci'
});

module.exports = User;
