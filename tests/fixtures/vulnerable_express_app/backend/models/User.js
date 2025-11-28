/**
 * User Model - Contains SQL Injection in raw queries
 */

const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: ':memory:',
    logging: false
});

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING
    },
    bio: {
        type: DataTypes.TEXT
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'user'
    }
});

// VULNERABILITY: CWE-89 - SQL Injection in custom finder (Line 40)
User.findByUsername = async function(username) {
    const query = `SELECT * FROM Users WHERE username = '${username}'`;
    const [users] = await sequelize.query(query);
    return users[0];
};

// VULNERABILITY: CWE-89 - SQL Injection in search (Line 47)
User.searchUsers = async function(searchTerm) {
    const query = `SELECT * FROM Users WHERE username LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`;
    const [users] = await sequelize.query(query);
    return users;
};

// Safe example - Using ORM properly (NOT a vulnerability)
User.findSafe = async function(id) {
    return await User.findByPk(id);
};

module.exports = { User, sequelize };
