// ./services/userService.js

module.exports = (pool, bcrypt, jwt) => {
    const hashPassword = async (password) => {
        const saltRounds = 10;
        return await bcrypt.hash(password, saltRounds);
    }

    const executeQuery = async (query, parameters) => {
        return await pool.query(query, parameters);
    }

    const registerUser = async (userData) => {
        const {username, password, email} = userData;

        const hashedPassword = await hashPassword(password);

        const query = `
        INSERT INTO users (username, password, email) 
        VALUES ($1, $2, $3) RETURNING *
        `;

        const user = await executeQuery(query, [username, hashedPassword, email]);

        return user.rows[0];
    }

    const login = async (userData) => {
        const {username, password} = userData;
        const user = await executeQuery("SELECT * FROM users WHERE username = $1", [username]);

        if (user.rows.length === 0) {
            throw new Error('User not found');
        }

        const match = await bcrypt.compare(password, user.rows[0].password);

        if (!match) {
            throw new Error('Incorrect password');
        }

        let secret = process.env.JWT_SECRET;
        const token = jwt.sign({id: user.rows[0].id}, secret, {expiresIn: "1h"});

        return { token, user: user.rows[0] };
    };

    const getAllUsers = async () => {
        const users = await executeQuery('SELECT * FROM users', []);
        return users.rows;
    };

    const getUserById = async (id) => {
        const user = await executeQuery('SELECT * FROM users WHERE id = $1', [id]);
        return user.rows[0];
    };

    const updateUser = async (userData) => {
        const { id, username, email } = userData;
        const updatedUser = await executeQuery('UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING *', [username, email, id]);
        return updatedUser.rows[0];
    };

    const deleteUser = async (id) => {
        const deletedUser = await executeQuery('DELETE FROM users WHERE id = $1', [id]);
        return (deletedUser.rowCount > 0);
    };

    return {
        registerUser,
        login,
        getAllUsers,
        getUserById,
        updateUser,
        deleteUser
    };
}