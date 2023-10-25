// Moved required modules up to the top of the file
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const createApp = () => {
    const app = express();
    app.use(express.json());
    app.use(cors({
        origin: '*',
        methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    }));

    return app;
}

const createPoolAndConnect = () => {
    const pool = new Pool({ // Database connection details moved to .env file
        connectionString: process.env.DB_URL,
        ssl: {
            rejectUnauthorized: false,
        },
    });

    pool.connect((err) => {
        err ? console.error('Error connecting to database:', err)
            : console.log('Connected to database');
    });

    return pool;
}

const pool = createPoolAndConnect();
const app = createApp();

const hashPassword = async (password) => {
    return await bcrypt.hash(password, 10);
}


     const verifyToken = (req, res, next) => {
         const token = req.headers.authorization;
         if (!token) {
             return res.status(401).json({error: "Unauthorized"});
         }

         jwt.verify(token, process.env.SECRET, (error, decoded) => {
             if (error) {
                 return res.status(401).json({error: "Unauthorized"});
             } else {
                 req.decoded = decoded;
                 next();
             }
         });
     };

const registerUser = async (userData) => {
    const {username, password, email} = userData;

    const hashedPassword = await hashPassword(password);

    const query = `
    INSERT INTO users (username, password, email) 
    VALUES ($1, $2, $3) RETURNING *
    `;

    const user = await pool.query(query, [username, hashedPassword, email]);

    return user.rows[0];
}

const loginUser = async (userData) => {
    const {username, password} = userData;
    const user = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

    if (user.rows.length === 0) {
        throw new Error('User not found');
    }

    const match = await bcrypt.compare(password, user.rows[0].password);

    if (!match) {
        throw new Error('Incorrect password');
    }

    let secret = process.env.SECRET;
    const token = jwt.sign({id: user.rows[0].id}, secret, {expiresIn: "1h"});

    return { token, user: user.rows[0] };
}

const getAllUsers = async () => {
    const users = await pool.query('SELECT * FROM users', []);
    return users.rows;
}

const getUserById = async (id) => {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return user.rows[0];
}

const updateUser = async (userData) => {
    const { id, username, email } = userData;
    const updatedUser = await pool.query('UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING *', [username, email, id]);
    return updatedUser.rows[0];
}

app.post('/api/register', async (req, res) => {
    try {
        const user = await registerUser(req.body);
        res.status(201).json({
            status: 'success',
            message: `User ${user.username} registered successfully`,
            data: user,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { token, user } = await loginUser(req.body);
        res.status(200).json({
            status: 'success',
            message: `User ${user.username} logged in successfully`,
            token,
            user,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.get('/api/users',verifyToken, async (req, res) => {
    try {
        const users = await getAllUsers();
        res.status(200).json({
            status: 'success',
            message: `Retrieved ${users.length} users`,
            data: users,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.get('/api/users/:id',verifyToken, async (req, res) => {
    try {
        const user = await getUserById(req.params.id);
        res.status(200).json({
            status: 'success',
            message: `Retrieved user with id ${req.params.id}`,
            data: user,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.put('/api/users/:id',verifyToken, async (req, res) => {
    try {
        const user = await updateUser({ id: req.params.id, ...req.body });
        res.status(200).json({
            status: 'success',
            message: `Updated user with id ${req.params.id}`,
            data: user,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.delete('/api/users/:id',verifyToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.status(200).json({
            status: 'success',
            message: `Deleted user with id ${req.params.id}`,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

const createJob = async (jobData, user_id) => {
    const {title, company, location, description, requirements} = jobData;
    const query = `
    INSERT INTO jobs (title, company, location, description, requirements, user_id) 
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `;

    const job = await pool.query(query, [title, company, location, description, requirements, user_id]);

    return job.rows[0];
}

const getJobs = async (userId, searchTerm = '', limit = 0) => {
    try {
        if (!searchTerm && userId && limit === 0) {
            const jobs = await pool.query("SELECT * FROM jobs WHERE user_id = $1 ORDER BY posted_at DESC", [userId]);
            return jobs.rows;
        } else if (searchTerm && userId && limit === 0) {
            const jobs = await pool.query("SELECT * FROM jobs WHERE user_id = $1 AND title ILIKE $2 ORDER BY posted_at DESC", [userId, `%${searchTerm}%`]);
            return jobs.rows;
        } else if (!searchTerm && userId && limit > 0) {
            const jobs = await pool.query("SELECT * FROM jobs WHERE user_id = $1 ORDER BY posted_at DESC LIMIT $2 ", [userId, limit]);
            return jobs.rows;
        } else if (searchTerm && userId && limit > 0) {
            const jobs = await pool.query("SELECT * FROM jobs WHERE user_id = $1 AND title ILIKE $2 ORDER BY posted_at DESC LIMIT $3", [userId, `%${searchTerm}%`, limit]);
            return jobs.rows;
        } else {
            throw new Error("Something went wrong");
        }
    } catch (error) {
        throw new Error(error.message);
    }
}

const getJob = async (userId, id) => {
    const job = await pool.query(
        "SELECT * FROM jobs WHERE user_id = $1 AND id = $2",
        [userId, id]
    );

    if (job.rows.length === 0) {
        throw new Error("Job not found");
    } else {
        return job.rows[0];
    }
}

const updateJob = async (jobData, userId, id) => {
    const {title, company, location, description, requirements, is_applied, updated_at} = jobData;
    const updatedJob = await pool.query(
        "UPDATE jobs SET title = $1, company = $2, location = $3, description = $4, requirements = $5, is_applied = $6, updated_at = $7 WHERE user_id = $8 AND id = $9 RETURNING *",
        [title, company, location, description, requirements, is_applied, updated_at, userId, id]
    );

    if (!updatedJob.rowCount) {
        throw new Error("Job not found");
    } else {
        return updatedJob.rows[0];
    }
}

const deleteJob = async (userId, id) => {
    await pool.query("DELETE FROM jobs WHERE user_id = $1 AND id = $2", [userId, id]);

}

app.post('/api/:user_id/jobs',verifyToken, async (req, res) => {
try {
        const newJob = await createJob(req.body, req.params.user_id);
        res.status(201).json({
            status: 'success',
            message: `Inserted job with id ${newJob.id}`,
            data: newJob,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.get('/api/:user_id/jobs',verifyToken, async (req, res) => {
    try {
        const jobs = await getJobs(req.params.user_id, req.query.search, req.query.limit);
        res.status(200).json({
            status: 'success',
            message: `Retrieved ${jobs.length} jobs`,
            data: jobs,
            pagination: {limit: req.query.limit}
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.get('/api/:user_id/jobs/:id',verifyToken, async (req, res) => {
    try {
        const job = await getJob(req.params.user_id, req.params.id);
        res.status(200).json({
            status: 'success',
            message: `Retrieved job with id ${req.params.id}`,
            data: job,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.put('/api/:user_id/jobs/:id',verifyToken, async (req, res) => {
    try {
        const updatedJob = await updateJob(req.body, req.params.user_id, req.params.id);
        res.status(200).json({
            status: 'success',
            message: `Updated job with id ${req.params.id}`,
            data: updatedJob,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});

app.delete('/api/:user_id/jobs/:id',verifyToken, async (req, res) => {
    try {
        await deleteJob(req.params.user_id, req.params.id);
        res.status(200).json({
            status: 'success',
            message: `Deleted job with id ${req.params.id}`,
        });
    }
    catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message,
        });
    }
});


app.listen(process.env.PORT, () => console.log(`Server listening on port ${process.env.PORT}`));