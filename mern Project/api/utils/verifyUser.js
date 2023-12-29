import jwt from 'jsonwebtoken';
import { errorHandler } from './error.js';

const JWT_SECRET = 'eoifkjefeu6193611986'

export const verifyToken = (req, res, next) => {
    const token = req.cookies.access_token;

    if(!token) return next(errorHandler(401, 'Unauthorized'));
        
    jwt.verify(token, JWT_SECRET, (err, user) => {
        console.log('Received token:', token);
        if (err) {
            console.error('Token verification failed:', err);
        return next(errorHandler(403, 'Forbidden', err.message));
        }
        req.user = user;
        next();
    });

};