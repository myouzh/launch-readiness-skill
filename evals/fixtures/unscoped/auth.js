import jwt from 'jsonwebtoken';
export function requireUser(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization.slice(7), process.env.JWT_SECRET);
    return next();
  } catch { return res.sendStatus(401); }
}
