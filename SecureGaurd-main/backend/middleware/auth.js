const jwt = require('jsonwebtoken');

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Enforce the Bearer scheme: any other scheme (or a bare token) is
  // rejected rather than silently accepted.
  if (!authHeader || !/^Bearer /i.test(authHeader)) {
    return res.status(401).json({ message: 'No token provided' });
  }
  const token = authHeader.slice('Bearer '.length);
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};
