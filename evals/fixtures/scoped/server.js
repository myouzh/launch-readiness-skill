import express from 'express';
import { requireUser } from './auth.js';
import { getDocument } from './documents.js';
const app = express();
app.use('/api', requireUser);
app.get('/api/documents/:id', getDocument);
export default app;
