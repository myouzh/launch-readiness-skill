import { scopedDocuments } from './repository.js';
export async function getDocument(req, res) {
  const row = await scopedDocuments(req.user).read(req.params.id);
  if (!row) return res.sendStatus(404);
  return res.json(row);
}
