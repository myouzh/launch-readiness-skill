import { PrismaClient } from '@prisma/client';
const db = new PrismaClient();
export async function getDocument(req, res) {
  const row = await db.document.findUnique({ where: { id: req.params.id } });
  if (!row) return res.sendStatus(404);
  return res.json(row);
}
