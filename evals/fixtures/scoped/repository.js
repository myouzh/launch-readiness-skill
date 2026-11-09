import { PrismaClient } from '@prisma/client';
const db = new PrismaClient();
export function scopedDocuments(user) {
  if (!user.tenantId) throw new Error('missing tenant');
  return { read: id => db.document.findFirst({ where: { id, tenantId: user.tenantId } }) };
}
