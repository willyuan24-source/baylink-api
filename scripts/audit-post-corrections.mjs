import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import dns from 'node:dns';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

// Run a dry preview by default. This repairs only four audited public posts,
// preserves private contact fields, and never chooses an unverified sale price.
const apply = process.argv.includes('--apply');
const envPath = process.argv.find(value => value.startsWith('--env='))?.slice(6);
const backup = process.argv.find(value => value.startsWith('--backup='))?.slice(9);
if (!envPath || (apply && !backup)) throw new Error('Provide --env=<existing env file> and --backup=<new backup path> when applying.');
dns.setServers(['1.1.1.1', '8.8.8.8']);
const env = dotenv.parse(await readFile(envPath));
await mongoose.connect(env.MONGO_URI, { serverSelectionTimeoutMS: 10000 });
try {
  const posts = mongoose.connection.db.collection('posts');
  const ids = ['1781325604074', '1781325990346', '1781322600508', '1781322130277'];
  const originals = await posts.find({ id: { $in: ids }, authorId: '1779316048437' }, { projection: { _id: 0, id: 1, authorId: 1, title: 1, description: 1, budget: 1, updatedAt: 1 } }).toArray();
  const changes = originals.flatMap(post => {
    let title = post.title, description = post.description, budget = post.budget;
    if (post.id === ids[0] && title.endsWith('，45万') && budget === '售$410,000' && description.includes('售价为 45 万美元')) {
      title = title.replace('，45万', '（报价待确认）');
      budget = '报价待发布者确认';
      description = description.replace('售价为 45 万美元', '原帖不同字段的报价不一致，当前售价待发布者确认');
    }
    if ([ids[1], ids[2]].includes(post.id) && description.includes('适合单身或情侣居住')) {
      description = description.replace('，适合单身或情侣居住', '').replace('适合单身或情侣居住。', '');
      if (post.id === ids[2]) description = description.replace('房子随时可入住。', '当前空置状态及可入住日期，请联系发布者确认。');
    }
    if (post.id === ids[3] && description.includes('租金包含水费和垃圾处理费') && description.includes('#包水电')) {
      const seen = new Set();
      description = description.replace(/#([^\s#]+)/g, (tag) => {
        if (tag === '#包水电' || seen.has(tag.toLocaleLowerCase())) return '';
        seen.add(tag.toLocaleLowerCase()); return tag;
      }).replace(/[ \t]{2,}/g, ' ').trimEnd();
      description = description.replace('随时可以入住', '可入住日期请联系发布者确认');
    }
    return title !== post.title || description !== post.description || budget !== post.budget ? [{ before: post, after: { title, description, budget } }] : [];
  });
  console.log(JSON.stringify(changes.map(({ before, after }) => ({ id: before.id, before: { title: before.title, budget: before.budget, description: before.description }, after })), null, 2));
  if (!apply) { console.log(`Dry run: ${changes.length} conditional corrections.`); }
  else {
    if (changes.length !== 4) throw new Error('Original audited fields no longer all match; review before changing production.');
    await mkdir(dirname(backup), { recursive: true });
    await writeFile(backup, JSON.stringify({ savedAt: new Date().toISOString(), originals }, null, 2), { flag: 'wx' });
    for (const { before, after } of changes) {
      const result = await posts.updateOne({ id: before.id, authorId: before.authorId, title: before.title, description: before.description, budget: before.budget }, { $set: { ...after, updatedAt: Date.now() } });
      if (result.modifiedCount !== 1) throw new Error(`Concurrent edit detected for ${before.id}; stop and inspect backup.`);
    }
    const result = await posts.find({ id: { $in: ids } }, { projection: { _id: 0, id: 1, title: 1, description: 1, budget: 1 } }).toArray();
    for (const { before, after } of changes) {
      const saved = result.find(post => post.id === before.id);
      if (!saved || Object.entries(after).some(([key, value]) => saved[key] !== value)) throw new Error(`Readback mismatch for ${before.id}`);
    }
    console.log('Applied and read back all four corrections. No contact details or source-verification dates changed.');
  }
} finally { await mongoose.disconnect(); }
