const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');

const SECRET = 'isolated-post-image-tests-no-provider-credentials';
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a/q8AAAAASUVORK5CYII=';
const cloudUrl = name => `https://res.cloudinary.com/test-post-cloud/image/upload/${name}.png`;
const postBody = (fields = {}) => ({ title: 'A complete image listing', description: 'A fictional listing used for isolated image tests.', category: '闲置', city: 'Oakland', type: 'provider', budget: '10', ...fields });
const existingPost = () => ({ ...postBody(), id: 'existing', authorId: 'owner', authorNickname: 'Fixture owner', imageUrls: [cloudUrl('original')],
  status: 'active', createdAt: 100, confirmedAt: 100, updatedAt: 100, isDeleted: false, likes: [], comments: [], reports: [], activePostOperations: 0,
  contactPreference: { mode: 'manual_approve', methods: [{ type: 'wechat', value: 'fixture-contact', enabled: true }] } });

async function fixture(t, upload, { existing = false } = {}) {
  const models = createMemoryModels({ User: [{ id: 'owner', nickname: 'Fixture owner', role: 'user', accountStatus: 'active' }], Post: existing ? [existingPost()] : [] });
  const create = t.mock.method(models.Post, 'create');
  const retrieved = [];
  const findOne = models.Post.findOne.bind(models.Post);
  t.mock.method(models.Post, 'findOne', query => {
    const result = findOne(query);
    const exec = result.exec.bind(result);
    result.exec = async () => {
      const document = await exec();
      if (document && typeof document.save === 'function') retrieved.push({ document, before: document.toObject(), save: t.mock.method(document, 'save') });
      return document;
    };
    return result;
  });
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, CLOUDINARY_CLOUD_NAME: 'test-post-cloud' },
    ...(upload ? { uploadPostImage: upload } : {}) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const token = jwt.sign({ id: 'owner', sessionIssuedAt: Date.now() }, SECRET, { expiresIn: '1h' });
  const request = async (method, body) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/posts${method === 'PUT' ? '/existing' : ''}`, {
      method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  return { request, models, create, retrieved };
}

for (const method of ['POST', 'PUT']) {
  test(`${method} refuses the whole image list when one upload fails and leaves post data untouched`, async t => {
    for (const failure of ['null', 'throw', 'unsafe']) await t.test(failure, async t => {
      let uploads = 0;
      const upload = async () => {
        if (++uploads === 1) return cloudUrl('successful-first-image');
        if (failure === 'throw') throw new Error('provider-private-diagnostic');
        return failure === 'unsafe' ? 'https://untrusted.example.test/provider-result.png' : null;
      };
      const f = await fixture(t, upload, { existing: method === 'PUT' });
      const before = structuredClone(f.models.Post.rows);
      const response = await f.request(method, postBody({ title: 'Edited title must not partially save', status: 'closed', imageUrls: [cloudUrl('retained'), PNG, PNG] }));
      assert.equal(response.status, 502);
      assert.equal(response.body.code, 'POST_IMAGE_UPLOAD_FAILED');
      assert.match(response.body.error, /图片上传失败.*帖子尚未保存/);
      assert.doesNotMatch(JSON.stringify(response.body), /provider-private|successful-first-image/);
      assert.equal(uploads, 2);
      assert.equal(f.create.mock.callCount(), 0);
      assert.deepEqual(f.models.Post.rows, before, 'no partial post or image list may be written');
      for (const { document, before, save } of f.retrieved) {
        assert.equal(save.mock.callCount(), 0);
        assert.deepEqual(document.toObject(), before, 'even the loaded edit document stays unchanged');
      }
    });
  });
}

test('missing and unsafe provider URLs fail closed without creating a post', async t => {
  for (const uploaded of [undefined, '', {}, PNG, '/default-covers/fixture.webp',
    'http://res.cloudinary.com/test-post-cloud/image/upload/photo.png', 'https://example.test/photo.png',
    'https://res.cloudinary.com/another-cloud/image/upload/photo.png', 'https://res.cloudinary.com/test-post-cloud/image/upload/',
    'https://user:private@res.cloudinary.com/test-post-cloud/image/upload/photo.png', 'https://res.cloudinary.com:8443/test-post-cloud/image/upload/photo.png']) {
    await t.test(String(uploaded), async t => {
      const f = await fixture(t, async () => uploaded);
      const response = await f.request('POST', postBody({ imageUrls: [PNG] }));
      assert.equal(response.status, 502);
      assert.equal(response.body.code, 'POST_IMAGE_UPLOAD_FAILED');
      assert.equal(f.create.mock.callCount(), 0);
      assert.deepEqual(f.models.Post.rows, []);
    });
  }
});

test('a failed batch keeps the account operation active until its other started upload settles', async t => {
  let markStarted, finishUpload, uploads = 0;
  const started = new Promise(resolve => { markStarted = resolve; });
  const f = await fixture(t, async () => {
    if (++uploads === 1) throw new Error('First image fails immediately');
    markStarted();
    return new Promise(resolve => { finishUpload = resolve; });
  });
  const pending = f.request('POST', postBody({ imageUrls: [PNG, PNG] }));
  await started;
  assert.ok(f.models.User.rows[0].activeAccountOperations > 0);
  assert.equal(f.create.mock.callCount(), 0);
  finishUpload(cloudUrl('second-image'));
  assert.equal((await pending).status, 502);
  assert.equal(f.models.User.rows[0].activeAccountOperations, 0);
  assert.equal(f.create.mock.callCount(), 0);
});

for (const method of ['POST', 'PUT']) {
  test(`${method} preserves image ordering, retained safe URLs and default covers when every upload succeeds`, async t => {
    let uploads = 0;
    const f = await fixture(t, async image => { assert.equal(image, PNG); return cloudUrl(`uploaded-${++uploads}`); }, { existing: method === 'PUT' });
    const images = ['/default-covers/fixture.webp', PNG, cloudUrl('existing'), PNG];
    const response = await f.request(method, postBody({ imageUrls: images }));
    const expected = [images[0], cloudUrl('uploaded-1'), images[2], cloudUrl('uploaded-2')];
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.imageUrls, expected);
    assert.deepEqual(f.models.Post.rows[0].imageUrls, expected);
    assert.equal(uploads, 2, 'retained image URLs are not re-uploaded');
    if (method === 'POST') assert.equal(f.create.mock.callCount(), 1);
    else assert.equal(f.retrieved[0].save.mock.callCount(), 1);
  });
}

test('editing without imageUrls preserves the images and an explicit empty list removes them without uploading', async t => {
  const upload = t.mock.fn(async () => { throw new Error('No upload is needed'); });
  const f = await fixture(t, upload, { existing: true });
  const first = await f.request('PUT', postBody({ title: 'Update text without changing images' }));
  assert.equal(first.status, 200);
  assert.deepEqual(first.body.imageUrls, [cloudUrl('original')]);
  const second = await f.request('PUT', postBody({ imageUrls: [] }));
  assert.equal(second.status, 200);
  assert.deepEqual(second.body.imageUrls, []);
  assert.equal(upload.mock.callCount(), 0);
});

test('invalid input is rejected before upload and the default test adapter cannot reach an external provider', async t => {
  const upload = t.mock.fn(async () => cloudUrl('unexpected'));
  const f = await fixture(t, upload);
  const invalid = await f.request('POST', postBody({ imageUrls: ['https://untrusted.example.test/photo.png'] }));
  assert.equal(invalid.status, 400);
  assert.equal(upload.mock.callCount(), 0);
  assert.equal(f.create.mock.callCount(), 0);
  const isolated = await fixture(t);
  const blocked = await isolated.request('POST', postBody({ imageUrls: [PNG] }));
  assert.equal(blocked.status, 502);
  assert.equal(isolated.create.mock.callCount(), 0);
});
