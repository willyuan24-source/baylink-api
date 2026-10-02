const test = require('node:test');
const assert = require('node:assert/strict');
const { inferFilters } = require('../lib/planner');

const TODAY = '2026-10-02';

test('explicit Chinese adult counts include 成年人 and retain existing adult wording', () => {
  for (const message of ['两个成年人', '兩個成年人', '两位成人', '兩位成人', '2 名成年人', '两个人', '两个大人', 'two adults']) {
    assert.equal(inferFilters(message, TODAY).partySize, 2, message);
  }
  assert.equal(inferFilters('两个成年人，不带孩子', TODAY).partySize, 2);
  assert.equal(inferFilters('成年人一起出游', TODAY).partySize, undefined);
});

test('adult counts add children once, whether counts or shared and separate ages are supplied', () => {
  const counted = inferFilters('两个成年人和两个孩子，5岁和12岁', TODAY);
  assert.equal(counted.partySize, 4);
  assert.deepEqual(counted.childAges, [5, 12]);
  const sharedAge = inferFilters('两位成年人和两个五岁孩子', TODAY);
  assert.equal(sharedAge.partySize, 4);
  assert.deepEqual(sharedAge.childAges, [5, 5]);
  const agesOnly = inferFilters('两个成年人带5岁和12岁的孩子', TODAY);
  assert.equal(agesOnly.partySize, 4);
  assert.deepEqual(agesOnly.childAges, [5, 12]);
});

test('an explicit party total remains authoritative over the adult and child breakdown', () => {
  const filters = inferFilters('一共四人，其中两个成年人和两个孩子，5岁和12岁', TODAY);
  assert.equal(filters.partySize, 4);
  assert.deepEqual(filters.childAges, [5, 12]);
  assert.throws(() => inferFilters('一共一人，两个成年人和两个孩子，5岁和12岁', TODAY), /同行总人数不能少于/);
});

test('Chinese adult counts retain the party-size bounds after adding children', () => {
  assert.equal(inferFilters('五十位成年人', TODAY).partySize, 50);
  for (const message of ['五十一位成年人', '51个成年人', '49个成年人和两个孩子', '零位成年人']) {
    assert.throws(() => inferFilters(message, TODAY), /同行总人数须为 1–50 人/, message);
  }
});

test('three-digit adult, child and total counts reach validation without suffix truncation', () => {
  for (const count of [100, 150, 151]) {
    for (const message of [
      `${count}个成年人`, `${count}位成人`, `${count} adults`,
      `两个成年人和${count}个孩子`, `两个成年人和${count}个五岁孩子`,
      `${count}人，其中两个成年人`, `party of ${count}`, `${count} people`, `2大${count}小`,
    ]) {
      assert.throws(() => inferFilters(message, TODAY), /同行总人数须为 1–50 人/, message);
    }
  }
});
