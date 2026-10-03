const test = require('node:test');
const assert = require('node:assert/strict');
const { guideSourceExcerpt } = require('../lib/guideConversation');
const catalogs = { zh:require('../data/guide-catalog.json'), en:require('../data/guide-catalog.en.json') };
const slug = 'bay-area-101-city-exploration-living-guide';

for (const language of ['zh','en']) {
  test(`${language}: every one of 101 city profiles remains complete and isolated in a city-specific assistant excerpt`,()=>{
    const guide=catalogs[language].find(guide=>guide.slug===slug);
    assert.ok(guide);
    const records=guide.content.split(/\n\s*\n/).filter(record=>record.startsWith('City guide: '));
    assert.equal(records.length,101);
    assert.ok(guide.content.indexOf(records.at(-1))>30000);
    for(const record of records){
      const name=record.split('\n')[0].match(/^City guide: (.+) \| /)[1];
      for(const query of [`${name} city guide visit transport resident library parks`, `请问 ${name} 景点 半日游 新居民 交通停车`]){
        const excerpt=guideSourceExcerpt(guide,query);
        assert.ok(excerpt.length<=9000,query);
        assert.ok(excerpt.includes(record),`${query}: keep complete city facts, boundary notes and source links`);
        assert.equal(excerpt.match(/City guide: /g)?.length,1,`${query}: neighboring cities are not this city`);
      }
    }
  });
  test(`${language}: overlapping and Chinese city names select the intended profile; comparisons keep both`,()=>{
    const guide=catalogs[language].find(guide=>guide.slug===slug);
    assert.ok(guide);
    for(const [query,name] of [
      ['南旧金山 半日游','South San Francisco'],['旧金山 半日游','San Francisco'],
      ['East Palo Alto city guide','East Palo Alto'],['东帕洛阿尔托 半日游','East Palo Alto'],
      ['Los Altos Hills city guide','Los Altos Hills'],['半月灣 景點','Half Moon Bay'],
      ['圣何塞 图书馆 公园','San Jose'],['桑尼維爾 景點','Sunnyvale'],
    ]){
      const excerpt=guideSourceExcerpt(guide,query);
      assert.match(excerpt,new RegExp(`City guide: ${name} \\| `));
      assert.equal(excerpt.match(/City guide: /g)?.length,1,query);
    }
    const comparison=guideSourceExcerpt(guide,'Compare Palo Alto and East Palo Alto half-day visits');
    assert.match(comparison,/City guide: Palo Alto \| /);
    assert.match(comparison,/City guide: East Palo Alto \| /);
    assert.equal(comparison.match(/City guide: /g)?.length,2);
  });
}
