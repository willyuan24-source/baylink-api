const crypto = require('node:crypto');
const { validDate, eventOccursOn } = require('./planner');
const { bayAreaDate } = require('./eventEngagement');
const cityAliases = require('../data/city-search-aliases.json');

// Pure plan computation. Candidates and route estimates must come from server
// retrieval tools, never from a model-written list of invented facts. Sources
// establish provenance, not a reservation or a guarantee of future operation.
const MAX_STOPS = 4;
const str = value => typeof value === 'string' ? value.trim() : '';
const arr = value => Array.isArray(value) ? value : [];
const amount = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100000 ? value : null;
const unique = values => [...new Set(values.filter(Boolean))];
const minute = value => /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(str(value)) ? Number(value.slice(0, 2)) * 60 + Number(value.slice(3)) : null;
const clock = value => Number.isInteger(value) && value >= 0 && value < 1440 ? `${String(Math.floor(value / 60)).padStart(2, '0')}:${String(value % 60).padStart(2, '0')}` : undefined;
const safeUrl = value => { try { const u = new URL(value); return u.protocol === 'https:' && !u.username && !u.password ? u.href : null; } catch { return null; } };
const normalized = value => str(value).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const city = value => Object.entries(cityAliases).find(([name, aliases]) => [name, ...aliases].some(alias => normalized(alias) === normalized(value)))?.[0] || str(value);
const cityInLabel = value => {
  const label = normalized(value);
  return Object.entries(cityAliases).flatMap(([name, aliases]) => [name, ...aliases].map(alias => ({ name, alias: normalized(alias) })))
    .sort((a, b) => b.alias.length - a.alias.length)
    .find(({ alias }) => /^[a-z]/.test(alias) ? new RegExp(`(?:^|[^a-z])${alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z])`).test(label) : label.includes(alias))?.name || null;
};
const sourceDate = value => validDate(str(value).slice(0, 10)) ? str(value).slice(0, 10) : null;
const key = row => `${row.kind}:${row.id}`;
const selectedKey = value => typeof value === 'string' ? value : value && `${value.kind}:${value.id}`;
const round = value => Math.round((value + Number.EPSILON) * 100) / 100;

function words(locale) {
  const en = locale === 'en', hant = locale === 'zh-Hant';
  const say = (english, hans, traditional = hans) => en ? english : hant ? traditional : hans;
  return { say,
    title: place => say(`${place || 'Bay Area'} day plan`, `${place || '湾区'}一日安排`, `${place || '灣區'}一日安排`),
    alternative: say('Alternative plan', '备选安排', '備選安排'),
    date: say('Choose one valid future date before arranging the day.', '请先选定一天，再安排具体行程。', '請先選定一天，再安排具體行程。'),
    noStops: say('No sourced option currently satisfies the hard constraints. Change a condition or search for more options.', '目前没有有来源的选项符合全部硬性条件，需要调整条件或继续查找。', '目前沒有有來源的選項符合全部硬性條件，需要調整條件或繼續查找。'),
    party: say('Confirm the party size and child ages before calculating the full admission total.', '完整门票合计还需要人数及儿童年龄。', '完整門票合計還需要人數及兒童年齡。'),
    start: say('Departure time is missing; the order below is a proposal, not a timed itinerary.', '出发时间未确定；以下为建议顺序，尚不是完整时间表。', '出發時間未確定；以下為建議順序，尚不是完整時間表。'),
    origin: say('The departure/return point is missing; door-to-door feasibility is unconfirmed.', '出发及返回地点未确定，尚不能确认全程可行性。', '出發及返回地點未確定，尚不能確認全程可行性。'),
    extras: say('Food, transport, parking and optional purchases are not yet included in the known amount.', '已知金额尚未包括未核实的餐饮、交通、停车及可选消费。', '已知金額尚未包括未核實的餐飲、交通、停車及可選消費。'),
    staleSelection: say('A previous selection no longer matches the updated constraints and was removed.', '此前选项已不符合修改后的条件，已移除并重新筛选。', '此前選項已不符合修改後的條件，已移除並重新篩選。'),
  };
}

function normalizeState(input = {}) {
  const children = arr(input.childAges ?? input.party?.childrenAges).filter(age => Number.isInteger(age) && age >= 0 && age <= 17);
  const adults = Number.isInteger(input.party?.adults) && input.party.adults >= 0 ? input.party.adults : null;
  const size = Number.isInteger(input.partySize) && input.partySize >= 1 && input.partySize <= 50 ? input.partySize : adults !== null && adults + children.length > 0 ? adults + children.length : null;
  const rawBudget = typeof input.budget === 'object' && input.budget !== null ? input.budget : {};
  const scope = input.budgetScope ?? rawBudget.scope;
  return { ...input, city: city(input.city || input.destinationCity),
    date: validDate(input.date) ? input.date : null,
    origin: typeof input.origin === 'object' && input.origin !== null ? str(input.origin.label || input.origin.city || input.origin.id) : str(input.origin),
    startTime: input.startTime || input.departureTime,
    finishBy: input.finishBy || input.returnBy,
    partySize: size, childAges: children,
    budget: amount(typeof input.budget === 'number' ? input.budget : rawBudget.limitUsd),
    budgetScope: ['total', 'group', 'all'].includes(scope) ? 'total' : 'person',
    budgetIncludes: rawBudget.includes === 'admission' || input.budgetIncludes === 'admission' ? 'admission' : 'all',
    excludedCities: arr(input.excludedCities).map(city),
    excludedCandidateIds: arr(input.excludedCandidateIds).map(selectedKey),
  };
}

function normalizeCandidate(row) {
  if (!row || typeof row !== 'object' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}$/.test(str(row.id)) || !str(row.title || row.name)) return null;
  const kind = row.kind === 'place' || (!row.startDate && row.kind !== 'event' && !row.date) ? 'place' : 'event';
  const sourceUrls = unique([row.officialUrl, ...arr(row.sourceUrls), ...arr(row.sources).map(source => source.url)].map(safeUrl));
  return { ...row, id: str(row.id), title: str(row.title || row.name).slice(0, 240), kind, city: city(row.city),
    sourceUrls, sourceIds: unique(arr(row.sourceIds).map(value => String(value)).slice(0, 20)),
    startDate: row.startDate || row.date, endDate: row.endDate || row.startDate || row.date,
    planning: row.planning && typeof row.planning === 'object' ? row.planning : {},
    external: row.external === true || row.origin === 'web' || row.sourceKind === 'web' || /^web-/.test(row.id),
    kindVerified: ['place', 'event'].includes(row.kind),
  };
}

function scheduleFor(row, date) {
  const s = row.planning.schedule;
  if (!s || !date || !safeUrl(s.sourceUrl) || !sourceDate(s.verifiedAt)) return null;
  if ((s.validFrom && date < s.validFrom) || (s.validThrough && date > s.validThrough)) return null;
  const hasDate = s.dates && Object.hasOwn(s.dates, date);
  const weekday = String(new Date(`${date}T12:00:00Z`).getUTCDay());
  const hasWeekly = s.weekly && Object.hasOwn(s.weekly, weekday);
  const rawWindows = hasDate ? s.dates[date] : hasWeekly ? s.weekly[weekday] : undefined;
  const windows = arr(rawWindows).filter(w => minute(w.open) !== null && minute(w.close) !== null && minute(w.close) > minute(w.open))
    .map(w => ({ open: w.open, close: w.close, ...(minute(w.lastEntry) !== null ? { lastEntry: w.lastEntry } : {}) }));
  const sessions = arr(s.sessions).filter(x => x.date === date && minute(x.start) !== null && (x.end === undefined || (minute(x.end) !== null && minute(x.end) > minute(x.start))))
    .map(x => ({ start: x.start, ...(x.end ? { end: x.end } : {}) })).sort((a, b) => a.start.localeCompare(b.start));
  const closed = Array.isArray(rawWindows) && rawWindows.length === 0 && !sessions.length;
  if (!closed && !windows.length && !sessions.length) return null;
  return { windows, sessions, closed,
    sourceUrl: safeUrl(s.sourceUrl), checkedAt: s.verifiedAt, note: str(s.note),
    dateSpecific: !!hasDate || sessions.length > 0,
  };
}

const restrictedPrice = row => {
  const label = `${row.costLabel || ''} ${row.planning.admissionNote || ''}`;
  const restricted = /(?:免费|免費|\bfree\b)[^。.;；]{0,55}(?:会员|會員|居民|学生|學生|儿童|兒童|[岁歲]|\b(?:for|to|with)\s+(?:all\s+)?(?:members?|residents?|students?|children|kids?|under\s+\d|a purchase)|\b(?:members?|residents?) only\b)|(?:会员|會員|居民|学生|學生|儿童|兒童|[岁歲]|\b(?:members?|residents?|students?|children|kids?|under\s+\d)\b)[^。.;；]{0,40}(?:免费|免費|\bfree\b)|\bfree\b[^.;。；]{0,80}\b(?:with|after|on|for)\b[^.;。；]{0,35}\b(?:purchase|purchases|spending|spend)\b|\b(?:buy one|get one|bogo)\b|买一送一|買一送一|(?:须|須|需先|需要)(?:购买|購買|消费|消費)/i.test(label);
  const extraOnly = /\bfree (?:parking|gift|book|drink|food|shipping)\b|免费(?:停车|礼物|书籍|饮料)|免費(?:停車|禮物|書籍|飲料)/i.test(label)
    && !/\bfree (?:general )?(?:admission|entry)\b|\b(?:admission|entry) (?:is )?free\b|(?:入场|入場|门票|門票|基础入场|基礎入場)(?:及停车|及停車)?免费|免费入场|免費入場|入場免費/i.test(label);
  return restricted || extraOnly;
};

// Numeric catalog admission is a price for an applicable ticket, not proof that
// every child, resident, member or party qualifies for that ticket. Tier pricing
// is used only when supplied as structured, sourced data by retrieval tools.
function admissionFor(row, state, w) {
  const p = row.planning, rule = p.admission && typeof p.admission === 'object' ? p.admission : {};
  const result = { knownTotal: 0, knownPerPerson: 0, unknowns: [], complete: false };
  const unknown = text => result.unknowns.push(`${row.title}: ${text}`);
  const unconfirmed = w.say('Admission/eligibility is unconfirmed; do not count it as free.', '入场费用或适用资格未确认，不能当作免费。', '入場費用或適用資格未確認，不能當作免費。');
  const hasSourcedRule = safeUrl(rule.sourceUrl) && sourceDate(rule.verifiedAt) && !rule.eligibility;
  const raw = amount(p.admissionUsd);
  const basic = raw !== null ? raw : row.cost === 'free' ? 0 : null;
  const restricted = restrictedPrice(row) || !!rule.eligibility || p.admissionEligibility;
  let all = hasSourcedRule ? amount(rule.allAgesUsd) : null;
  if (all === null && basic !== null && !restricted && (basic === 0 || p.admissionAppliesTo === 'all')) all = basic;
  const group = hasSourcedRule && rule.scope === 'group' ? amount(rule.groupUsd) : p.admissionScope === 'group' && !restricted ? basic : null;
  const adult = hasSourcedRule ? amount(rule.adultUsd) ?? (restricted ? null : basic) : restricted ? null : basic;
  if (group !== null) {
    const groupLimit = rule.maxPartySize ?? p.maxPartySize;
    if (!state.partySize || (Number.isInteger(groupLimit) && state.partySize > groupLimit)) unknown(unconfirmed);
    else { result.knownTotal = group; result.knownPerPerson = group / state.partySize; result.complete = true; }
  } else if (all !== null) {
    result.knownPerPerson = all;
    if (all === 0) { result.complete = true; }
    else if (!state.partySize) unknown(w.party);
    else { result.knownTotal = all * state.partySize; result.complete = true; }
  } else if (adult !== null && !(adult === 0 && restricted)) {
    result.knownPerPerson = adult;
    if (!state.partySize || state.partySize < state.childAges.length) unknown(w.party);
    else {
      result.knownTotal = adult * (state.partySize - state.childAges.length);
      result.complete = true;
      for (const age of state.childAges) {
        const child = hasSourcedRule && arr(rule.children).find(t => Number.isInteger(t.minAge) && Number.isInteger(t.maxAge) && age >= t.minAge && age <= t.maxAge && amount(t.usd) !== null && !t.eligibility);
        if (!child) { result.complete = false; unknown(w.say(`Admission for age ${age} is unconfirmed.`, `${age} 岁儿童的适用票价未确认。`, `${age} 歲兒童的適用票價未確認。`)); }
        else { result.knownTotal += child.usd; result.knownPerPerson = Math.max(result.knownPerPerson, child.usd); }
      }
    }
  } else unknown(unconfirmed);
  if (restricted && !hasSourcedRule) { result.complete = false; unknown(w.say('A conditional discount is listed; full-party eligibility is unconfirmed.', '记录含附条件优惠，尚未核实全体人员是否适用。', '記錄含附條件優惠，尚未核實全體人員是否適用。')); }
  if (result.knownPerPerson > 0 || result.knownTotal > 0) {
    if (hasSourcedRule && rule.feesIncluded === true) { /* Sourced all-in price. */ }
    else if (p.feesIncluded !== true) { result.complete = false; unknown(w.say('Mandatory ticket fees/taxes are unconfirmed.', '必要票务附加费及税费未确认。', '必要票務附加費及稅費未確認。')); }
  }
  result.knownTotal = round(result.knownTotal);
  result.knownPerPerson = round(result.knownPerPerson);
  if (basic !== null && (!restricted || (hasSourcedRule && (amount(rule.adultUsd) !== null || amount(rule.allAgesUsd) !== null)))) result.admissionUsd = basic;
  if (hasSourcedRule) result.sourceUrl = safeUrl(rule.sourceUrl);
  return result;
}

function rejectedReason(row, state, schedule, admission, w) {
  const no = (code, english, hans, hant) => ({ code, message: w.say(english, hans, hant) });
  if (!row.sourceUrls.length) return no('source_missing', 'No usable source.', '缺少可核对来源。', '缺少可核對來源。');
  if (!row.city) return no('city_missing', 'The destination city is missing.', '目的地城市尚未确认。', '目的地城市尚未確認。');
  if (row.external && (!row.kindVerified || row.verification !== 'page-verified' || !row.verifiedFacts?.city || (row.kind === 'event' && !row.verifiedFacts?.date))) return no('web_unverified', 'A search discovery still needs page verification of the city and event date.', '网上发现的选项仍需页面证据确认城市及活动日期。', '網上發現的選項仍需頁面證據確認城市及活動日期。');
  if (['closed', 'cancelled', 'canceled', 'suspended'].includes(row.status) || row.cancelled || row.suspended || row.planning.closed === true) return no('closed', 'Closed or cancelled.', '已关闭、取消或暂停。', '已關閉、取消或暫停。');
  if (/^(?:sold[_ -]?out|full|waitlist|waitlisted|unavailable)$/i.test(str(row.availability || row.planning.availability)) || row.soldOut === true) return no('full', 'Full or waitlist-only; no available admission is established.', '已满或仅限候补，不能作为可直接参加的安排。', '已滿或僅限候補，不能作為可直接參加的安排。');
  if (state.city && normalized(row.city) !== normalized(state.city)) return no('city_mismatch', 'Outside the selected city.', '不在所选城市。', '不在所選城市。');
  if (state.excludedCities.some(name => normalized(row.city) === normalized(name))) return no('city_excluded', 'City was explicitly excluded.', '用户已排除此城市。', '使用者已排除此城市。');
  if (state.region && state.region !== 'all' && row.region && row.region !== state.region) return no('region_mismatch', 'Outside the selected area.', '不在所选区域。', '不在所選區域。');
  if (state.setting && state.setting !== 'any' && row.planning.setting && row.planning.setting !== state.setting) return no('setting_mismatch', 'Does not match the requested indoor/outdoor setting.', '不符合指定的室内外条件。', '不符合指定的室內外條件。');
  if (state.excludedCandidateIds.includes(row.id) || state.excludedCandidateIds.includes(key(row))) return no('excluded', 'Previously excluded option.', '此前已排除此选项。', '此前已排除此選項。');
  if (row.kind === 'event' && state.date && (!validDate(row.startDate) || !validDate(row.endDate) || !eventOccursOn(row, state.date))) return no('date_mismatch', 'The event is not confirmed on the selected date.', '活动未确认在所选日期举行。', '活動未確認在所選日期舉行。');
  if (row.kind === 'event' && !row.occurrenceDates && !schedule && /每(?:周|週|星期|月)|\bevery\s+(?:week|month|mon|tue|wed|thu|fri|sat|sun)/i.test(`${row.dateLabel || ''} ${row.summary || ''}`)) return no('recurrence_unconfirmed', 'The recurring event needs a confirmed occurrence on this date.', '周期活动仍需要确认所选日期确有一场。', '週期活動仍需要確認所選日期確有一場。');
  if (schedule?.closed) return no('closed_on_date', 'Published hours say closed on this date.', '已公布时段显示当天不开放。', '已公布時段顯示當天不開放。');
  if (state.childAges.some(age => (Number.isFinite(row.planning.minAge) && age < row.planning.minAge) || (Number.isFinite(row.planning.maxAge) && age > row.planning.maxAge))
    || (state.childAges.length && /\b(?:18|21)\s*\+|adults?[- ]only|仅限成人|僅限成人/.test(`${row.title} ${row.summary || ''} ${row.costLabel || ''}`))) return no('age_mismatch', 'Does not meet the published age rules.', '不符合已公布年龄条件。', '不符合已公布年齡條件。');
  if (state.freeOnly && (!admission.complete || admission.knownPerPerson !== 0 || admission.knownTotal !== 0)) return no('free_unconfirmed', 'Unconditional free admission for this party is not established.', '尚未确认这组人员可免费入场。', '尚未確認這組人員可免費入場。');
  return null;
}

function routeFor(routes, from, to, state, cursor, now) {
  const ref = value => typeof value === 'string' ? value : value?.id;
  return arr(routes).find(route => {
    if (!route || ref(route.from) !== from || ref(route.to) !== to || !Number.isInteger(route.durationMinutes) || route.durationMinutes < 0 || route.durationMinutes > 720) return false;
    if (state.travelMode && state.travelMode !== 'any' && route.travelMode !== state.travelMode) return false;
    if (!route.provider && !safeUrl(route.sourceUrl)) return false;
    const checked = Date.parse(route.checkedAt);
    if (!Number.isFinite(checked) || checked > now + 60000 || now - checked > 86400000) return false;
    let date = route.date, departure = minute(route.departureTime);
    if (route.departureAt && Number.isFinite(Date.parse(route.departureAt))) {
      date = bayAreaDate(Date.parse(route.departureAt));
      const parts = new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Los_Angeles', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date(route.departureAt));
      departure = minute(parts);
    }
    if (date !== state.date) return false;
    // A rush-hour or transit estimate is not reusable for a different time.
    if (cursor !== null && (departure === null || Math.abs(departure - cursor) > 30)) return false;
    return true;
  });
}

function makePlan({ state, candidates, selectedIds, travelEstimates = [], now, locale, alternative = false, noAlternatives = false }) {
  const w = words(locale), checks = [], rejectedCandidates = [], unknowns = [], notes = [];
  const maxStops = Number.isInteger(state.maxStops) && state.maxStops > 0 ? Math.min(state.maxStops, MAX_STOPS) : MAX_STOPS;
  const returnToOrigin = state.returnToOrigin !== false;
  const check = (code, status, message, stopId) => checks.push({ code, status, message, ...(stopId ? { stopId } : {}) });
  if (!state.date || state.date < bayAreaDate(now)) check('date', 'fail', w.date);
  else check('date', 'pass', w.say(`Date: ${state.date} (Pacific time).`, `日期：${state.date}（湾区时间）。`, `日期：${state.date}（灣區時間）。`));
  const eligible = [];
  for (const row of candidates) {
    const schedule = scheduleFor(row, state.date), admission = admissionFor(row, state, w);
    const rejected = rejectedReason(row, state, schedule, admission, w);
    if (rejected) rejectedCandidates.push({ entityId: row.id, kind: row.kind, title: row.title, ...rejected });
    else eligible.push({ row, schedule, admission });
  }
  const requested = unique(arr(selectedIds ?? state.selectedCandidateIds).map(selectedKey));
  const originCity = cityInLabel(state.origin);
  const localityMessage = name => w.say(`Keep this proposal in ${name}; unverified cross-city transfers were removed.`, `本方案集中在 ${name}，未核实交通的跨城选项已移出。`, `本方案集中在 ${name}，未核實交通的跨城選項已移出。`);
  let selected = requested.length ? requested.map(id => eligible.find(x => x.row.id === id || key(x.row) === id)).filter(Boolean) : [];
  selected = selected.filter((item, index) => selected.findIndex(other => key(other.row) === key(item.row)) === index);
  if (requested.length && selected.length < requested.length) notes.push(w.staleSelection);
  if (!requested.length) {
    const anchor = eligible.find(item => normalized(item.row.city) === normalized(originCity)) || eligible[0];
    selected = anchor ? eligible.filter(item => normalized(item.row.city) === normalized(anchor.row.city)).slice(0, Math.min(3, maxStops)) : [];
  }
  // A model's selected IDs are preferences, not authority to assemble Fremont,
  // Novato and Burlingame into a day whose transfers have never been measured.
  if (selected.length > 1 && state.allowMultipleCities !== true) {
    const anchor = selected.find(item => normalized(item.row.city) === normalized(originCity)) || selected[0];
    const distant = selected.filter(item => normalized(item.row.city) !== normalized(anchor.row.city));
    if (distant.length) {
      notes.push(localityMessage(anchor.row.city));
      for (const item of distant) rejectedCandidates.push({ entityId: item.row.id, kind: item.row.kind, title: item.row.title, code: 'cross_city_unverified', message: localityMessage(anchor.row.city) });
      selected = selected.filter(item => normalized(item.row.city) === normalized(anchor.row.city));
    }
  }
  selected = selected.slice(0, maxStops);
  if (!selected.length) check('candidates', 'fail', w.noStops);
  if (!state.origin) check('origin', 'unknown', returnToOrigin ? w.origin : w.say('The departure point is missing; travel feasibility is unconfirmed.', '出发地点未确定，尚不能确认全程交通可行性。', '出發地點未確定，尚不能確認全程交通可行性。'));
  let cursor = minute(state.startTime);
  if (cursor === null) check('start_time', 'unknown', w.start);
  const finish = minute(state.finishBy);
  if (cursor !== null && finish !== null && finish <= cursor) check('day_window', 'fail', returnToOrigin
    ? w.say('Return time must be later than departure on this date.', '同日返回时间须晚于出发时间。', '同日返回時間須晚於出發時間。')
    : w.say('Finish time must be later than departure on this date.', '同日结束时间须晚于出发时间。', '同日結束時間須晚於出發時間。'));
  let previousId = state.origin ? 'origin' : null;
  const stops = [], legs = [], admissions = [];
  for (const { row, schedule, admission } of selected) {
    const id = key(row), p = row.planning;
    const stop = { id, kind: row.kind, entityId: row.id, title: row.title, city: row.city, date: state.date,
      timeStatus: 'unknown', sourceIds: [...row.sourceIds], sourceUrls: [...row.sourceUrls], notes: [],
      ...(row.venue ? { venue: row.venue } : {}), ...(row.path ? { path: row.path } : {}), ...(row.guideSlug ? { guideSlug: row.guideSlug } : {}),
      ...(row.location ? { location: { ...row.location } } : {}), external: row.external,
    };
    const previousStop = stops[stops.length - 1];
    if (previousStop && normalized(previousStop.city) !== normalized(row.city)
      && (state.allowMultipleCities !== true || cursor === null || !routeFor(travelEstimates, previousId, row.id, state, cursor, now))) {
      rejectedCandidates.push({ entityId: row.id, kind: row.kind, title: row.title, code: 'cross_city_unverified', message: localityMessage(previousStop.city) });
      notes.push(localityMessage(previousStop.city));
      continue;
    }
    if (previousId !== null) {
      const route = routeFor(travelEstimates, previousId, row.id, state, cursor, now);
      if (route) {
        legs.push({ from: previousId, to: row.id, durationMinutes: route.durationMinutes, travelMode: route.travelMode, provider: route.provider, checkedAt: route.checkedAt, status: 'estimate' });
        stop.travelMinutes = route.durationMinutes;
        if (cursor !== null) cursor += route.durationMinutes;
      } else {
        check('travel_time', 'unknown', w.say(`Travel to ${row.title} needs a route estimate for this departure time.`, `前往「${row.title}」的这段交通时间尚待查询。`, `前往「${row.title}」的這段交通時間尚待查詢。`), id);
        cursor = null;
      }
    }
    const desiredDuration = Number.isInteger(p.suggestedDurationMinutes) && p.suggestedDurationMinutes >= 5 && p.suggestedDurationMinutes <= 480 ? p.suggestedDurationMinutes : 60;
    stop.suggestedDurationMinutes = desiredDuration;
    if (schedule) {
      stop.sourceUrls = unique([...stop.sourceUrls, schedule.sourceUrl]);
      stop.scheduleCheckedAt = schedule.checkedAt;
      if (schedule.note) stop.notes.push(schedule.note);
      if (schedule.windows.length) stop.openingWindows = schedule.windows;
      if (schedule.sessions.length) stop.publishedSessions = schedule.sessions;
      if (schedule.sessions.length) {
        const session = schedule.sessions.find(s => cursor === null || minute(s.start) >= cursor);
        if (!session) {
          check('session_unreachable', 'fail', w.say(`The published session at ${row.title} starts before the calculated arrival.`, `按已知交通计算，赶不上「${row.title}」的已公布场次。`, `按已知交通計算，趕不上「${row.title}」的已公布場次。`), id);
          cursor = null;
        } else {
          stop.startTime = session.start; stop.timeStatus = 'verified';
          if (session.end) { stop.endTime = session.end; stop.durationMinutes = minute(session.end) - minute(session.start); cursor = minute(session.end); }
          else { cursor = null; check('end_time', 'unknown', w.say(`${row.title}: session end time is unconfirmed.`, `「${row.title}」场次结束时间未确认。`, `「${row.title}」場次結束時間未確認。`), id); }
          stop.notes.push(w.say('Published session time; a seat or booking has not been secured.', '这是已公布场次时间，尚未取得名额或完成预约。', '這是已公布場次時間，尚未取得名額或完成預約。'));
        }
      } else if (schedule.windows.length && cursor !== null) {
        const window = schedule.windows.find(win => Math.max(cursor, minute(win.open)) + desiredDuration <= minute(win.close) && (minute(win.lastEntry) === null || Math.max(cursor, minute(win.open)) <= minute(win.lastEntry)));
        if (!window) {
          check('opening_window', 'fail', w.say(`${row.title} does not fit within the published opening window.`, `「${row.title}」无法放入已公布开放时段。`, `「${row.title}」無法放入已公布開放時段。`), id); cursor = null;
        } else {
          const start = Math.max(cursor, minute(window.open));
          stop.startTime = clock(start); stop.endTime = clock(start + desiredDuration); stop.durationMinutes = desiredDuration; stop.timeStatus = 'suggested'; cursor = start + desiredDuration;
          stop.notes.push(w.say('Suggested visit within an opening window; it is not a booked session.', '开放窗口内的建议停留时间，不代表已预约场次。', '開放窗口內的建議停留時間，不代表已預約場次。'));
        }
      } else cursor = null;
      if (!schedule.dateSpecific) check('date_opening', 'unknown', w.say(`${row.title}: regular hours are recorded; special closure on this date is unconfirmed.`, `「${row.title}」有常规开放时间，所选日期临时调整仍待核实。`, `「${row.title}」有常規開放時間，所選日期臨時調整仍待核實。`), id);
    } else {
      cursor = null;
      check('opening_hours', 'unknown', w.say(`${row.title}: usable opening/session times for this date are missing.`, `「${row.title}」缺少可用于安排这一天的开放或场次时间。`, `「${row.title}」缺少可用於安排這一天的開放或場次時間。`), id);
    }
    if (p.reservation === 'required' || p.reservation === 'unknown' || !p.reservation) check('reservation', 'unknown', w.say(`${row.title}: confirm booking requirements and remaining availability.`, `「${row.title}」的预约要求或剩余名额仍待确认。`, `「${row.title}」的預約要求或剩餘名額仍待確認。`), id);
    if (state.setting && state.setting !== 'any' && !p.setting) check('setting', 'unknown', w.say(`${row.title}: indoor/outdoor suitability is unconfirmed.`, `「${row.title}」的室内外条件未确认。`, `「${row.title}」的室內外條件未確認。`), id);
    if (state.childAges.length && p.minAge === undefined && !p.allAges && !p.familyFriendly) check('child_access', 'unknown', w.say(`${row.title}: confirm child admission/access rules.`, `「${row.title}」的儿童参加及入场规则仍待确认。`, `「${row.title}」的兒童參加及入場規則仍待確認。`), id);
    const lastKnownTime = minute(stop.endTime) ?? minute(stop.startTime);
    if (finish !== null && lastKnownTime !== null && lastKnownTime > finish) check('finish_time', 'fail', returnToOrigin
      ? w.say(`${row.title} runs past the required return time, even before return travel.`, `「${row.title}」已超过要求返回时间，尚未计算回程。`, `「${row.title}」已超過要求返回時間，尚未計算回程。`)
      : w.say(`${row.title} runs past the required finish time.`, `「${row.title}」已超过要求结束时间。`, `「${row.title}」已超過要求結束時間。`), id);
    if (admission.admissionUsd !== undefined) stop.admissionUsd = admission.admissionUsd;
    stop.knownAdmissionTotalUsd = admission.knownTotal;
    stop.admissionStatus = admission.complete ? 'recorded' : 'incomplete';
    if (admission.sourceUrl) stop.sourceUrls = unique([...stop.sourceUrls, admission.sourceUrl]);
    if (row.costLabel) stop.notes.push(row.costLabel);
    stop.notes.push(...admission.unknowns);
    admissions.push(admission); stops.push(stop); previousId = row.id;
  }
  let returnTime;
  if (returnToOrigin && state.origin && stops.length) {
    const route = routeFor(travelEstimates, previousId, 'origin', state, cursor, now);
    if (route && cursor !== null) {
      const arrival = cursor + route.durationMinutes;
      returnTime = clock(arrival);
      legs.push({ from: previousId, to: 'origin', durationMinutes: route.durationMinutes, travelMode: route.travelMode, provider: route.provider, checkedAt: route.checkedAt, status: 'estimate' });
      check('return_time', finish !== null && arrival > finish || arrival >= 1440 ? 'fail' : 'pass', w.say(`Estimated return ${returnTime || 'after midnight'}; route estimates can change.`, `预计 ${returnTime || '午夜之后'} 返回；交通估算仍可能变化。`, `預計 ${returnTime || '午夜之後'} 返回；交通估算仍可能變化。`));
    } else check('return_time', 'unknown', w.say('The return journey/time has not been verified.', '回程交通及返回时间尚未核实。', '回程交通及返回時間尚未核實。'));
  }
  // A one-way day ends at its last stop. Keep the end constraint meaningful
  // without requesting, displaying or validating an unwanted return journey.
  if (!returnToOrigin && stops.length && finish !== null && !checks.some(item => item.code === 'finish_time' && item.status === 'fail')) {
    const last = stops[stops.length - 1], end = minute(last.endTime);
    check('finish_time', end === null ? 'unknown' : end > finish ? 'fail' : 'pass', end === null
      ? w.say('The final stop’s end time is unconfirmed; finishing by the requested time is not established.', '最后一站的结束时间尚未核实，不能确认按要求时间结束。', '最後一站的結束時間尚未核實，不能確認按要求時間結束。')
      : w.say(`The final stop is estimated to finish at ${last.endTime}; the finish-by requirement is ${state.finishBy}.`, `最后一站预计 ${last.endTime} 结束；要求最晚 ${state.finishBy} 结束。`, `最後一站預計 ${last.endTime} 結束；要求最晚 ${state.finishBy} 結束。`), last.id);
  }
  const knownTotalUsd = round(admissions.reduce((sum, admission) => sum + admission.knownTotal, 0));
  const knownPerPersonUsd = round(admissions.reduce((sum, admission) => sum + admission.knownPerPerson, 0));
  const unknownItems = unique(admissions.flatMap(admission => admission.unknowns));
  if (state.budgetIncludes !== 'admission') unknownItems.push(w.extras);
  const budget = { knownTotalUsd, knownPerPersonUsd, unknownItems, scope: state.budgetScope, ...(state.budget !== null ? { limitUsd: state.budget } : {}) };
  if (state.budget !== null) {
    const minimum = state.budgetScope === 'total' ? knownTotalUsd : knownPerPersonUsd;
    check('budget', minimum > state.budget ? 'fail' : unknownItems.length ? 'unknown' : 'pass', minimum > state.budget
      ? w.say('Known admission alone exceeds the budget.', '仅已知入场费用已超过预算。', '僅已知入場費用已超過預算。')
      : unknownItems.length ? w.say('The budget cannot be confirmed until the missing costs are known.', '费用仍有未知项，尚不能确认总安排符合预算。', '費用仍有未知項，尚不能確認總安排符合預算。')
        : w.say('Recorded admission fits the admission budget.', '已知门票符合门票预算。', '已知門票符合門票預算。'));
  }
  unknowns.push(...checks.filter(c => c.status === 'unknown').map(c => c.message), ...unknownItems);
  const status = checks.some(c => c.status === 'fail') ? 'needs_details' : unknowns.length ? 'needs_verification' : 'ready';
  const title = alternative ? w.alternative : w.title(state.city);
  const id = `baybay-${crypto.createHash('sha256').update(JSON.stringify({ date: state.date, ids: stops.map(s => s.id), city: state.city, start: state.startTime, end: state.finishBy, returnToOrigin, budget, party: state.partySize })).digest('hex').slice(0, 20)}`;
  const plan = { id, date: state.date, title, status, stops, budget, checks, alternatives: [], unknowns: unique(unknowns), notes, rejectedCandidates,
    constraints: { city: state.city || null, origin: state.origin || null, startTime: state.startTime || null, finishBy: state.finishBy || null,
      partySize: state.partySize, childAges: [...state.childAges], travelMode: state.travelMode || null, excludedCities: [...state.excludedCities], freeOnly: state.freeOnly === true,
      ...(state.maxStops ? { maxStops } : {}), ...(typeof state.returnToOrigin === 'boolean' ? { returnToOrigin } : {}) },
    travelLegs: legs, ...(returnTime ? { returnTime } : {}),
    summary: status === 'needs_details' ? w.say('This plan has an unresolved hard constraint; review the checks before using it.', '安排仍有硬性条件不成立，请先处理检查项。', '安排仍有硬性條件不成立，請先處理檢查項。')
      : status === 'needs_verification' ? w.say('Suggested order with sources. Missing hours, travel, eligibility and costs remain explicitly unconfirmed.', '已按条件列出有来源的建议顺序；缺少的时段、交通、资格与费用仍待核实。', '已按條件列出有來源的建議順序；缺少的時段、交通、資格與費用仍待核實。')
        : w.say('The supplied evidence supports this suggested plan; no bookings have been made.', '现有资料支持这份建议安排；尚未代为预约。', '現有資料支持這份建議安排；尚未代為預約。'),
  };
  const siteStops = stops.filter(stop => !stop.external).map(stop => ({ kind: stop.kind, id: stop.entityId }));
  if (state.date && siteStops.length) plan.handoff = { title, date: state.date, stops: siteStops };
  if (!noAlternatives && stops.length) {
    const other = eligible.find(x => !stops.some(stop => stop.id === key(x.row)));
    const alternativeIds = other ? normalized(other.row.city) === normalized(stops[0].city)
      ? [...stops.slice(0, -1).map(stop => stop.id), key(other.row)]
      : eligible.filter(item => normalized(item.row.city) === normalized(other.row.city)).slice(0, 3).map(item => key(item.row))
      : stops.length > 1 ? stops.slice(0, -1).map(stop => stop.id) : [];
    if (alternativeIds.length) plan.alternatives = [makePlan({ state, candidates, selectedIds: alternativeIds, travelEstimates, now, locale, alternative: true, noAlternatives: true })];
  }
  return plan;
}

function buildItinerary({ state = {}, candidates = [], selectedIds, travelEstimates = [], now = Date.now(), locale = 'zh-Hans' } = {}) {
  const instant = typeof now === 'function' ? now() : now;
  const timestamp = Number.isFinite(instant) ? instant : Date.now();
  const seen = new Set();
  const rows = arr(candidates).slice(0, 200).map(normalizeCandidate).filter(row => row && !seen.has(key(row)) && seen.add(key(row)));
  return makePlan({ state: normalizeState(state), candidates: rows, selectedIds, travelEstimates, now: timestamp, locale });
}

function replaceItineraryStop({ plan, state = {}, candidates = [], stopId, replacementId, travelEstimates = [], now = Date.now(), locale = 'zh-Hans' } = {}) {
  const old = arr(plan?.stops), index = old.findIndex(stop => stop.id === stopId || stop.entityId === stopId);
  if (index === -1) throw new Error('Unknown itinerary stop.');
  const selectedIds = old.map(stop => stop.id);
  selectedIds[index] = selectedKey(replacementId);
  return buildItinerary({ state: { ...plan?.constraints, date: plan?.date, ...state }, candidates, selectedIds, travelEstimates, now, locale });
}

module.exports = { buildItinerary, replaceItineraryStop };
