/* API Trace v0.2 — browser-only Salesforce debug log analysis. No log data is sent to a server. */
const sample = `12:15:00.000 (1000000)|USER_INFO|[EXTERNAL]|005xx0000012345|dev@example.test|(GMT+05:30) India Standard Time (Asia/Kolkata)|GMT+05:30
12:15:00.010 (1010000)|EXECUTION_STARTED
12:15:00.015 (1020000)|CODE_UNIT_STARTED|[EXTERNAL]|01p000000000001|ServiceRequestController.submitRequest()
12:15:00.045 (1050000)|USER_DEBUG|[42]|DEBUG|Enqueued outbound integration job
12:15:00.120 (1120000)|METHOD_ENTRY|[1]|01p000000000002|PartnerApiService.sendRequest()
12:15:00.200 (1200000)|CALLOUT_REQUEST|[12]|System.HttpRequest[Endpoint=callout:Partner_API/v1/policies, Method=POST]
12:15:00.465 (1465000)|CALLOUT_RESPONSE|[12]|System.HttpResponse[Status=Too Many Requests, StatusCode=429]
12:15:00.470 (1470000)|EXCEPTION_THROWN|[45]|System.CalloutException: Partner API rate limit exceeded
12:15:00.480 (1480000)|FATAL_ERROR|System.CalloutException: Partner API rate limit exceeded
12:15:00.490 (1490000)|CUMULATIVE_LIMIT_USAGE
12:15:00.500 (1500000)|Number of SOQL queries: 3 out of 100
12:15:00.501 (1501000)|Number of query rows: 8 out of 50000
12:15:00.502 (1502000)|Number of callouts: 1 out of 100
12:15:00.503 (1503000)|Maximum CPU time: 124 out of 10000
12:15:00.510 (1510000)|CODE_UNIT_FINISHED|ServiceRequestController.submitRequest()
12:15:00.520 (1520000)|EXECUTION_FINISHED`;
let events = [], filename = 'salesforce-debug-sample.log', isSample = true, selected = null, warnings = [], callouts = [], limits = [], findings = [], securityFindings = [];
const $ = id => document.getElementById(id);
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function parseClock(raw) { const m = raw.match(/^(\d{2}):(\d{2}):(\d{2})\.(\d{1,6})/); if (!m) return null; return (+m[1]*3600 + +m[2]*60 + +m[3])*1000 + Number((m[4]+'000').slice(0,3)); }
function classify(raw, marker, statusCode) {
  if (/FATAL_ERROR|EXCEPTION_THROWN|EXCEPTION|\bERROR\b/i.test(marker + ' ' + raw) || (statusCode >= 400 && statusCode <= 599)) return 'ERROR';
  if (/LIMIT_USAGE|WARN(?:ING)?/i.test(marker + ' ' + raw)) return 'WARN';
  if (/USER_DEBUG|\bDEBUG\b/.test(marker + ' ' + raw)) return 'DEBUG';
  return 'INFO';
}
function parseLog(text) {
  const out = []; const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    const clean = raw.trim(); if (!clean) return;
    // Salesforce debug lines are timestamp | EVENT | event-specific fields. Preserve unrecognized lines.
    const parts = clean.split('|');
    const mi = parts.findIndex((part, j) => j > 0 && /^[A-Z][A-Z0-9_]+$/.test(part.trim()));
    const marker = mi >= 0 ? parts[mi].trim() : 'UNPARSED_LINE';
    const message = mi >= 0 ? parts.slice(mi + 1).join('|').trim() : clean;
    const statusMatch = clean.match(/(?:StatusCode\s*[=: ]\s*|HTTP\s+|status(?:Code)?\s*[=: ]\s*)(\d{3})/i);
    const durationMatch = clean.match(/(?:duration|elapsed)(?:Ms|_ms)?\s*[=: ]\s*(\d+(?:\.\d+)?)/i);
    const endpoint = (clean.match(/Endpoint\s*=\s*([^,\]]+)/i) || [])[1]?.trim() || null;
    const method = (clean.match(/Method\s*=\s*([A-Z]+)/i) || [])[1] || null;
    const statusCode = statusMatch ? Number(statusMatch[1]) : null;
    out.push({ id:`line-${i+1}`, lineNumber:i+1, timeLabel:(clean.match(/^\d{2}:\d{2}:\d{2}\.\d{1,6}/)||[])[0] || null, clockMs:parseClock(clean), level:classify(clean, marker, statusCode), category:marker, message, raw, statusCode, durationMs:durationMatch ? Number(durationMatch[1]) : null, endpoint, method });
  });
  return out;
}
function parseLimits() {
  const defs = [
    {key:'SOQL queries', re:/Number of SOQL queries:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'Query rows', re:/Number of query rows:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'DML statements', re:/Number of DML statements:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'DML rows', re:/Number of DML rows:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'Callouts', re:/Number of callouts:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'CPU time (ms)', re:/Maximum CPU time:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'Heap size (bytes)', re:/Maximum heap size:\s*(\d+)\s+out of\s+(\d+)/i},
    {key:'Email invocations', re:/Number of Email Invocations:\s*(\d+)\s+out of\s+(\d+)/i}
  ];
  const text = events.map(e=>e.raw).join('\n'); const found=[];
  defs.forEach(d=>{const m=text.match(d.re); if(m) found.push({name:d.key,used:Number(m[1]),limit:Number(m[2]),pct:Number(m[2])?Number(m[1])/Number(m[2])*100:null});});
  return found;
}
function scanSecurity() {
  const rules = [
    { key:'Possible bearer/basic authorization token', severity:'HIGH', re:/\b(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}/i },
    { key:'Possible secret, password, API key or OAuth token', severity:'HIGH', re:/\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|api[_-]?key|secret)\s*[:=]\s*["']?[^\s,;"']{4,}/i },
    { key:'Possible Salesforce session token', severity:'HIGH', re:/\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._-]{10,}\b/i },
    { key:'Email address / possible personal data', severity:'MEDIUM', re:/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
    { key:'Salesforce record ID', severity:'LOW', re:/\b(?:001|003|005|006|500|a0[A-Za-z0-9])[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?\b/i },
    { key:'Sensitive query-string parameter', severity:'HIGH', re:/[?&](?:access_token|refresh_token|token|api_key|apikey|password|secret|client_secret|authorization)=([^&#\s]+)/i }
  ];
  const hits = new Map();
  events.forEach(e => rules.forEach(rule => {
    if (rule.re.test(e.raw)) {
      const key = `${rule.key}|${rule.severity}`;
      if (!hits.has(key)) hits.set(key, { title:rule.key, severity:rule.severity, lines:[] });
      hits.get(key).lines.push(e.lineNumber);
    }
  }));
  return [...hits.values()].map(x => ({...x, lines:[...new Set(x.lines)]}));
}
function redactSensitive(value) {
  let s = String(value ?? '');
  s = s.replace(/(authorization\s*[:=]\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/ig, '$1[REDACTED]');
  s = s.replace(/\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}/ig, '$1[REDACTED]');
  s = s.replace(/(\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|api[_-]?key|secret)\s*[:=]\s*["']?)[^\s,;"']+/ig, '$1[REDACTED]');
  s = s.replace(/([?&](?:access_token|refresh_token|token|api_key|apikey|password|secret|client_secret|authorization)=)[^&#\s]+/ig, '$1[REDACTED]');
  s = s.replace(/\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._-]{10,}\b/ig, '[REDACTED_SF_SESSION_TOKEN]');
  s = s.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/ig, '[REDACTED_EMAIL]');
  s = s.replace(/\b(?:001|003|005|006|500|a0[A-Za-z0-9])[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?\b/g, '[REDACTED_SF_ID]');
  return s;
}
function redactDeep(value) {
  if (typeof value === 'string') return redactSensitive(value);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,redactDeep(v)]));
  return value;
}
function buildCallouts() {
  const out=[]; let pending=[];
  events.forEach(e=>{
    if(e.category==='CALLOUT_REQUEST') {
      const endpoint = e.endpoint || ((e.message.match(/Endpoint\s*=\s*([^,\]]+)/i)||[])[1]||null);
      const method = e.method || ((e.message.match(/Method\s*=\s*([A-Z]+)/i)||[])[1]||null);
      pending.push({request:e,endpoint,method});
    } else if(e.category==='CALLOUT_RESPONSE') {
      // Pair response with the earliest preceding unmatched request; flag pairing as heuristic.
      const req = pending.shift(); const status = e.statusCode ?? ((e.raw.match(/StatusCode\s*=\s*(\d{3})/i)||[])[1] ? Number((e.raw.match(/StatusCode\s*=\s*(\d{3})/i)||[])[1]) : null);
      let duration = null; if(req && req.request.clockMs!==null && e.clockMs!==null) { let delta=e.clockMs-req.request.clockMs; if(delta<0) delta+=86400000; if(delta>=0 && delta<86400000) duration=delta; }
      out.push({id:`call-${out.length+1}`,request:req?.request||null,response:e,endpoint:req?.endpoint||null,method:req?.method||null,statusCode:status,durationMs:duration,requestLine:req?.request.lineNumber||null,responseLine:e.lineNumber,matched:!!req});
    }
  });
  pending.forEach(req=>out.push({id:`call-${out.length+1}`,request:req.request,response:null,endpoint:req.endpoint,method:req.method,statusCode:null,durationMs:null,requestLine:req.request.lineNumber,responseLine:null,matched:false}));
  return out;
}
function buildFindings() {
  const out=[];
  const errors=events.filter(e=>e.level==='ERROR'); const httpErrors=callouts.filter(c=>c.statusCode>=400); const rateLimits=callouts.filter(c=>c.statusCode===429); const serverErrors=callouts.filter(c=>c.statusCode>=500 && c.statusCode<=599);
  if(rateLimits.length) out.push({severity:'ERROR',title:`${rateLimits.length} HTTP 429 rate-limit response${rateLimits.length>1?'s':''}`,body:'The log explicitly contains a 429 response. Check the provider rate limit, retry policy, backoff strategy, and whether requests are being duplicated.',evidence:rateLimits.map(c=>`Response line ${c.responseLine}${c.endpoint?' · '+c.endpoint:''}`).join('; ')});
  const unauthorized=callouts.filter(c=>c.statusCode===401); if(unauthorized.length) out.push({severity:'ERROR',title:`${unauthorized.length} HTTP 401 authentication response${unauthorized.length>1?'s':''}`,body:'The remote service returned 401. Verify the Named Credential or OAuth configuration, token validity, audience/scope, and whether the credential is authorized for this endpoint. Do not paste tokens into reports.',evidence:unauthorized.map(c=>`HTTP 401 at response line ${c.responseLine}`).join('; ')});
  const forbidden=callouts.filter(c=>c.statusCode===403); if(forbidden.length) out.push({severity:'ERROR',title:`${forbidden.length} HTTP 403 permission response${forbidden.length>1?'s':''}`,body:'The remote service returned 403. Authentication may have succeeded, but the principal may lack required permission or scope. Confirm provider-side access policy and endpoint permissions.',evidence:forbidden.map(c=>`HTTP 403 at response line ${c.responseLine}`).join('; ')});
  const badRequests=callouts.filter(c=>c.statusCode===400); if(badRequests.length) out.push({severity:'WARN',title:`${badRequests.length} HTTP 400 bad-request response${badRequests.length>1?'s':''}`,body:'The server rejected the request as invalid. Check the HTTP method, required headers, content type, field names, schema, and payload shape. The status alone does not reveal which field is wrong.',evidence:badRequests.map(c=>`HTTP 400 at response line ${c.responseLine}`).join('; ')});
  const notFound=callouts.filter(c=>c.statusCode===404); if(notFound.length) out.push({severity:'WARN',title:`${notFound.length} HTTP 404 endpoint/resource response${notFound.length>1?'s':''}`,body:'The requested resource was not found. Verify the base URL, path, API version, resource ID, and any path or query parameters.',evidence:notFound.map(c=>`HTTP 404 at response line ${c.responseLine}${c.endpoint?' · '+c.endpoint:''}`).join('; ')});
  const timeouts=events.filter(e=>/timed?\s*out|timeout|sockettimeoutexception|read timed out|connect timed out/i.test(e.raw)); if(timeouts.length) out.push({severity:'WARN',title:`${timeouts.length} timeout-related log line${timeouts.length>1?'s':''}`,body:'The log contains timeout-related text. Check the remote service latency, Salesforce callout timeout configuration, network path, and whether retrying is safe for this operation.',evidence:timeouts.slice(0,6).map(e=>`Line ${e.lineNumber} · ${e.category}`).join('; ')});
  const slowCalls=callouts.filter(c=>c.durationMs!==null && c.durationMs>=2000); if(slowCalls.length) out.push({severity:'WARN',title:`${slowCalls.length} callout(s) with observed timestamp delta ≥ 2 seconds`,body:'The request-to-response timestamp delta is at least two seconds. This is an observed log-time delta, not a guarantee of pure remote-server latency. Compare with provider telemetry and the full transaction timeline.',evidence:slowCalls.map(c=>`~${Math.round(c.durationMs)} ms at lines ${c.requestLine}→${c.responseLine}`).join('; ')});
  if(serverErrors.length) out.push({severity:'ERROR',title:`${serverErrors.length} HTTP 5xx response${serverErrors.length>1?'s':''}`,body:'A server-side failure response is present. Check the provider status, request correlation identifiers, retry safety, and the remote service logs.',evidence:serverErrors.map(c=>`HTTP ${c.statusCode} at line ${c.responseLine}`).join('; ')});
  const clientErrors=callouts.filter(c=>c.statusCode>=400 && c.statusCode<500 && ![400,401,403,404,429].includes(c.statusCode));
  if(clientErrors.length) out.push({severity:'WARN',title:`${clientErrors.length} HTTP 4xx response${clientErrors.length>1?'s':''}`,body:'The remote endpoint rejected a request. Verify authentication, permissions, endpoint path, request method, and payload requirements. The status alone does not identify the exact cause.',evidence:clientErrors.map(c=>`HTTP ${c.statusCode} at line ${c.responseLine}`).join('; ')});
  if(errors.length) out.push({severity:'ERROR',title:`${errors.length} error/exception-marked log line${errors.length>1?'s':''}`,body:'Inspect the raw lines and surrounding events for the first exception. A later fatal error may be a consequence rather than the original cause.',evidence:errors.slice(0,5).map(e=>`${e.category} at line ${e.lineNumber}`).join('; ')});
  const unmatched=callouts.filter(c=>!c.matched);
  if(unmatched.length) out.push({severity:'WARN',title:`${unmatched.length} callout response without a matched request`,body:'This parser pairs callouts by source order. The request may be absent, truncated, formatted differently, or not included in this file.',evidence:unmatched.map(c=>`Response line ${c.responseLine}`).join('; ')});
  const pending=callouts.filter(c=>c.matched && !c.response);
  if(pending.length) out.push({severity:'WARN',title:`${pending.length} callout request without a response`,body:'The log may be truncated, the callout may have failed before a response event was recorded, or the response marker may use an unsupported format.',evidence:pending.map(c=>`Request line ${c.requestLine}`).join('; ')});
  limits.forEach(l=>{if(l.pct!==null && l.pct>=80) out.push({severity:l.pct>=95?'ERROR':'WARN',title:`${l.name} usage is ${l.pct.toFixed(1)}%`,body:'This usage is high relative to the limit captured in the log. Review repeated queries/callouts, bulk behavior, and execution path before changing limits.',evidence:`${l.used} used out of ${l.limit}`});});
  if(!callouts.length) out.push({severity:'INFO',title:'No matched API callout response pairs found',body:'No CALLOUT_REQUEST / CALLOUT_RESPONSE events were recognized. This log may not contain an HTTP callout, or the format may differ. Absence here does not prove no API traffic occurred elsewhere.',evidence:'Parser searched for Salesforce CALLOUT_REQUEST and CALLOUT_RESPONSE markers.'});
  if(!out.length) out.push({severity:'INFO',title:'No rule-based issues detected',body:'No supported error pattern was found in the parsed lines. This is not proof that the transaction or integration is healthy; review the callout list and available log context.',evidence:`${events.length} non-empty lines parsed.`});
  return out;
}
function summarize(){const statuses=callouts.filter(c=>c.statusCode!==null).map(c=>c.statusCode); const measured=callouts.filter(c=>c.durationMs!==null).map(c=>c.durationMs); const clocks=events.map(e=>e.clockMs).filter(v=>v!==null); let span=null;if(clocks.length>1){span=Math.max(...clocks)-Math.min(...clocks);if(span>43200000)span=86400000-span;} const avgDuration=measured.length?measured.reduce((a,b)=>a+b,0)/measured.length:null; return {total:events.length,errors:events.filter(e=>e.level==='ERROR').length,warnings:events.filter(e=>e.level==='WARN').length,callouts:callouts.length,statuses,durations:measured,averageCalloutDurationMs:avgDuration,span,matched:callouts.filter(c=>c.matched&&c.response).length};}
function fmt(n){if(n==null||!Number.isFinite(n))return 'Not available';return n>=1000?(n/1000).toFixed(2)+' s':Math.round(n)+' ms';}
function load(text,name,sampleData=false){filename=name;isSample=sampleData;events=parseLog(text);warnings=[];if(!events.length)warnings.push('No non-empty lines were found.');if(!events.some(e=>e.category!=='UNPARSED_LINE'))warnings.push('No recognizable Salesforce event markers were detected.');if(!events.some(e=>e.timeLabel))warnings.push('No supported wall-clock timestamp was found; time-based metrics may be unavailable.');callouts=buildCallouts();limits=parseLimits();securityFindings=scanSecurity();findings=buildFindings();selected=events.find(e=>e.level==='ERROR')?.id||events[0]?.id||null;render();}
function render(){const s=summarize();$('filename').textContent=filename;$('filemeta').textContent=`${events.length} non-empty lines parsed · ${callouts.length} callout response/request records`;$('sampleTag').textContent=isSample?'SAMPLE DATA':'LOCAL FILE';$('disclaimer').textContent=(isSample?'Sample data is fictional. ':'Analysis is based only on the uploaded file. ')+'Callout duration is calculated only when both request and response timestamps are available; it is an approximate timestamp delta. Findings are rule-based, not proof of root cause. '+warnings.join(' ');
$('metrics').innerHTML=[['Parsed lines',s.total,'Non-empty lines, not unique transactions'],['Error-marked lines',s.errors,'Rule-based severity classification'],['Callout records',s.callouts,`${s.matched} request/response pairs matched`],['Observed log span',fmt(s.span),'First-to-last wall-clock timestamp']].map(m=>`<div class="metric"><div class="mlabel">${m[0]}</div><div class="mvalue">${m[1]}</div><div class="mnote">${m[2]}</div></div>`).join('');
const q=$('search').value.toLowerCase(),f=$('filter').value;const shown=events.filter(e=>(f==='ALL'||e.level===f)&&`${e.message} ${e.category} ${e.raw}`.toLowerCase().includes(q));$('eventCount').textContent=shown.length+' LINES';$('shown').textContent=`Showing ${shown.length} of ${events.length} parsed lines`;$('list').innerHTML=shown.length?shown.map(e=>`<button class="event ${e.id===selected?'selected':''}" data-id="${e.id}"><div class="rail"><div class="dot ${e.level}"></div></div><div><div class="line1"><span class="etime">${escapeHtml(e.timeLabel||'time unavailable')} · line ${e.lineNumber}</span><span class="level ${e.level}">${e.level}</span></div><div class="category">${escapeHtml(e.category)}</div><div class="message">${escapeHtml(e.message)}</div><div class="tags">${e.statusCode!==null?`<span class="smalltag ${e.statusCode>=400?'bad':''}">HTTP ${e.statusCode}</span>`:''}${e.durationMs!==null?`<span class="smalltag">Explicit duration ${fmt(e.durationMs)}</span>`:''}</div></div><span>›</span></button>`).join(''):'<div class="empty">No matching lines. Try another search or filter.</div>';
document.querySelectorAll('.event').forEach(b=>b.addEventListener('click',()=>{selected=b.dataset.id;render();}));const e=events.find(x=>x.id===selected);$('detail').innerHTML=e?`<div class="level ${e.level}">${e.level}</div><div class="dtitle">${escapeHtml(e.category)}</div><div class="dtime">${escapeHtml(e.timeLabel||'Timestamp unavailable')} · source line ${e.lineNumber}</div><div class="section"><div class="slab">MESSAGE</div><div class="bodymsg">${escapeHtml(e.message)}</div></div><div class="section"><div class="slab">PARSED ATTRIBUTES</div>${[['Category',e.category],['Time label',e.timeLabel||'Not present'],['HTTP status',e.statusCode??'Not present'],['Endpoint',e.endpoint||'Not present'],['HTTP method',e.method||'Not present'],['Explicit duration',e.durationMs==null?'Not present':fmt(e.durationMs)],['Source line',e.lineNumber]].map(a=>`<div class="attr"><span>${a[0]}</span><b>${escapeHtml(a[1])}</b></div>`).join('')}</div><div class="section"><div class="slab">RAW LINE</div><pre class="raw">${escapeHtml(e.raw)}</pre></div>`:'<div class="empty">Select an event to inspect its attributes.</div>';
$('calloutCount').textContent=`${callouts.length} CALLS`;$('calloutTable').innerHTML=callouts.length?`<table class="trace-table"><thead><tr><th>Method</th><th>Endpoint</th><th>Status</th><th>Duration</th><th>Lines</th></tr></thead><tbody>${callouts.map(c=>`<tr><td>${escapeHtml(c.method||'—')}</td><td class="endpoint-cell">${escapeHtml(c.endpoint||'Endpoint unavailable')}</td><td><span class="status-chip ${c.statusCode>=400?'bad':c.statusCode>=200?'good':''}">${c.statusCode??'—'}</span></td><td>${c.durationMs===null?'Not available*':fmt(c.durationMs)}</td><td>${c.requestLine??'—'} → ${c.responseLine??'—'}</td></tr>`).join('')}</tbody></table><div class="table-note">*Duration uses the difference between visible request/response timestamps and is approximate. Unmatched events are not assigned a duration.</div>`:'<div class="empty">No callout events recognized in this log.</div>';
$('findingCount').textContent=`${findings.length} FINDINGS`;$('findings').innerHTML=findings.map(x=>`<article class="finding ${x.severity}"><div class="finding-top"><span class="level ${x.severity}">${x.severity}</span><strong>${escapeHtml(x.title)}</strong></div><p>${escapeHtml(x.body)}</p><div class="evidence">Evidence: ${escapeHtml(x.evidence)}</div></article>`).join('');
$('limits').innerHTML=limits.length?limits.map(l=>`<div class="limit-row"><div class="limit-top"><span>${escapeHtml(l.name)}</span><b>${l.used.toLocaleString()} / ${l.limit.toLocaleString()}${l.pct===null?'':' · '+l.pct.toFixed(1)+'%'}</b></div><div class="bar"><span style="width:${Math.max(0,Math.min(100,l.pct||0))}%" class="${l.pct>=95?'critical':l.pct>=80?'warning':''}"></span></div></div>`).join(''):'<div class="empty">No recognized cumulative limit counters found. The log may not include CUMULATIVE_LIMIT_USAGE details.</div>';
$('securityCount').textContent=securityFindings.length?`${securityFindings.length} PATTERN TYPES`:'NO PATTERNS FOUND';$('securityCount').className='count '+(securityFindings.some(x=>x.severity==='HIGH')?'security-error':securityFindings.length?'security-warn':'security-safe');$('securityFindings').innerHTML=securityFindings.length?securityFindings.map(x=>`<div class="security-item"><b>${escapeHtml(x.title)} <span class="level ${x.severity==='HIGH'?'ERROR':x.severity==='MEDIUM'?'WARN':'INFO'}">${x.severity}</span></b><span>${x.lines.length} line(s) flagged · source line(s): ${escapeHtml(x.lines.slice(0,12).join(', '))}${x.lines.length>12?'…':''}</span></div>`).join(''):'<div class="security-item"><b class="security-safe">No configured sensitive-data patterns detected</b><span>This does not prove the file contains no secrets or personal data.</span></div>';
const recognized=events.filter(e=>e.category!=='UNPARSED_LINE').length;const coverage=[['Recognized event markers',`${recognized} / ${events.length}`],['Callout request/response pairing','Source-order heuristic'],['Measured callout durations',`${callouts.filter(c=>c.durationMs!==null).length} / ${callouts.length}`],['Explicit governor counters',limits.length],['Sensitive-data pattern scan',`${securityFindings.length} pattern types found`],['Raw log retention','Available per event']];$('quality').innerHTML=coverage.map(([k,v])=>`<div class="attr"><span>${escapeHtml(k)}</span><b>${escapeHtml(v)}</b></div>`).join('')+`<div class="table-note">The parser preserves unknown lines but may not recognize every Salesforce event variant. Confirm important conclusions against the raw log.</div>`;$('exportBtn').disabled=!events.length;}
function acceptFile(file){if(!file)return;if(file.size>20*1024*1024){toast('For this browser MVP, files must be smaller than 20 MB.');return;}if(!/\.(log|txt)$/i.test(file.name)){toast('Upload a Salesforce .log or .txt file.');return;}file.text().then(text=>{if(text.includes('\u0000')){toast('This file appears to contain binary data. Choose a plain-text Salesforce .log or .txt file.');return;} $('search').value='';$('filter').value='ALL';load(text,file.name,false);}).catch(()=>toast('Could not read this file in the browser.'));}
$('importBtn').onclick=()=>$('file').click();$('file').onchange=e=>{acceptFile(e.target.files[0]);e.target.value='';};$('sampleBtn').onclick=()=>{$('search').value='';$('filter').value='ALL';load(sample,'salesforce-debug-sample.log',true);};$('clearBtn').onclick=()=>load('','No file loaded',false);$('search').oninput=render;$('filter').onchange=render;$('exportBtn').onclick=()=>{const report={product:'API Trace',version:'0.3.0-phase2',sourceFile:filename,isSample,generatedAt:new Date().toISOString(),privacy:{redactionEnabled:$('redactExport').checked,notice:'Local browser analysis. Pattern-based redaction is best-effort and should be reviewed before sharing.'},metrics:summarize(),findings,securityFindings:securityFindings.map(x=>({title:x.title,severity:x.severity,lineNumbers:x.lines})),governorLimits:limits,callouts:callouts.map(c=>({method:c.method,endpoint:c.endpoint,statusCode:c.statusCode,durationMs:c.durationMs,requestLine:c.requestLine,responseLine:c.responseLine,matched:c.matched})),warnings,events:events.map(({id,lineNumber,timeLabel,level,category,message,statusCode,durationMs,endpoint,method,raw})=>({id,lineNumber,timeLabel,level,category,message,statusCode,durationMs,endpoint,method,raw}))};const finalReport=$('redactExport').checked?redactDeep(report):report;if(!$('redactExport').checked&&!confirm('Export without redaction? The report may contain personal data, Salesforce IDs, endpoints, or secrets. Continue only if you trust the destination.'))return;const blob=new Blob([JSON.stringify(finalReport,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='api-trace-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
let toastTimer;function toast(s){const t=$('toast');t.textContent=s;t.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.hidden=true,3500);}const dropTarget=document.querySelector('.source');dropTarget.addEventListener('dragover',e=>{e.preventDefault();dropTarget.style.outline='2px dashed #8294ff';});dropTarget.addEventListener('dragleave',()=>dropTarget.style.outline='');dropTarget.addEventListener('drop',e=>{e.preventDefault();dropTarget.style.outline='';acceptFile(e.dataTransfer?.files?.[0]);});
load(sample,'salesforce-debug-sample.log',true);
