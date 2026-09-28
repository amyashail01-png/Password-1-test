const $=id=>document.getElementById(id);
const $$=s=>[...document.querySelectorAll(s)];
const COMMON="password,123456,123456789,12345678,12345,1234567,qwerty,abc123,111111,123123,admin,letmein,welcome,monkey,dragon,iloveyou,sunshine,princess,football,baseball,master,login,passw0rd,password1,qwerty123,1q2w3e4r,trustno1,starwars,hello,freedom,whatever,shadow,superman,batman,michael,jessica,charlie,summer,spring,winter,autumn,cricket,india,mumbai,pune,ganesh,secret,computer,internet,cheese,banana,soccer,hockey,troubadour".split(",");
const ROWS=["qwertyuiop","asdfghjkl","zxcvbnm","1234567890"];
const LEET={"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","$":"s","@":"a","!":"i"};
const LEVELS=["Very weak","Weak","Moderate","Good","Strong"];
const DESC=["Falls almost instantly to any guessing tool.","Vulnerable even to casual offline cracking.","Reasonable against casual online guessing, but vulnerable to dedicated offline GPU rigs.","Resists most offline attacks for a long time.","Out of reach for current guessing hardware."];
const COL=["--l0","--l1","--l2","--l3","--l4"];
const ATTACKS=[["Web login with lockout","about 100 guesses an hour",100/3600],["Unthrottled API","about 1,000 guesses a second",1e3],["Slow hash (bcrypt, Argon2)","about 10,000 guesses a second",1e4],["Fast hash on a GPU rig","about 100 billion guesses a second",1e11]];
const WORDS=[...new Set("amber apple arrow atlas badge bagel beach bench berry bike bison blanket bloom boat brick bridge brush cabin cactus camel candle canyon carpet castle cedar chair cherry cliff cloud clover coast comet copper coral cotton crane creek crown daisy delta desert dolphin dragon drum eagle ember engine falcon feather fern field flame forest fossil fox garden ginger glacier globe grape harbor hazel heron honey igloo island ivory jacket jungle kettle kiwi ladder lagoon lantern lemon lizard maple marble meadow mirror moon mango mountain nest noodle oak ocean olive orbit otter paddle panda pearl pepper pine planet pond puzzle quartz rabbit rain river rocket saddle sailor salmon shell silver spark spoon storm sunset tent tiger tulip valley velvet violet walnut whale willow window yarn zebra".split(" "))];

/* helpers */
function fmt(s){
  if(s<1)return"instantly";if(s<60)return Math.round(s)+" seconds";
  let v=s/60;if(v<60)return Math.round(v)+" minutes";
  v/=60;if(v<24)return Math.round(v)+" hours";
  v/=24;if(v<365)return Math.round(v)+" days";
  v/=365;
  if(v>1.4e10)return"longer than the universe has existed";
  if(v>=1e9)return(v/1e9).toFixed(1)+" billion years";
  if(v>=1e6)return(v/1e6).toFixed(1)+" million years";
  if(v>=1000)return Math.round(v/1000).toLocaleString()+" thousand years";
  return Math.round(v).toLocaleString()+" years";
}
const secs=(bits,rate)=>Math.pow(2,Math.max(bits,1)-1)/rate;
function attacks(el,bits){el.innerHTML=ATTACKS.map((a,i)=>`<div class="adv${i===3?" hot":""}"><b>${a[0]}</b><span class="t">${bits?fmt(secs(bits,a[2])):"-"}</span><small>${a[1]}</small></div>`).join("")}
function rnd(n){const b=new Uint32Array(1),lim=Math.floor(2**32/n)*n;let x;do{crypto.getRandomValues(b);x=b[0]}while(x>=lim);return x%n}
async function copyText(t,el){try{await navigator.clipboard.writeText(t);el.textContent="Copied. Paste it into a password manager."}catch(e){el.textContent="Copy failed. Select the text and copy it manually."}}

/* analysis */
function hasRun(s){let c=1;for(let i=1;i<s.length;i++){if(Math.abs(s.charCodeAt(i)-s.charCodeAt(i-1))===1){if(++c>=3)return true}else c=1}return false}
function hasKeys(s){const l=s.toLowerCase();for(const r of ROWS){const rr=[...r].reverse().join("");for(let i=0;i+4<=l.length;i++){const p=l.slice(i,i+4);if(r.includes(p)||rr.includes(p))return true}}return false}
function analyze(p){
  const lower=p.toLowerCase(),norm=[...lower].map(c=>LEET[c]||c).join(""),base=norm.replace(/[^a-z]/g,"");
  const f={len:p.length,lc:/[a-z]/.test(p),uc:/[A-Z]/.test(p),num:/\d/.test(p),sym:/[^A-Za-z0-9]/.test(p)};
  const pool=Math.max((f.lc?26:0)+(f.uc?26:0)+(f.num?10:0)+(f.sym?33:0),2);
  const uniq=new Set(p).size,eff=uniq+.3*(p.length-uniq),raw=eff*Math.log2(pool);let bits=raw;
  const flaws=[],pen=[];
  const exact=COMMON.includes(lower)||COMMON.includes(norm)||COMMON.includes(base)||COMMON.includes(lower.replace(/[\d\W]+$/,""));
  const word=!exact&&COMMON.find(w=>w.length>=5&&norm.includes(w));
  f.common=exact||!!word;f.pattern=hasRun(lower)||hasKeys(p);
  f.repeat=/(.)\1{2,}/.test(p)||/^(.{1,6})\1+$/.test(p);f.year=/(19|20)\d\d/.test(p);f.shape=/^[A-Z]?[a-z]{3,}[\d\W]{1,4}$/.test(p);
  const add=(t,tag,d,x,fix,crit)=>flaws.push({t,tag,d,x,fix,crit});
  if(exact){bits=Math.min(bits,10);pen.push("common password: capped at 10");add("Common password","Critical flaw","This appears in lists of the most common or leaked passwords.","Cracking tools start with these lists and try every entry, plus common swaps, in milliseconds.","Start over with unrelated words picked at random.",1)}
  else if(word){bits-=16;pen.push("common word -16");add(`Common word ("${word}")`,"Design pattern","Dictionary words are the base of most guessing attacks.","Rule engines take a dictionary word and apply thousands of variations: capital letters, digits, symbols.","Use words or characters chosen at random, not ones that mean something to you.")}
  if(f.pattern){bits-=12;pen.push("pattern -12");add("Sequence or keyboard walk","Critical flaw","Typing adjacent keys or counting up feels memorable but is very predictable.","Keyboard walks and counting runs are cataloged in attack dictionaries and tried early.","Avoid consecutive adjacent keys and number strips. Build from unrelated words.",1)}
  if(f.repeat){bits-=8;pen.push("repeats -8");add("Repeated characters or chunks","Design pattern","Repetition adds length on paper but few extra guesses in practice.","Attackers test repeated characters and repeated chunks as a single cheap pattern.","Make every part different so each character adds new information.")}
  if(f.year){bits-=6;pen.push("year -6");add("Year in the password","Design pattern","Birth years and recent years are easy to guess.","Append-digit rules try 1, 12, 123 and every recent year immediately.","Avoid years. If you need digits, use random ones.")}
  if(f.shape&&!exact){bits-=10;pen.push("word+digits shape -10");add("Trailing number or symbol on a word","Design pattern","A word with a few digits or a symbol added at the end is the most common shape.","Mask attacks try Capital + lowercase + digits + symbol shapes first.","Add more random words instead of decorating one word.")}
  if(p.length<12)add("Short length",`Critical flaw`,`At ${p.length} characters, the total number of combinations is small.`,"A fast rig can try every combination of a short password.","Aim for 14 or more characters, for example 5 or more random words.",1);
  bits=Math.max(bits,1);
  const good=[];
  if(p.length>=14)good.push(["Good length",`${p.length} characters gives attackers a large search space.`]);
  if((f.lc+f.uc+f.num+f.sym)>=3)good.push(["Mixed character types","Several types of characters enlarge the pool an attacker must cover."]);
  if(!f.common&&!f.pattern&&p.length>=8)good.push(["No known patterns","No common word, sequence or keyboard walk was found."]);
  if(uniq/p.length>=.7&&p.length>=10)good.push(["Little repetition","Most characters are different, so each adds new information."]);
  return{f,pool,raw,bits,pen,flaws,good,level:bits<30?0:bits<40?1:bits<64?2:bits<80?3:4};
}
const DEMO="qwerty123456";
function render(){
  const p=$("pw").value;
  $("meta").textContent=`Length: ${p.length} · Pool: ${p?analyze(p).pool:0}`;
  const cls=[["a-z",/[a-z]/g,"--l4"],["A-Z",/[A-Z]/g,"--accent"],["0-9",/\d/g,"--l2"],["Symbols",/[^A-Za-z0-9]/g,"--l1"]];
  $("pools").innerHTML=cls.map(c=>`<span style="--c:var(${c[2]})">${c[0]} (${(p.match(c[1])||[]).length})</span>`).join("");
  $("tiles").innerHTML=[...p].map(ch=>{const c=/[a-z]/.test(ch)?"--l4":/[A-Z]/.test(ch)?"--accent":/\d/.test(ch)?"--l2":"--l1";return`<span style="--c:var(${c})">${ch.replace(/&/g,"&amp;").replace(/</g,"&lt;")}</span>`}).join("");
  if(!p){
    ["fill","fill2"].forEach(i=>$(i).style.width="0");$("sline").textContent="Start typing";$("pct").textContent="0";$("lvl").textContent="Waiting";$("lvl").className="pill";
    $("desc").textContent="Type a password above to see how it holds up.";$("eff").textContent="0";$("raw").textContent="0";$("math").textContent="";
    attacks($("attacks"),0);$("flaws").innerHTML='<p class="muted small">Type a password to see weaknesses.</p>';$("strengths").innerHTML="";$("flawCount").hidden=true;return;
  }
  const a=analyze(p),pct=Math.min(100,Math.round(a.bits)),col=`var(${COL[a.level]})`;
  ["fill","fill2"].forEach(i=>{$(i).style.width=pct+"%";$(i).style.background=col});
  $("sline").innerHTML=`Strength: <b>${pct}% (${LEVELS[a.level]})</b>`;
  $("pct").textContent=pct;$("lvl").textContent=LEVELS[a.level]+" resistance";$("lvl").className="pill"+(a.level<2?" bad":a.level>2?" good":"");
  $("desc").textContent=DESC[a.level];$("eff").textContent=Math.round(a.bits);$("raw").textContent=Math.round(a.raw);
  $("math").innerHTML=`Raw: effective characters × log2(<b>${a.pool}</b>) = <b>${a.raw.toFixed(0)}</b> bits`+(a.pen.length?`<br>Pattern penalties: ${a.pen.join(", ")} → <b>${Math.round(a.bits)}</b> effective bits`:"");
  attacks($("attacks"),a.bits);
  $("flawCount").hidden=!a.flaws.length;$("flawCount").textContent=`${a.flaws.length} flaw${a.flaws.length>1?"s":""} detected`;
  $("flaws").innerHTML=a.flaws.length?a.flaws.map(x=>`<div class="flaw${x.crit?" crit":""}"><h3>${x.t} <span class="pill${x.crit?" bad":""}">${x.tag}</span></h3><p>${x.d}</p><div class="boxes"><div><b>How crackers exploit it</b>${x.x}</div><div class="fix"><b>How to fix it</b>${x.fix}</div></div></div>`).join(""):'<p class="muted small">No obvious weaknesses found.</p>';
  $("strengths").innerHTML=a.good.length?`<p class="hl">Strengths detected <span class="pill good">${a.good.length}</span></p>`+a.good.map(g=>`<div class="strength"><h3>${g[0]}</h3><p>${g[1]}</p></div>`).join(""):"";
}
$("pw").addEventListener("input",render);
$("pw").addEventListener("focus",()=>{if($("pw").value===DEMO){$("pw").value="";$("pw").type="password";$("toggle").textContent="Show";$("toggle").setAttribute("aria-pressed","false");render()}});
$("toggle").onclick=()=>{const i=$("pw"),s=i.type==="password";i.type=s?"text":"password";$("toggle").textContent=s?"Hide":"Show";$("toggle").setAttribute("aria-pressed",s)};
$("clear").onclick=()=>{$("pw").value="";render();$("pw").focus()};
function checkThis(t){$("pw").value=t;render();$("analyzer").scrollIntoView({behavior:"smooth"})}
$("scen").innerHTML=[["Password123!","Corporate illusion"],["Spring2026!","Seasonal pattern"],["qwerty123456","Keyboard walk"],["j7#eK9q!L","Short gibberish"],["correct-horse-battery-staple","Famous passphrase"]].map(s=>`<button type="button" data-p="${s[0]}"><b>${s[0]}</b><small>${s[1]}</small></button>`).join("");
$("scen").onclick=e=>{const b=e.target.closest("button");if(b)checkThis(b.dataset.p)};

/* paradox */
$("vsA").textContent="Crack time at 28 bits: "+fmt(secs(28,1e11));
$("vsB").textContent="Crack time at 64.6 bits: "+fmt(secs(64.6,1e11));
$("take").innerHTML="<b>The takeaway:</b> B is about "+Math.round(Math.pow(2,64.6-28)/1e12)+" trillion times harder to guess than A, yet far easier for a person to remember.";

/* passphrase + random password */
function phrase(){
  const n=+$("ppCount").value;$("ppCountVal").textContent=n;
  $("ppOut").textContent=Array.from({length:n},()=>WORDS[rnd(WORDS.length)]).join("-");
  const per=Math.log2(WORDS.length);
  $("ppMath").innerHTML=`<b>${n}</b> words × log2(<b>${WORDS.length}</b> words) = <b>${(n*per).toFixed(0)}</b> bits<br>Fast-hash GPU rig: <b>${fmt(secs(n*per,1e11))}</b>`;
  $("ppToast").textContent="";
}
$("ppCount").oninput=phrase;$("ppNew").onclick=phrase;
$("ppCopy").onclick=()=>copyText($("ppOut").textContent,$("ppToast"));
$("ppCheck").onclick=()=>checkThis($("ppOut").textContent);
function generate(){
  const L=+$("len").value,sets=["abcdefghijkmnopqrstuvwxyz","ABCDEFGHJKLMNPQRSTUVWXYZ","23456789","!@#$%^&*-_=+?"];
  const all=sets.join("");let out=sets.map(s=>s[rnd(s.length)]);
  while(out.length<L)out.push(all[rnd(all.length)]);
  for(let i=out.length-1;i>0;i--){const j=rnd(i+1);[out[i],out[j]]=[out[j],out[i]]}
  $("genOut").textContent=out.join("");$("toast").textContent="";
}
$("len").oninput=()=>{$("lenVal").textContent=$("len").value;generate()};
$("gen").onclick=generate;$("copy").onclick=()=>copyText($("genOut").textContent,$("toast"));$("test").onclick=()=>checkThis($("genOut").textContent);

/* entropy sandbox */
let R=62;
function sandbox(){
  const L=+$("sbLen").value;$("sbLenVal").textContent=L;
  const per=Math.log2(R),bits=per*L,g=Math.pow(R,L);
  $("sbFormula").innerHTML=`Possibilities = R<sup>L</sup> = <b>${R}<sup>${L}</sup></b> ≈ <b>${g.toExponential(2).replace("e+"," × 10^")}</b><br>Entropy H = L × log2(R) = ${L} × ${per.toFixed(2)} = <b>${bits.toFixed(1)} bits</b>`;
  $("sbBits").textContent=bits.toFixed(0);
  $("sbFacts").textContent=`Each extra character multiplies the possibilities by ${R}.`;
  attacks($("sbAttacks"),bits);
}
$("presets").onclick=e=>{const b=e.target.closest("button");if(!b)return;R=+b.dataset.r;$$("#presets button").forEach(x=>x.setAttribute("aria-pressed",x===b));sandbox()};
$("sbLen").oninput=sandbox;

/* quiz */
const QZ=[
 ["P@ssw0rd2026!","Capital letter, two leetspeak swaps, a year and an exclamation mark","timber-orchid-cobalt-haven","Four plain lowercase words separated by hyphens (26 characters)",1,"Option A follows the classic pattern every cracking tool tries first. Option B has more length and randomness, and it is easier to remember."],
 ["Dragon!1985","A dictionary word, a symbol and a year","vT7#kq9Lm2$xWe4Z","16 random characters",1,"Option A is a word plus a year plus a symbol, which is predictable. Option B is long and random."],
 ["qwerty!Z9x","A keyboard walk with a few extras","hazel-orbit-canyon-lemon-drum","Five random words",1,"Keyboard walks are cataloged in attack dictionaries. Five random words give far more possibilities."],
 ["kdjfhwmqpzxcvb","14 random lowercase letters (about 66 bits)","Summer2026!","A season, a year and a symbol",0,"Option A is longer and random. Option B is short and follows a common pattern, even though it uses more character types."]];
let qi=0,ans=[];
function quiz(){
  const el=$("quiz"),score=ans.filter(x=>x&&x.ok).length,done=ans.filter(Boolean).length;
  if(qi>=QZ.length){el.innerHTML=`<h2>Quiz complete</h2><div class="big" style="margin:12px 0">${score} <span class="muted" style="font:500 1rem Figtree,sans-serif">of ${QZ.length} correct</span></div><p class="muted">${score===QZ.length?"Perfect. You know what makes a password strong.":"Review the sections above, then try again."}</p><button class="primary" id="qr" type="button">Try again</button>`;$("qr").onclick=()=>{qi=0;ans=[];quiz()};return}
  const q=QZ[qi],a=ans[qi];
  el.innerHTML=`<div class="head"><h2>Spot the hidden flaw</h2><span class="meta">Question ${qi+1} of ${QZ.length} · ${score} correct</span></div><p style="margin:0;font-weight:600">Which credential takes an attacker longer to crack?</p><div class="qa">${[0,1].map(i=>`<button type="button" data-i="${i}"><small class="muted">Choice ${"AB"[i]}</small><b>${q[i*2]}</b><span class="muted small">${q[i*2+1]}</span></button>`).join("")}</div><div id="fb" aria-live="polite"></div><div class="row"><button id="qp" type="button" ${qi?"":"disabled"}>Previous</button><button class="primary" id="qn" type="button" ${a?"":"disabled"}>${qi<QZ.length-1?"Next scenario":"See my score"}</button></div>`;
  const btns=el.querySelectorAll(".qa button"),mark=pick=>{btns.forEach((b,j)=>{b.classList.toggle("right",j===q[4]);b.classList.toggle("wrong",j===pick&&j!==q[4])});$("fb").innerHTML=`<p class="take"><b>${pick===q[4]?"Correct.":"Not quite."}</b> ${q[5]}</p>`;$("qn").disabled=false};
  if(a)mark(a.pick);
  btns.forEach(b=>b.onclick=()=>{if(ans[qi])return;const pick=+b.dataset.i;ans[qi]={pick,ok:pick===q[4]};mark(pick);$("qn").focus()});
  $("qp").onclick=()=>{qi--;quiz()};$("qn").onclick=()=>{qi++;quiz()};
}

/* nav highlight */
const secs2=["analyzer","weaknesses","passphrase-lab","entropy-sandbox","weakness-quiz"];
addEventListener("scroll",()=>{let cur="";secs2.forEach(id=>{if($(id).getBoundingClientRect().top<140)cur=id});$$(".links a").forEach(a=>a.classList.toggle("on",a.getAttribute("href")==="#"+cur))},{passive:true});

$("pw").value=DEMO;$("toggle").setAttribute("aria-pressed","true");
generate();phrase();sandbox();quiz();render();
