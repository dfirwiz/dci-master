(() => {
  'use strict';
  const copy={
    en:{skip:'Skip to content',workspace:'Workspace',mainNav:'Main navigation',home:'Home',overview:'DCI overview',lessons:'Lessons',resources:'Resources',shellStatus:'Foundations',repository:'Source repository',language:'Select language',print:'Print / Save PDF',curriculum:'Curriculum',resourceLibrary:'Resource library',openLessons:'View lessons',openResources:'View resources',footer:'Public-source learning notes',menuOpen:'Open menu',menuClose:'Close menu',foundations:'Foundations · 00',readOverview:'Read the overview',overviewSummary:'Understand the purpose of DCI, its relationship with security operations, and how evidence guides action.',bilingualNote:'English / 한국어 · Print-friendly reading',publicSources:'Public sources',resourcesEmptyDescription:'Read the official sources supporting the DCI overview.',homeTitle:'Your DCI workspace',homeDescription:'Start with DCI: the purpose, the mission cycle and the evidence.',overviewTitle:'DCI overview',overviewDescription:'Discovery and Counter Infiltration · A mission-oriented introduction',lessonsTitle:'Lessons',lessonsDescription:'Begin with the foundations. Further lessons will be added separately.',resourcesTitle:'Resources',resourcesDescription:'Official public sources used in the DCI overview.',homeEyebrow:'YOUR LEARNING WORKSPACE',overviewEyebrow:'FOUNDATIONS / OVERVIEW',lessonsEyebrow:'LEARNING / LESSONS',resourcesEyebrow:'LEARNING / RESOURCES',status:'Foundations',reviewDate:'Sources checked: 5 November 2026'},
    ko:{skip:'본문으로 이동',workspace:'학습 공간',mainNav:'주 메뉴',home:'홈',overview:'DCI 개요',lessons:'강의',resources:'자료',shellStatus:'기초 과정',repository:'GitHub 저장소',language:'언어 선택',print:'인쇄 / PDF 저장',curriculum:'학습 과정',resourceLibrary:'자료실',openLessons:'강의 목록 보기',openResources:'자료실 보기',footer:'공개 자료를 바탕으로 한 학습 노트',menuOpen:'메뉴 열기',menuClose:'메뉴 닫기',foundations:'기초 과정 · 00',readOverview:'DCI 개요 읽기',overviewSummary:'DCI의 목적, 보안 운영과의 관계, 증거가 조치로 이어지는 흐름을 이해합니다.',bilingualNote:'English / 한국어 · 인쇄하기 편한 학습 노트',publicSources:'공개 참고 자료',resourcesEmptyDescription:'DCI 개요의 근거가 되는 공식 공개 자료를 확인하세요.',homeTitle:'DCI 학습 공간',homeDescription:'DCI의 목적과 작전 흐름, 증거를 이해하는 것부터 시작합니다.',overviewTitle:'DCI 개요',overviewDescription:'Discovery and Counter Infiltration · 임무 중심으로 이해하기',lessonsTitle:'강의',lessonsDescription:'먼저 기초부터 살펴봅니다. 후속 강의는 별도로 추가할 예정입니다.',resourcesTitle:'자료',resourcesDescription:'DCI 개요를 작성할 때 참고한 공식 공개 자료입니다.',homeEyebrow:'나의 학습 공간',overviewEyebrow:'기초 과정 / 개요',lessonsEyebrow:'학습 / 강의',resourcesEyebrow:'학습 / 자료',status:'기초 과정',reviewDate:'출처 확인일: 2026년 11월 5일'}
  };
  let lang='en';
  try{const saved=localStorage.getItem('dci-language');if(saved==='en'||saved==='ko')lang=saved;}catch(_){}
  const queryLang=new URLSearchParams(location.search).get('lang');
  if(queryLang==='ko'||queryLang==='en')lang=queryLang;
  const view=document.getElementById('view');
  const menu=document.getElementById('menu-button');
  const sidebar=document.getElementById('sidebar');
  const backdrop=document.getElementById('sidebar-backdrop');
  Object.assign(copy.en,{toolNav:'Network tools',status:'Learning notes',lessonsDescription:'DCI foundations and practical network-tool guides.',toolLibrary:'Network tools',homeDescription:'Learn the DCI foundations, then follow the Snort, Zeek and Arkime guides.',resourcesDescription:'Public references and synthetic practice files for the learning guides.'});
  Object.assign(copy.ko,{toolNav:'네트워크 도구',status:'학습 노트',lessonsDescription:'DCI 기초와 네트워크 도구의 상세 사용법을 배웁니다.',toolLibrary:'네트워크 도구',homeDescription:'DCI 기초에서 시작해 Snort·Zeek·Arkime 상세 강의로 이어갑니다.',resourcesDescription:'강의에서 참고한 공개 자료와 자체 제작한 실습 파일입니다.'});
  Object.assign(copy.en,{fundamentals:'Fundamentals',fundamentalsTitle:'Fundamentals: TCP flags and essential ports',fundamentalsDescription:'TCP flags, connection states, well-known ports and SMB named pipes, with verified packet examples.',fundamentalsEyebrow:'FOUNDATIONS / FUNDAMENTALS'});
  Object.assign(copy.ko,{fundamentals:'기초지식',fundamentalsTitle:'기초지식: TCP 플래그와 필수 포트',fundamentalsDescription:'TCP 플래그, 연결 상태, 주요 포트와 SMB 네임드 파이프를 검증된 패킷 예제로 배웁니다.',fundamentalsEyebrow:'기초 과정 / 기초지식'});
  Object.assign(copy.en,{cheatsheet:'Cheat sheet',cheatsheetTitle:'Cheat sheet: apply and test Snort 2 rules',cheatsheetDescription:'Copy-ready commands for applying and testing rules, HOME_NET and EXTERNAL_NET, rule syntax and common errors.',cheatsheetEyebrow:'Reference'});
  Object.assign(copy.ko,{cheatsheet:'치트시트',cheatsheetTitle:'치트시트: Snort 2 규칙 적용과 시험',cheatsheetDescription:'규칙 적용·시험 명령, HOME_NET·EXTERNAL_NET 설정, 규칙 문법, 자주 나는 에러를 한 곳에 모았습니다.',cheatsheetEyebrow:'참조'});
  Object.assign(copy.en,{copy:'Copy',copied:'Copied',printSection:'Print this section',printed:'Printed',printHint:'The print button prints the whole page. To print one section, use the printer icon beside its heading.'});
  Object.assign(copy.ko,{copy:'복사',copied:'복사됨',printSection:'이 절만 인쇄',printed:'인쇄일',printHint:'상단 인쇄 버튼은 페이지 전체를 인쇄합니다. 한 절만 인쇄하려면 제목 옆의 프린터 아이콘을 누르세요.'});
  for(const [id,c] of Object.entries(window.DCI_CHAPTERS))for(const l of ['en','ko'])Object.assign(copy[l],{[id]:id==='snort'?'Snort':id==='zeek'?'Zeek':'Arkime',[id+'Title']:c.title[l],[id+'Description']:c.subtitle[l],[id+'Eyebrow']:l==='en'?'NETWORK TOOLS / '+id.toUpperCase():'네트워크 도구 / '+id.toUpperCase()});
  function closeMenu(){sidebar.classList.remove('is-open');backdrop.hidden=true;sidebar.inert=window.innerWidth<=700;menu.setAttribute('aria-expanded','false');menu.setAttribute('aria-label',copy[lang].menuOpen);menu.querySelector('use').setAttribute('href','#icon-menu');}
  function translate(){
    document.documentElement.lang=lang;
    document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=copy[lang][el.dataset.i18n];});
    document.querySelectorAll('[data-i18n-label]').forEach(el=>{el.setAttribute('aria-label',copy[lang][el.dataset.i18nLabel]);});
    document.querySelectorAll('[data-lang]').forEach(el=>el.setAttribute('aria-pressed',String(el.dataset.lang===lang)));
    menu.setAttribute('aria-label',copy[lang][menu.getAttribute('aria-expanded')==='true'?'menuClose':'menuOpen']);
    document.getElementById('print-language').textContent=lang==='en'?'English':'한국어';
    document.querySelector('meta[name="description"]').content=lang==='en'?'DCI Master — an English and Korean introduction to Discovery and Counter Infiltration.':'DCI Master — 영어와 한국어로 배우는 DCI 개요.';
  }
  function lessonCard(){return `<section class="panel lesson-list" aria-label="${copy[lang].lessons}"><a href="#overview" class="lesson-entry"><span class="lesson-index">00</span><span class="lesson-entry-body"><span class="lesson-label" data-i18n="foundations"></span><h2 data-i18n="overview"></h2><span class="lesson-summary" data-i18n="overviewSummary"></span></span><svg class="icon" aria-hidden="true"><use href="#icon-arrow"/></svg></a></section>`;}
  let tocLinks=[];
  function printSection(section){
    const done=()=>{document.body.classList.remove('print-section');section.classList.remove('print-target');window.removeEventListener('afterprint',done);};
    document.body.classList.add('print-section');section.classList.add('print-target');
    window.addEventListener('afterprint',done);
    window.print();
  }
  function enhance(){
    const t=copy[lang];
    view.querySelectorAll('pre').forEach(pre=>{
      if(pre.parentElement.classList.contains('code-block')||pre.closest('td'))return;
      const wrap=document.createElement('div');wrap.className='code-block';pre.before(wrap);wrap.append(pre);
      const button=document.createElement('button');button.type='button';button.className='copy-button';button.textContent=t.copy;
      button.addEventListener('click',async()=>{
        const text=(pre.querySelector('code')||pre).innerText;
        try{await navigator.clipboard.writeText(text);}catch(_){const range=document.createRange();range.selectNodeContents(pre);const sel=getSelection();sel.removeAllRanges();sel.addRange(range);document.execCommand('copy');sel.removeAllRanges();}
        button.textContent=t.copied;button.classList.add('is-done');
        setTimeout(()=>{button.textContent=t.copy;button.classList.remove('is-done');},1600);
      });
      wrap.append(button);
    });
    view.querySelectorAll('.article-body>section[id]:not(.sources-section)').forEach(section=>{
      const heading=section.querySelector(':scope>h2');
      if(!heading||section.querySelector(':scope>.section-print'))return;
      const button=document.createElement('button');button.type='button';button.className='section-print';
      button.title=t.printSection;button.setAttribute('aria-label',t.printSection+': '+heading.textContent);
      button.innerHTML='<svg class="icon" aria-hidden="true"><use href="#icon-print"/></svg>';
      button.addEventListener('click',()=>printSection(section));
      heading.after(button);
    });
    const links=[...view.querySelectorAll('.article-toc a[data-scroll]')];
    tocLinks=links.map(a=>[a,document.getElementById(a.dataset.scroll)]).filter(([,el])=>el);
    updateToc();
    const meta=view.querySelector('.article-meta');
    if(meta&&view.querySelector('.section-print')&&!view.querySelector('.print-hint')){
      const hint=document.createElement('p');hint.className='print-hint';
      hint.innerHTML='<svg class="icon" aria-hidden="true"><use href="#icon-print"/></svg><span>'+t.printHint+'</span>';
      meta.after(hint);
    }
  }
  function updateToc(){
    if(!tocLinks.length)return;
    let current=tocLinks[0][0];
    for(const [a,el] of tocLinks){if(el.getBoundingClientRect().top<=140)current=a;else break;}
    tocLinks.forEach(([a])=>a.classList.toggle('is-current',a===current));
  }
  let tocTicking=false;
  window.addEventListener('scroll',()=>{if(tocTicking)return;tocTicking=true;requestAnimationFrame(()=>{updateToc();tocTicking=false;});},{passive:true});
  function render(){
    const requested=location.hash.slice(1);
    const tutIds=[];
    const page=['home','overview','fundamentals','cheatsheet','lessons','resources','snort','zeek','arkime',...tutIds].includes(requested)?requested:'home';
    document.body.dataset.page=page;
    const navPage=page;
    document.querySelectorAll('[data-page]').forEach(el=>{if(el.dataset.page===navPage)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
    if(page==='home'){
      view.replaceChildren(document.getElementById('home-template').content.cloneNode(true));
      view.insertAdjacentHTML('beforeend',`<section class="panel home-tool-library"><div class="panel-heading"><h2 data-i18n="toolLibrary"></h2></div>${window.DCI_FUNDAMENTALS.card(lang)}${window.DCI_CHEATSHEET.card(lang)}${window.DCI_TOOL_VIEW.cards(lang)}</section>`);
    }
    else if(page==='overview')view.innerHTML=window.DCI_OVERVIEW.render(lang);
    else if(page==='fundamentals')view.innerHTML=window.DCI_FUNDAMENTALS.render(lang);
    else if(page==='cheatsheet')view.innerHTML=window.DCI_CHEATSHEET.render(lang);
    else if(window.DCI_CHAPTERS[page])view.innerHTML=window.DCI_TOOL_VIEW.render(page,lang);
    else if(page==='lessons')view.innerHTML=lessonCard()+`<section class="panel tool-lesson-list">${window.DCI_FUNDAMENTALS.card(lang)}${window.DCI_CHEATSHEET.card(lang)}${window.DCI_TOOL_VIEW.cards(lang)}</section>`;
    else view.innerHTML=`<section class="panel resources-list"><div class="panel-heading"><h2 data-i18n="publicSources"></h2></div><div class="resources-body"><p data-i18n="reviewDate"></p>${window.DCI_OVERVIEW.sources(lang,true)}<h2 data-i18n="toolLibrary"></h2>${Object.entries(window.DCI_CHAPTERS).map(([id,c])=>`<h3><a href="#${id}">${c.title[lang]}</a></h3><ol class="source-list">${c.sources.map(r=>`<li><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title}</a></li>`).join('')}</ol>`).join('')}<h3><a href="#fundamentals">${copy[lang].fundamentalsTitle}</a></h3><ol class="source-list">${window.DCI_FUNDAMENTALS.sources.map(r=>`<li><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title}</a></li>`).join('')}</ol><h2>${lang==='ko'?'실습 파일':'Practice files'}</h2><p>${['dci-winrm.pcap','dci-http-dns.pcap','dci-smb-samr.pcap','dci-smb-samr-badsum.pcap','dci-tcp-flags.pcap','dci-local.rules','dci-snort2-local.rules','dci-tcp-flags.rules','README.txt','manifest.json'].map(f=>`<a href="./assets/labs/${f}" download>${f}</a>`).join(' · ')}</p></div></section>`;
    translate();
    document.getElementById('page-title').textContent=copy[lang][page+'Title'];
    document.getElementById('page-description').textContent=copy[lang][page+'Description'];
    document.getElementById('page-eyebrow').textContent=copy[lang][page+'Eyebrow'];
    document.getElementById('page-status').textContent=copy[lang].status;
    document.getElementById('breadcrumb-current').textContent=copy[lang][page];
    document.title='DCI Master · '+copy[lang][page];
    enhance();
    document.querySelectorAll('[data-scroll]').forEach(a=>a.addEventListener('click',event=>{event.preventDefault();const target=document.getElementById(a.dataset.scroll);if(target){target.scrollIntoView({block:'start'});target.setAttribute('tabindex','-1');target.focus({preventScroll:true});}}));
  }
  document.querySelectorAll('[data-lang]').forEach(button=>button.addEventListener('click',()=>{lang=button.dataset.lang;try{localStorage.setItem('dci-language',lang);}catch(_){}const url=new URL(location.href);url.searchParams.set('lang',lang);history.replaceState(null,'',url);render();}));
  document.getElementById('print-button').addEventListener('click',()=>window.print());
  window.addEventListener('beforeprint',()=>{
    const url=new URL(location.href);url.searchParams.set('lang',lang);
    document.getElementById('print-url').textContent=url.href;
    const target=document.querySelector('.print-target>h2');
    document.getElementById('print-page').textContent=copy[lang][document.body.dataset.page]+(target?' — '+target.textContent:'');
    document.getElementById('print-date').textContent=copy[lang].printed+': '+new Date().toLocaleDateString(lang==='ko'?'ko-KR':'en-AU',{year:'numeric',month:'long',day:'numeric'});
  });
  document.querySelector('.skip-link').addEventListener('click',event=>{event.preventDefault();document.getElementById('main').focus();});
  menu.addEventListener('click',()=>{if(menu.getAttribute('aria-expanded')==='true'){closeMenu();return;}sidebar.inert=false;sidebar.classList.add('is-open');backdrop.hidden=false;menu.setAttribute('aria-expanded','true');menu.setAttribute('aria-label',copy[lang].menuClose);menu.querySelector('use').setAttribute('href','#icon-close');sidebar.querySelector('[aria-current="page"]').focus();});
  backdrop.addEventListener('click',closeMenu);
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&menu.getAttribute('aria-expanded')==='true'){closeMenu();menu.focus();}});
  sidebar.querySelectorAll('[data-page],.brand').forEach(a=>a.addEventListener('click',closeMenu));
  window.addEventListener('hashchange',()=>{closeMenu();render();window.scrollTo(0,0);document.getElementById('main').focus({preventScroll:true});});
  window.addEventListener('resize',()=>{if(window.innerWidth>700)closeMenu();});
  closeMenu();render();
})();
