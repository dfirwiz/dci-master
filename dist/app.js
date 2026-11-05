/* Interface only. Add learning content in a later, separately reviewed change. */
(() => {
  'use strict';
  const copy = {
    ko: {
      skip:'본문으로 이동', workspace:'학습 공간', mainNav:'주 메뉴', home:'홈', lessons:'강의', resources:'자료',
      shellStatus:'기본 구조', repository:'GitHub 저장소', language:'언어 선택', inPreparation:'준비 중',
      curriculum:'학습 과정', resourceLibrary:'자료실', noLessons:'아직 등록된 강의가 없습니다',
      lessonsEmptyDescription:'새 강의가 추가되면 이곳에 표시됩니다.', openLessons:'강의 목록 보기',
      emptyCurriculum:'학습 과정이 아직 구성되지 않았습니다', noResources:'아직 등록된 자료가 없습니다',
      resourcesEmptyDescription:'참고 자료와 실습 파일이 추가될 공간입니다.', openResources:'자료실 보기',
      footer:'학습 콘텐츠 준비 중', menuOpen:'메뉴 열기', menuClose:'메뉴 닫기',
      homeTitle:'DCI 학습 공간', homeDescription:'강의와 자료가 추가될 공간입니다.',
      lessonsTitle:'강의', lessonsDescription:'DCI 학습 과정을 위한 공간입니다.',
      resourcesTitle:'자료', resourcesDescription:'학습에 필요한 자료를 모을 공간입니다.',
      homeEyebrow:'나의 학습 공간', lessonsEyebrow:'학습 / 강의', resourcesEyebrow:'학습 / 자료'
    },
    en: {
      skip:'Skip to content', workspace:'WORKSPACE', mainNav:'Main navigation', home:'Home', lessons:'Lessons', resources:'Resources',
      shellStatus:'Site scaffold', repository:'SOURCE REPOSITORY', language:'Select language', inPreparation:'In preparation',
      curriculum:'Curriculum', resourceLibrary:'Resource library', noLessons:'No lessons yet',
      lessonsEmptyDescription:'New lessons will appear here when added.', openLessons:'View lessons',
      emptyCurriculum:'The curriculum has not been set up yet', noResources:'No resources yet',
      resourcesEmptyDescription:'A space for reference materials and practice files.', openResources:'View resources',
      footer:'Learning content in preparation', menuOpen:'Open menu', menuClose:'Close menu',
      homeTitle:'Your DCI workspace', homeDescription:'A space for your future lessons and resources.',
      lessonsTitle:'Lessons', lessonsDescription:'A space for your DCI learning journey.',
      resourcesTitle:'Resources', resourcesDescription:'A home for your learning materials.',
      homeEyebrow:'YOUR LEARNING WORKSPACE', lessonsEyebrow:'LEARNING / LESSONS', resourcesEyebrow:'LEARNING / RESOURCES'
    }
  };
  let lang = 'en';
  try {
    const saved=localStorage.getItem('dci-language');
    if (saved==='en' || saved==='ko') lang=saved;
  } catch (_) {}
  const queryLang=new URLSearchParams(location.search).get('lang');
  if (queryLang === 'ko' || queryLang === 'en') lang=queryLang;
  const view=document.getElementById('view');
  const menu=document.getElementById('menu-button');
  const sidebar=document.getElementById('sidebar');
  const backdrop=document.getElementById('sidebar-backdrop');
  function closeMenu() {
    sidebar.classList.remove('is-open');backdrop.hidden=true;
    sidebar.inert=window.innerWidth<=700;
    menu.setAttribute('aria-expanded','false');menu.setAttribute('aria-label',copy[lang].menuOpen);
    menu.querySelector('use').setAttribute('href','#icon-menu');
  }
  function translate() {
    document.documentElement.lang=lang;
    document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent=copy[lang][el.dataset.i18n]; });
    document.querySelectorAll('[data-i18n-label]').forEach(el => { el.setAttribute('aria-label',copy[lang][el.dataset.i18nLabel]); });
    document.querySelectorAll('[data-lang]').forEach(el => { el.setAttribute('aria-pressed',String(el.dataset.lang === lang)); });
    menu.setAttribute('aria-label',copy[lang][menu.getAttribute('aria-expanded')==='true'?'menuClose':'menuOpen']);
    document.querySelector('meta[name="description"]').content=lang==='ko'?'DCI Master — 한국어와 영어를 지원하는 학습 공간의 기본 구조입니다.':'DCI Master — a bilingual learning workspace scaffold.';
  }
  function render() {
    const requested=location.hash.slice(1);
    const page=['home','lessons','resources'].includes(requested)?requested:'home';
    document.querySelectorAll('[data-page]').forEach(el => {
      if(el.dataset.page===page)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');
    });
    if (page==='home') view.replaceChildren(document.getElementById('home-template').content.cloneNode(true));
    else {
      const resource=page==='resources';
      view.innerHTML=`<section class="panel single-panel" aria-labelledby="collection-title"><div class="panel-heading"><div><span class="section-number">${resource?'02':'01'}</span><h2 id="collection-title" data-i18n="${resource?'resourceLibrary':'lessons'}"></h2></div><svg class="icon" aria-hidden="true"><use href="#icon-${resource?'folder':'book'}"/></svg></div><div class="single-empty"><span class="empty-folder" aria-hidden="true"><svg><use href="#icon-${resource?'folder':'book'}"/></svg></span><h3 data-i18n="${resource?'noResources':'noLessons'}"></h3><p data-i18n="${resource?'resourcesEmptyDescription':'lessonsEmptyDescription'}"></p></div></section>`;
    }
    translate();
    document.getElementById('page-title').textContent=copy[lang][page+'Title'];
    document.getElementById('page-description').textContent=copy[lang][page+'Description'];
    document.getElementById('page-eyebrow').textContent=copy[lang][page+'Eyebrow'];
    document.getElementById('breadcrumb-current').textContent=copy[lang][page];
    document.title='DCI Master · '+copy[lang][page];
  }
  document.querySelectorAll('[data-lang]').forEach(button=>button.addEventListener('click',()=>{
    lang=button.dataset.lang;
    try{localStorage.setItem('dci-language',lang);}catch(_){}
    const url=new URL(location.href);url.searchParams.set('lang',lang);history.replaceState(null,'',url);
    render();
  }));
  menu.addEventListener('click',()=>{
    if(menu.getAttribute('aria-expanded')==='true'){closeMenu();return;}
    sidebar.inert=false;
    sidebar.classList.add('is-open');backdrop.hidden=false;
    menu.setAttribute('aria-expanded','true');menu.setAttribute('aria-label',copy[lang].menuClose);
    menu.querySelector('use').setAttribute('href','#icon-close');
    sidebar.querySelector('[aria-current="page"]').focus();
  });
  backdrop.addEventListener('click',closeMenu);
  document.addEventListener('keydown',event=>{if(event.key==='Escape'){closeMenu();menu.focus();}});
  sidebar.querySelectorAll('[data-page],.brand').forEach(a=>a.addEventListener('click',closeMenu));
  window.addEventListener('hashchange',()=>{closeMenu();render();document.getElementById('main').focus();});
  window.addEventListener('resize',()=>{if(window.innerWidth>700)closeMenu();});
  closeMenu();
  render();
})();
