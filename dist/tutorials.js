/* Tutorials container. Each tutorial lives in its own file and registers itself on window:
   tutorial-snort-smb.js (T01) and tutorial-zeek-hunt.js (T02). All scenario data is fictional. */
window.DCI_TUTORIALS = (() => {
  const tutorials = [window.DCI_TUTORIAL_SNORT_SMB, window.DCI_TUTORIAL_ZEEK_HUNT].filter(Boolean);

  const text = {
    en: {label: 'Tutorial · Hands-on', toc: 'In this tutorial', sources: 'Sources', back: 'All tutorials', listHeading: 'Tutorials', next: 'Cheat sheet'},
    ko: {label: '튜토리얼 · 실습', toc: '이 튜토리얼의 내용', sources: '출처', back: '전체 튜토리얼', listHeading: '튜토리얼', next: '치트시트'}
  };

  function render(id, lang) {
    const i = Math.max(0, tutorials.findIndex((x) => x.id === id));
    const tut = tutorials[i];
    const nextTut = tutorials[i + 1];
    const t = Object.assign({}, text[lang], tut.meta[lang]);
    const nextHref = nextTut ? '#' + nextTut.id : '#cheatsheet';
    const nextLabel = nextTut ? nextTut.title[lang] : t.next;
    const body = tut.sections.map((s) => `<section id="tut-${s.id}"><h2>${s.title[lang]}</h2>${s.html[lang]}</section>`).join('');
    const refs = tut.sources.map((r) => `<li><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title}</a></li>`).join('');
    return `<article class="overview-article tool-chapter tutorial-chapter"><div class="article-meta"><span>${t.meta}</span><span>${t.review}</span></div><nav class="article-toc" aria-label="${t.toc}"><h2>${t.toc}</h2><ol>${tut.sections.map((s) => `<li><a href="#tut-${s.id}" data-scroll="tut-${s.id}">${s.title[lang]}</a></li>`).join('')}</ol></nav><div class="article-body">${body}<section class="sources-section"><h2>${t.sources}</h2><ol class="source-list">${refs}</ol></section></div><nav class="chapter-pagination"><a href="#tutorials">${t.back}</a><a href="${nextHref}">${nextLabel}</a></nav></article>`;
  }
  function cards(lang) {
    const t = text[lang];
    return tutorials.map((x) => `<a href="#${x.id}" class="lesson-entry"><span class="lesson-index">${x.index}</span><span class="lesson-entry-body"><span class="lesson-label">${t.label}</span><h2>${x.title[lang]}</h2><span class="lesson-summary">${x.summary[lang]}</span></span><svg class="icon" aria-hidden="true"><use href="#icon-arrow"/></svg></a>`).join('');
  }
  function list(lang) {
    return `<section class="panel tool-lesson-list" aria-label="${text[lang].listHeading}">${cards(lang)}</section>`;
  }
  return {render, cards, list, tutorials, text};
})();
