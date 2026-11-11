/* Lesson 04: PCAP incident investigation — a repeatable method with tshark, Zeek, Snort 2 and Wireshark.
   Section bodies live in pcap-investigation-data.js. Methods only: no exercise questions or answers.
   Command outputs on this page are illustrative placeholders (fake values), not recorded engine runs. */
window.DCI_PCAP = (() => {
  const data = window.DCI_PCAP_DATA || {sections: []};
  const intro = {
    id: 'intro',
    title: {en: 'What this lesson covers', ko: '이 강의에서 배우는 것'},
    html: {
      en: '<p>A capture lands on your desk with one sentence attached: “a computer on the network is behaving oddly”. This lesson is a fixed order of work for turning that PCAP into answers you can defend: which host, which user, what it downloaded and from where, what the file is, where it talked next and whether it spread to the Domain Controller.</p><p>Every step is shown three ways: <strong>tshark</strong> on the command line, <strong>Zeek</strong> logs (with <strong>Snort 2</strong> for alerts), and the <strong>Wireshark</strong> GUI. Learn the order once and most investigation questions become a matter of running the right command and reading the right column.</p><ol><li><strong>Setup and the standard workflow</strong>: Zeek logs, Snort alerts, Wireshark essentials, UTC and timelines.</li><li><strong>Identifying hosts</strong>: infected host, user account, Domain Controller, device and OS fingerprinting, network information, public IP.</li><li><strong>Downloads, files and hashes</strong>: URLs and sizes, safe extraction, real file type, hashing, Zeek <code>uid</code>/<code>fuid</code>, macros.</li><li><strong>Delivery, malware type and C2</strong>: alerts, delivery method, download tool, direction, post-infection traffic.</li><li><strong>SMB attacks on the DC and Snort rules</strong>: lateral movement, failed TCP 445 attempts, writing and testing rules.</li></ol><p class="example-label"><strong>About the examples.</strong> Commands assume the capture is <code>case.pcap</code>, Zeek logs are in <code>zeek_out/</code> and Snort output is in <code>snort_out/</code>. Example outputs are illustrative placeholders such as <code>172.xx.xx.xx</code> or <code>&lt;infected IP&gt;</code>; they show the shape of the output and are not results from a real or practice capture. Run the commands on your own PCAP to get real values.</p><p class="example-label"><strong>Live malware.</strong> Files carved from real incident captures are real malware. Work in an isolated analysis VM, never open or run them, and look up hashes rather than uploading files (see <a href="#pcap-safe-handling" data-scroll="pcap-safe-handling">Handling samples safely</a>).</p>',
      ko: '<p>“네트워크의 한 컴퓨터가 이상하게 동작한다”는 한 문장과 함께 캡처 파일이 넘어왔다고 생각해 보세요. 이 강의는 그 PCAP을 근거 있는 답으로 바꾸는 고정된 작업 순서입니다. 어느 호스트인지, 어느 사용자인지, 무엇을 어디서 받았는지, 그 파일이 무엇인지, 그다음 어디와 통신했는지, 도메인 컨트롤러까지 퍼졌는지까지 다룹니다.</p><p>모든 단계를 세 가지 방법으로 보여 줍니다. 명령줄의 <strong>tshark</strong>, <strong>Zeek</strong> 로그(알림은 <strong>Snort 2</strong>), 그리고 <strong>Wireshark</strong> 화면입니다. 순서를 한 번 익히면 대부분의 조사 질문은 맞는 명령을 돌리고 맞는 칸을 읽는 일이 됩니다.</p><ol><li><strong>준비와 표준 분석 순서</strong>: Zeek 로그, Snort 알림, Wireshark 기본 기술, UTC와 타임라인.</li><li><strong>호스트 신원 확인</strong>: 감염 호스트, 사용자 계정, 도메인 컨트롤러, 기기·OS 판별, 네트워크 정보, 공인 IP.</li><li><strong>다운로드·파일·해시</strong>: URL과 크기, 안전한 추출, 진짜 파일 종류, 해시, Zeek <code>uid</code>/<code>fuid</code>, 매크로.</li><li><strong>전달 방식·악성코드 종류·C2</strong>: 알림, 전달 방식, 다운로드 도구, 방향, 감염 후 통신.</li><li><strong>DC SMB 공격과 Snort 규칙</strong>: 내부 전파, TCP 445 실패 시도, 규칙 작성과 시험.</li></ol><p class="example-label"><strong>예시에 대해.</strong> 명령어는 캡처 파일을 <code>case.pcap</code>, Zeek 로그 폴더를 <code>zeek_out/</code>, Snort 결과 폴더를 <code>snort_out/</code>으로 가정합니다. 결과 예시는 <code>172.xx.xx.xx</code>, <code>&lt;infected IP&gt;</code> 같은 설명용 자리표시이며, 출력의 모양만 보여 줄 뿐 실제 캡처나 실습 파일을 돌린 결과가 아닙니다. 실제 값은 각자의 PCAP에서 명령을 돌려 얻습니다.</p><p class="example-label"><strong>실제 악성코드.</strong> 실제 사고 캡처에서 꺼낸 파일은 진짜 악성코드입니다. 격리된 분석 VM에서만 다루고, 열거나 실행하지 말고, 파일 대신 해시만 조회합니다(<a href="#pcap-safe-handling" data-scroll="pcap-safe-handling">샘플 안전하게 다루기</a> 참고).</p>'
    }
  };
  const sections = [intro].concat(data.sections);
  const sources = [
    {url: 'https://docs.zeek.org/en/master/logs/index.html', title: 'Zeek documentation: Zeek logs'},
    {url: 'https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html', title: 'Zeek documentation: files framework (fuid, files.log)'},
    {url: 'https://www.wireshark.org/docs/man-pages/tshark.html', title: 'tshark manual page'},
    {url: 'https://www.wireshark.org/docs/dfref/', title: 'Wireshark display filter reference'},
    {url: 'https://www.snort.org/documents', title: 'Snort documents (Snort 2.9 manual)'},
    {url: 'https://github.com/decalage2/oletools', title: 'oletools (oleid, olevba)'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/', title: 'MS-SMB2: Server Message Block Protocol Versions 2 and 3'},
    {url: 'https://www.rfc-editor.org/rfc/rfc1918', title: 'RFC 1918: Address Allocation for Private Internets'}
  ];
  const text = {
    en: {label: 'Investigation', review: 'Written: 11 November 2026', scope: 'Public-source teaching material. A method for investigating a PCAP; outputs are illustrative placeholders, not engine runs or real incident data.', toc: 'In this lesson', sources: 'Sources', back: 'All lessons', next: 'Cheat sheet', title: 'PCAP incident investigation: a repeatable workflow', summary: 'From one capture to a defensible answer: infected host, user, downloads and hashes, delivery, C2, spread to the DC over SMB and Snort rules — in tshark, Zeek and Wireshark.'},
    ko: {label: '침해 분석', review: '작성일: 2026년 11월 11일', scope: '공개 자료를 바탕으로 한 교육 자료입니다. PCAP을 조사하는 방법을 다루며, 출력 예시는 설명용 자리표시로 실제 엔진 실행 결과나 사고 데이터가 아닙니다.', toc: '이 강의에서 다룰 내용', sources: '출처', back: '전체 강의', next: '치트시트', title: 'PCAP 침해사고 분석: 반복 가능한 분석 순서', summary: '캡처 하나에서 근거 있는 답까지 — 감염 호스트, 사용자, 다운로드와 해시, 전달 방식, C2, SMB를 통한 DC 전파, Snort 규칙을 tshark·Zeek·Wireshark로 다룹니다.'}
  };
  function render(lang) {
    const t = text[lang];
    const body = sections.map((s, i) => `<section id="pcap-${s.id}"><h2>${i + 1}. ${s.title[lang]}</h2>${s.html[lang]}</section>`).join('');
    const refs = sources.map((r) => `<li><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title}</a></li>`).join('');
    return `<article class="overview-article tool-chapter pcap-chapter"><div class="article-meta"><span>${t.label} / 04</span><span>${t.review}</span></div><p class="chapter-scope">${t.scope}</p><nav class="article-toc" aria-label="${t.toc}"><h2>${t.toc}</h2><ol>${sections.map((s) => `<li><a href="#pcap-${s.id}" data-scroll="pcap-${s.id}">${s.title[lang]}</a></li>`).join('')}</ol></nav><div class="article-body">${body}<section class="sources-section"><h2>${t.sources}</h2><ol class="source-list">${refs}</ol></section></div><nav class="chapter-pagination"><a href="#lessons">← ${t.back}</a><a href="#cheatsheet">${t.next} →</a></nav></article>`;
  }
  function card(lang) {
    const t = text[lang];
    return `<a href="#pcap" class="lesson-entry"><span class="lesson-index">04</span><span class="lesson-entry-body"><span class="lesson-label">${t.label}</span><h2>${t.title}</h2><span class="lesson-summary">${t.summary}</span></span><svg class="icon" aria-hidden="true"><use href="#icon-arrow"/></svg></a>`;
  }
  return {render, card, sources, text};
})();
