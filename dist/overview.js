/* Public-source educational overview. No restricted operational procedures. */
window.DCI_OVERVIEW = (() => {
  const refs = [
    {url:'https://www.doncio.navy.mil/CHIPS/ArticleDetails.aspx?ID=20396',title:'DISA / CHIPS · Disciplined analysis drives comprehensive cyber defense',date:'2025-08-20'},
    {url:'https://news.maryland.gov/ng/2022/09/22/cpt-169-fights-cyber-with-cyber-at-cyber-flag-22/',title:'Maryland National Guard · CPT 169 at CYBER FLAG 22',date:'2022-09-22'},
    {url:'https://www.army.mil/article/183500/154th_cyber_protection_team_engaged_in_network_defense_at_cybertropolis_indiana',title:'U.S. Army · 154th Cyber Protection Team at Cybertropolis',date:'2017-03-02'},
    {url:'https://www.ncsc.gov.uk/collection/building-a-security-operations-centre/detection/detection-approaches',title:'UK NCSC · SOC detection approaches and threat hunting',date:'2022-05-23'},
    {url:'https://csrc.nist.gov/pubs/sp/800/61/r3/final',title:'NIST SP 800-61 Rev. 3 · Incident response and cybersecurity risk management',date:'2025-04-03'},
    {url:'https://attack.mitre.org/',title:'MITRE ATT&CK · Adversary tactics and techniques',date:null},
    {url:'https://learn.microsoft.com/en-au/windows/win32/winrm/installation-and-configuration-for-windows-remote-management',title:'Microsoft Learn · Windows Remote Management configuration',date:null}
  ];
  const cite = n => `<sup><a class="source-ref" href="#ref-${n}" data-scroll="ref-${n}" aria-label="${n}">[${n}]</a></sup>`;
  const toc = {
    en:['Why look when nothing is broken?','What DCI means here','DCI, SOC and incident response','Start with the mission','A practical mission cycle','Connect network and host evidence','A small investigation example','What a useful hunt leaves behind','Check your understanding','Sources and scope'],
    ko:['멀쩡해 보이는데 왜 조사할까요?','이 사이트에서 말하는 DCI','SOC·사고 대응과의 관계','먼저 지켜야 할 임무부터','작전을 이해하는 기본 흐름','네트워크와 호스트 증거 연결','작은 조사 사례로 이해하기','헌팅이 남겨야 하는 결과','복습 질문과 해설','출처와 적용 범위']
  };
  function sources(lang,compact=false){
    return `<ol class="source-list">${refs.map((r,i)=>`<li id="${compact?'resource-':'ref-'}${i+1}"><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title}</a>${r.date?`<span class="source-date">${lang==='ko'?'발행':'Published'} ${r.date}</span>`:''}</li>`).join('')}</ol>`;
  }
  function cycle(lang){
    const names=lang==='ko'?[['계획'],['헌트'],['클리어'],['하드닝','지원'],['평가']]:[['Plan'],['Hunt'],['Clear'],['Enable','hardening'],['Assess']];
    const title=lang==='ko'?'그림 1. 계획에서 평가까지의 학습용 작전 흐름':'Figure 1. An educational mission cycle, from planning to assessment';
    const desc=lang==='ko'?'화살표를 따라 계획, 헌트, 클리어, 하드닝 지원, 평가로 진행하며 평가 결과는 다음 계획에 반영됩니다.':'Follow the arrows through Plan, Hunt, Clear, Enable hardening and Assess. Assessment informs the next plan.';
    const label=(x,y,words)=>words.map((s,i)=>`<text x="${x}" y="${y+(i-(words.length-1)/2)*21}" text-anchor="middle">${s}</text>`).join('');
    const nodes=names.map((n,i)=>{const x=8+i*135;return `<rect x="${x}" y="28" width="112" height="78" rx="6"/>${label(x+56,73,n)}${i<4?`<path class="flow-arrow" d="M${x+116} 67h16m-5-5 5 5-5 5"/>`:''}`}).join('');
    const stacked=names.map((n,i)=>{const y=12+i*89;return `<rect x="56" y="${y}" width="228" height="65" rx="6"/>${label(170,y+39,n)}${i<4?`<path class="flow-arrow" d="M170 ${y+68}v18m-5-5 5 5 5-5"/>`:''}`}).join('');
    return `<figure class="learning-figure"><figcaption>${title}</figcaption><svg class="diagram diagram-wide" viewBox="0 0 680 180" role="img" aria-label="${desc}"><title>${title}</title>${nodes}<path class="feedback-arrow" d="M604 110v38H64v-34m-5 6 5-6 5 6"/><text x="334" y="140" text-anchor="middle" class="feedback-label">${lang==='ko'?'평가 결과로 계획과 탐지 개선':'Feed findings back into planning and detection'}</text></svg><svg class="diagram diagram-stack" viewBox="0 0 340 455" role="img" aria-label="${desc}"><title>${title}</title>${stacked}</svg><p class="figure-note">${lang==='ko'?'화살표는 설명을 위한 순서입니다. 실제 작업은 반복되거나 겹칠 수 있습니다.':'Arrows show a teaching sequence. Real activities can overlap and repeat.'}</p></figure>`;
  }
  function evidence(lang){
    const ko=lang==='ko';
    const title=ko?'그림 2. 서로 다른 증거를 하나의 조사로 연결하기':'Figure 2. Bringing different evidence into one investigation';
    return `<figure class="learning-figure evidence-figure"><figcaption>${title}</figcaption><svg class="diagram" viewBox="0 0 340 365" role="img" aria-label="${ko?'네트워크 증거와 호스트 증거가 시간과 자산을 기준으로 연결되어 분석가의 판단으로 이어집니다.':'Network and host evidence are correlated by time and asset, then interpreted by an analyst.'}"><title>${title}</title><rect x="10" y="15" width="150" height="80" rx="6"/><rect x="180" y="15" width="150" height="80" rx="6"/><text x="85" y="47" text-anchor="middle">${ko?'네트워크':'Network'}</text><text x="85" y="73" text-anchor="middle">${ko?'통신·패킷':'Traffic / packets'}</text><text x="255" y="47" text-anchor="middle">${ko?'호스트':'Host'}</text><text x="255" y="73" text-anchor="middle">${ko?'계정·프로세스':'Accounts / processes'}</text><path class="flow-arrow" d="M85 95v30h85v25m85-55v30h-85m-5 19 5 6 5-6"/><rect x="45" y="154" width="250" height="73" rx="6"/><text x="170" y="183" text-anchor="middle">${ko?'시간·자산을 맞춰 연결':'Correlate time and assets'}</text><text x="170" y="207" text-anchor="middle">${ko?'SIEM / 조사 기록':'SIEM / investigation record'}</text><path class="flow-arrow" d="M170 229v33m-5-5 5 5 5-5"/><rect x="45" y="267" width="250" height="74" rx="6"/><text x="170" y="297" text-anchor="middle">${ko?'분석가의 판단':'Analyst judgement'}</text><text x="170" y="321" text-anchor="middle">${ko?'사실 / 가설 / 미확인':'Facts / hypotheses / unknowns'}</text></svg></figure>`;
  }
  const body={
    en:()=>`
      <section id="overview-1"><h2>1. Why look when nothing is broken?</h2>
      <p>Imagine a building where the doors still open and everyone can do their work. Someone has quietly entered with a stolen access card. Watching the front entrance helps, but it does not tell you which rooms that person visited after getting inside.</p>
      <p>A network can look just as ordinary while an intruder uses a legitimate account, reaches another system or maintains access. <strong>A working service and a quiet alert queue do not establish that the environment is free of intrusion.</strong> DCI starts with a question: if an adversary had already entered, what evidence could we look for?</p>
      <p>The building is an analogy. Network evidence can be incomplete, encrypted or scattered across systems; analysts must establish what their sensors and logs can actually show.</p></section>

      <section id="overview-2"><h2>2. What DCI means here</h2>
      <p>In this learning space, <strong>DCI means Discovery and Counter Infiltration</strong>. A 2025 article by a DISA author, published in the U.S. Department of the Navy’s CHIPS publication, describes analytics supporting DCI and enterprise hunts for advanced persistent threats that had not previously been detected. It also identifies improved analytics as an important outcome.${cite(1)}</p>
      <p>Think of DCI as a mission-oriented defensive effort: understand the environment, investigate possible adversary presence, support authorised action and improve the defences. <strong>Assuming that a breach is possible is a working mindset, not a finding that a breach has occurred.</strong></p>
      <p>Threat hunting is a closely related activity: analysts proactively search for threats that existing controls may have missed.${cite(4)} The DCI framing used here also connects that investigation to coordinated clearance, hardening support and assessment. Terminology and responsibilities can vary between organisations; this page does not establish the origin of the acronym or any official definition.</p></section>

      <section id="overview-3"><h2>3. DCI, SOC and incident response</h2>
      <p>A <strong>Security Operations Centre (SOC)</strong> provides ongoing security operations, including monitoring, investigation and detection development. A hunt asks a focused question even when an alert has not supplied the starting point. <strong>Incident response (IR)</strong> coordinates investigation, containment and recovery when an incident is suspected or confirmed.</p>
      <div class="article-table-wrap"><table class="article-table"><thead><tr><th>Activity</th><th>A typical starting question</th></tr></thead><tbody><tr><td>SOC monitoring</td><td>What triggered this alert, and does it need action?</td></tr><tr><td>Threat hunting / DCI hunt</td><td>What evidence would reveal activity our detections may have missed?</td></tr><tr><td>Incident response</td><td>What happened, what is affected, and how do we contain and recover?</td></tr></tbody></table></div>
      <p>These responsibilities overlap. A SOC can conduct hunts, an incident can trigger a wider hunt, and a hunt can uncover an incident. It would be misleading to describe every SOC as passive or IR as having no preparation work. NIST’s 2025 incident-response guidance integrates response with wider cybersecurity risk management.${cite(5)}</p></section>

      <section id="overview-4"><h2>4. Start with the mission</h2>
      <p>Before choosing a tool, ask what must keep working. A mission may depend on a planning server, identity services, a network link and the administrators who maintain them. That dependency chain is more useful than an unexplained list of IP addresses.</p>
      <p><strong>Mission-relevant cyber terrain</strong> means the systems, services and connections that matter to the mission. Identify their owners, normal access paths and the effects of interrupting them. Then decide what you can observe and what actions are authorised.</p>
      <p>A useful plan records the question to investigate, included assets, time window, required data, visibility gaps, investigation contacts and action authority. Collecting more data is not a substitute for knowing why it is needed. Historical “normal” activity may itself contain malicious activity, so validate the baseline with system owners.${cite(3)}</p></section>

      <section id="overview-5"><h2>5. A practical mission cycle</h2>
      <p>Public CPT reporting describes Hunt, Clear, Enable hardening and Assess activities.${cite(2)} The diagram adds a planning step to make the learning sequence explicit. <strong>This is an educational synthesis, not a prescribed operational procedure.</strong></p>
      ${cycle('en')}
      <h3>Plan: choose the question and the boundaries</h3><p>Identify the mission, relevant assets, available evidence and permitted actions. Write a testable hypothesis: for example, an intruder may be using a workstation to reach a server through a remote-management service.</p>
      <h3>Hunt: test the hypothesis</h3><p>Search the relevant network and host evidence. Compare findings with legitimate administration and normal dependencies. A hunt may support the hypothesis, weaken it or remain inconclusive because the required evidence is missing.</p>
      <h3>Clear: support coordinated removal</h3><p>When malicious activity is established, help scope affected systems, accounts and access mechanisms. Coordinate containment and removal under incident authority. An urgent threat may require immediate containment; understanding the full scope must not become a rule to delay necessary action.</p>
      <h3>Enable hardening: help close the route back in</h3><p>Turn findings into changes such as tighter administration paths or corrected access. Public Army reporting notes that the supported organisation normally implements hardening while the CPT advises.${cite(3)} Exact responsibilities depend on the local operating model.</p>
      <h3>Assess: verify outcomes and record limits</h3><p>Check that changes achieved the intended result, essential services still work and relevant detection remains effective. Feed lessons into the next plan. A disappearance of alerts alone does not demonstrate successful clearance.</p></section>

      <section id="overview-6"><h2>6. Connect network and host evidence</h2>
      <p>The network view helps explain who communicated with whom, when and over which visible protocols. The host view helps explain which accounts, processes and local changes were involved. Public Army reporting describes separate host-hunt and network-monitoring cells.${cite(3)}</p>
      <p>In this guide, a <strong>Network Analyst</strong> examines network traffic and related records, while a <strong>Host Analyst</strong> examines evidence from individual computers and servers, such as event logs and processes. These are descriptive role labels; one person may perform both kinds of analysis.</p>
      ${evidence('en')}
      <p>A <strong>Security Information and Event Management system (SIEM)</strong> can help search and connect collected records. Match time zones, asset identity and the relevant period; an IP address can be reassigned. The diagram shows an analysis relationship, not a requirement that every packet be stored in the SIEM.</p>
      <p>In a possible toolset, Snort provides network detection leads, Arkime supports examination of retained packets, Velociraptor supports host investigation, Hayabusa supports Windows event-log analysis and Splunk supports searching collected records. These are examples, not mandated DCI tools or proof of a particular organisation’s kit. Capabilities depend on deployment and configuration.</p>
      <p>MITRE ATT&amp;CK is a shared knowledge base for describing adversary tactics and techniques. Mapping a finding to ATT&amp;CK helps communicate the behaviour; it does not prove that an attack succeeded or that the necessary data was collected.${cite(6)}</p></section>

      <section id="overview-7"><h2>7. A small investigation example</h2>
      <p class="example-label">Fictional teaching example. Documentation-only addresses. No commands were run and no actual packets were analysed.</p>
      <p>Suppose an ordinary workstation, <code>192.0.2.25</code>, sends a TCP connection-start packet, a <strong>SYN</strong>, to <code>198.51.100.10:5985</code>. The destination is a critical server in this fictional environment. The colon separates the IP address from the port number.</p>
      <p>TCP port 5985 is the default HTTP listener port for WinRM, a Windows remote-management service.${cite(7)} That association makes it worth investigating if the workstation is not an approved administration source. It does not establish which application actually used the port.</p>
      <div class="evidence-level"><h3>Observed fact</h3><p>A packet with these addresses and destination port was captured at the stated time.</p><h3>Supported hypothesis</h3><p>The workstation may be attempting remote-management access. Legitimate management activity is an alternative explanation.</p><h3>Still unproven</h3><p>A completed connection, successful authentication, command execution, stolen credentials and compromise.</p></div>
      <p>The Network Analyst checks the response path, capture coverage and relevant traffic. The Host Analyst checks the associated host and authentication evidence. Both compare the activity with authorised work. Missing replies could reflect collection gaps; encrypted traffic may hide application content.</p></section>

      <section id="overview-8"><h2>8. What a useful hunt leaves behind</h2>
      <p>A useful result is more than a list of suspicious addresses. Record the question, examined assets and period, evidence locations, findings, alternative explanations and remaining gaps. Give each recommended action an owner and a way to verify completion.</p>
      <p>Separate <strong>observed facts, supported hypotheses and unresolved questions</strong>. Preserve the provenance of evidence: where it came from and how it was obtained. Where justified, convert a validated finding into a tested detection and document expected legitimate activity.</p>
      <p>“No matching activity was found in these data during this period” is a defensible scoped result. “There are no attackers anywhere in the environment” requires much more than a quiet search.</p></section>

      <section id="overview-9" class="review-section"><h2>9. Check your understanding</h2>
      <div class="review-item"><h3>1. No alert fired. Can you rule out intrusion?</h3><p><strong>Explanation:</strong> No. Establish sensor coverage, collection period, available data and detection conditions. A missing alert can reflect either an absence of matching activity or an observation gap.</p></div>
      <div class="review-item"><h3>2. Does a connection attempt to port 5985 prove malicious PowerShell execution?</h3><p><strong>Explanation:</strong> No. A port and a SYN show a connection attempt under the stated observation conditions. Confirm the service, connection, authentication, execution and authorisation separately.</p></div>
      <div class="review-item"><h3>3. Must the hunt team apply every hardening change itself?</h3><p><strong>Explanation:</strong> No. Identify the responsible operator and approval path. The team may recommend changes while the system owner implements them. Verify the effect afterwards.</p></div>
      <div class="review-item"><h3>4. What if a hunt finds nothing because the server logs are missing?</h3><p><strong>Explanation:</strong> Record an inconclusive result for questions requiring those logs. State what was checked, what remains unknown and which evidence would resolve it.</p></div></section>

      <section id="overview-10" class="sources-section"><h2>10. Sources and scope</h2><p>This overview combines public sources with original teaching examples. It is not a doctrine extract or a substitute for approved organisational procedures. Terminology, authority and task sequence must be confirmed for the actual mission.</p><p><strong>Sources checked: 5 November 2026.</strong> The 2017 and 2022 military reports describe particular teams and events; they are context, not evidence of how any organisation is structured today. NIST SP 800-61 Rev. 3 was published in 2025 and supersedes Rev. 2.</p>${sources('en')}</section>
    `,
    ko:()=>`
      <section id="overview-1"><h2>1. 멀쩡해 보이는데 왜 조사할까요?</h2>
      <p>건물의 문도 잘 열리고 직원들도 평소처럼 일하고 있다고 생각해볼게요. 그런데 누군가 훔친 출입증으로 들어와 사무실을 돌아다니고 있다면 어떨까요? 정문을 감시하는 일은 중요하지만, 이미 들어온 사람이 어느 방에 갔는지까지 알려주지는 않습니다.</p>
      <p>네트워크도 비슷합니다. 공격자가 정상 계정을 이용하거나 다른 시스템에 접근하면서도 서비스는 계속 정상 동작할 수 있어요. <strong>서비스가 정상이고 경보가 조용하다는 사실만으로 침입자가 없다고 판단할 수는 없습니다.</strong> DCI는 “이미 들어온 공격자가 있다면 어떤 증거로 찾아낼 수 있을까?”라는 질문에서 출발합니다.</p>
      <p>건물은 이해를 돕는 비유예요. 실제 네트워크 증거는 일부만 남거나 암호화되거나 여러 장비에 나뉘어 있을 수 있습니다. 먼저 센서와 로그로 무엇을 확인할 수 있는지 알아야 합니다.</p></section>

      <section id="overview-2"><h2>2. 이 사이트에서 말하는 DCI</h2>
      <p>이 학습 공간에서는 <strong>DCI를 Discovery and Counter Infiltration</strong>이라는 의미로 사용합니다. 미 국방정보시스템국(DISA) 소속 필자가 작성한 2025년 미 해군부 CHIPS 기사는, 이전에 탐지되지 않은 지능형 지속 위협을 찾는 DCI와 엔터프라이즈 헌팅을 지원하는 분석 규칙을 설명합니다. 분석 규칙의 개선도 주요 성과로 제시합니다.${cite(1)}</p>
      <p>쉽게 말하면, 임무 환경을 이해하고 침입자의 존재를 조사하며, 승인된 조치와 방어 개선까지 연결하는 방어 활동으로 생각하면 됩니다. 여기서 <strong>“침입이 가능하다고 가정한다”는 조사 태도와 “침입이 확인되었다”는 결론은 다릅니다.</strong></p>
      <p>이미 있는 보안 통제가 놓쳤을 수 있는 위협을 능동적으로 찾는 <strong>위협 헌팅(threat hunting)</strong>과 밀접한 관계가 있어요.${cite(4)} 이 사이트에서는 그 조사를 클리어, 하드닝 지원, 평가까지 연결해 설명합니다. 조직마다 용어와 책임이 다를 수 있으므로, 이 설명을 약어의 기원이나 공식 정의로 단정하지는 않습니다.</p></section>

      <section id="overview-3"><h2>3. SOC·사고 대응과의 관계</h2>
      <p><strong>SOC(Security Operations Centre, 보안관제센터)</strong>는 지속적인 감시와 조사, 탐지 능력 개발 등을 수행합니다. 헌팅은 경보가 출발점을 제공하지 않더라도 특정 질문을 정해 조사하는 활동입니다. <strong>IR(Incident Response, 사고 대응)</strong>은 사고가 의심되거나 확인되었을 때 조사·확산 방지·복구를 조정합니다.</p>
      <div class="article-table-wrap"><table class="article-table"><thead><tr><th>활동</th><th>대표적인 출발 질문</th></tr></thead><tbody><tr><td>SOC 모니터링</td><td>이 경보는 왜 발생했고 조치가 필요할까요?</td></tr><tr><td>위협 헌팅 / DCI 헌트</td><td>기존 탐지가 놓친 활동을 어떤 증거로 찾을까요?</td></tr><tr><td>사고 대응</td><td>무슨 일이 일어났고, 영향 범위와 차단·복구 방법은 무엇일까요?</td></tr></tbody></table></div>
      <p>실제로는 역할이 겹칩니다. SOC가 헌팅을 할 수도 있고, 사고 대응 중 더 넓은 범위를 헌팅할 수도 있으며, 헌팅에서 사고를 발견할 수도 있어요. 따라서 SOC는 항상 수동적이고 IR에는 준비 활동이 없다는 식으로 나누면 부정확합니다. 2025년 NIST 사고 대응 지침도 대응을 조직의 전반적인 사이버 위험 관리와 연결합니다.${cite(5)}</p></section>

      <section id="overview-4"><h2>4. 먼저 지켜야 할 임무부터</h2>
      <p>도구를 고르기 전에 “무엇이 계속 동작해야 하는가?”부터 생각해볼게요. 하나의 임무가 계획 서버뿐 아니라 계정 인증 서비스, 네트워크 연결, 이를 관리하는 인원에게도 의존할 수 있습니다. 이런 관계를 알아야 IP 주소 목록에 의미가 생깁니다.</p>
      <p><strong>임무 관련 사이버 지형(mission-relevant cyber terrain)</strong>은 임무에 중요한 시스템·서비스·연결을 뜻합니다. 소유자와 정상 접근 경로를 확인하고, 서비스를 중단했을 때의 영향도 파악합니다. 그다음 무엇을 관측하고 어떤 조치를 할 권한이 있는지 정해요.</p>
      <p>계획에는 조사 질문, 대상 자산, 시간 범위, 필요한 데이터, 관측 공백, 협조 담당자와 조치 권한을 기록합니다. 데이터를 많이 모으는 것만으로 목적이 분명해지는 것은 아닙니다. 과거에 관찰한 평소 활동 안에도 악성 활동이 섞여 있을 수 있으므로 시스템 소유자와 정상 기준을 확인해야 합니다.${cite(3)}</p></section>

      <section id="overview-5"><h2>5. 작전을 이해하는 기본 흐름</h2>
      <p>공개된 CPT(Cyber Protection Team, 사이버 보호팀) 자료에는 Hunt, Clear, Enable hardening, Assess 활동이 등장합니다.${cite(2)} 아래 그림은 이해를 돕기 위해 앞에 계획을 붙인 흐름입니다. <strong>공개 자료를 종합한 학습용 구조이며, 정해진 작전 절차를 재현한 것은 아닙니다.</strong></p>
      ${cycle('ko')}
      <h3>계획: 무엇을 어디까지 조사할까요?</h3><p>임무와 중요 자산, 확보할 수 있는 증거, 허용된 조치를 정합니다. 예를 들어 “공격자가 직원 PC에서 원격 관리 기능으로 서버에 접근할 수 있다”처럼 증거로 확인할 수 있는 가설을 세워요.</p>
      <h3>헌트: 가설을 증거와 대조합니다</h3><p>관련 네트워크와 호스트 데이터를 확인하고 정상 관리 작업·업무 의존 관계와 비교합니다. 결과가 가설을 지지할 수도, 약화할 수도 있어요. 필요한 증거가 없어서 판단을 유보해야 할 수도 있습니다.</p>
      <h3>클리어: 승인된 제거 조치를 함께 준비합니다</h3><p>악성 활동이 확인되면 영향받은 시스템·계정·접근 수단의 범위를 파악하고 사고 대응 권한 아래에서 확산 방지와 제거를 조정합니다. 즉각적인 피해가 우려되면 긴급 차단이 필요할 수 있어요. 전체 범위를 알아야 한다는 이유로 필요한 조치를 무조건 미루어서는 안 됩니다.</p>
      <h3>하드닝 지원: 같은 길로 다시 들어오지 못하게 합니다</h3><p>조사 결과를 관리 경로 제한이나 접근 권한 개선 같은 변경으로 연결합니다. 미 육군의 공개 사례에서는 지원받는 조직이 보통 하드닝을 실행하고 CPT가 권고한다고 설명해요.${cite(3)} 실제 책임은 해당 조직의 운영 구조에 따라 확인해야 합니다.</p>
      <h3>평가: 조치가 효과가 있었는지 확인합니다</h3><p>변경의 목적을 달성했는지, 필수 서비스가 정상인지, 관련 탐지가 계속 동작하는지 확인하고 다음 계획에 반영합니다. 경보가 사라진 것만으로 공격자 제거가 끝났다고 판단하지는 않습니다.</p></section>

      <section id="overview-6"><h2>6. 네트워크와 호스트 증거 연결</h2>
      <p>네트워크에서는 누가 누구와 언제, 어떤 관측 가능한 방식으로 통신했는지 살펴봅니다. 호스트, 즉 PC·서버 같은 개별 시스템에서는 어떤 계정과 프로세스, 로컬 변경이 관련되었는지 조사해요. 미 육군 공개 사례에도 호스트 헌트와 네트워크 감시 셀이 등장합니다.${cite(3)}</p>
      <p>이 사이트에서는 통신과 관련 기록을 살펴보는 사람을 <strong>네트워크 분석 담당자(Network Analyst)</strong>, 개별 PC·서버의 이벤트 로그와 프로세스 같은 증거를 살펴보는 사람을 <strong>호스트 분석 담당자(Host Analyst)</strong>라고 부릅니다. 분석 업무를 설명하는 일반적인 표현이며, 한 사람이 두 업무를 함께 맡을 수도 있어요.</p>
      ${evidence('ko')}
      <p><strong>SIEM(Security Information and Event Management, 보안 정보·이벤트 관리 시스템)</strong>은 수집한 기록을 검색하고 연결하는 데 도움을 줍니다. 시간대와 자산, 해당 시점의 주소 할당을 맞춰야 해요. IP 주소는 다른 장비에 재할당될 수 있습니다. 그림은 분석 관계를 보여주는 것이며, 모든 패킷을 SIEM에 저장해야 한다는 뜻은 아닙니다.</p>
      <p>도구 구성의 예로는 Snort의 네트워크 탐지 단서, Arkime의 보관 패킷 확인, Velociraptor의 호스트 조사, Hayabusa의 Windows 이벤트 로그 분석, Splunk의 수집 기록 검색을 연결할 수 있습니다. 이는 예시이며 DCI의 필수 제품 목록이나 특정 조직 키트의 공식 구성을 뜻하지 않습니다. 실제 능력은 배치와 설정에 따라 달라져요.</p>
      <p><strong>MITRE ATT&amp;CK</strong>는 공격자의 전술과 기법을 설명하는 공통 지식 체계입니다. 관측한 행위를 공통 언어로 설명하는 데 유용하지만, 기법에 연결했다고 공격 성공이 증명되거나 필요한 데이터가 자동 수집되는 것은 아닙니다.${cite(6)}</p></section>

      <section id="overview-7"><h2>7. 작은 조사 사례로 이해하기</h2>
      <p class="example-label">자체 제작한 가상 사례입니다. 문서용 주소를 사용했으며, 명령 실행이나 실제 패킷 분석 결과가 아닙니다.</p>
      <p>일반 직원 PC인 <code>192.0.2.25</code>가 이 가상 환경의 핵심 서버 <code>198.51.100.10:5985</code>로 TCP 연결 시작 패킷인 <strong>SYN</strong>을 보냈다고 해볼게요. 콜론은 IP 주소와 통신 포트 번호를 구분하는 기호입니다.</p>
      <p>TCP 5985는 Windows 원격 관리 서비스인 WinRM의 기본 HTTP 포트입니다.${cite(7)} 이 PC가 승인된 관리 장비가 아니라면 조사할 가치가 있어요. 하지만 포트 번호만으로 실제 사용 프로그램을 확정할 수는 없습니다.</p>
      <div class="evidence-level"><h3>직접 관측한 사실</h3><p>해당 시각에 이 주소와 목적지 포트를 가진 패킷을 수집했습니다.</p><h3>그 사실이 지지하는 가설</h3><p>직원 PC가 원격 관리 접근을 시도했을 수 있습니다. 정상 관리 작업이라는 다른 설명도 검토해야 합니다.</p><h3>아직 확인되지 않은 결론</h3><p>연결 성립, 인증 성공, 명령 실행, 계정 탈취와 시스템 침해 여부입니다.</p></div>
      <p>네트워크 분석 담당자는 응답 경로와 수집 범위, 관련 통신을 확인합니다. 호스트 분석 담당자는 관련 호스트와 인증 증거를 확인하고, 함께 승인된 작업 여부를 대조해요. 응답이 없는 것은 수집 공백 때문일 수 있고, 암호화된 통신에서는 애플리케이션 내용을 읽지 못할 수 있습니다.</p></section>

      <section id="overview-8"><h2>8. 헌팅이 남겨야 하는 결과</h2>
      <p>좋은 결과는 의심 주소 목록만으로 끝나지 않습니다. 조사 질문, 확인한 자산과 기간, 증거 위치, 발견 사항, 다른 가능한 설명과 남은 공백을 기록해요. 권고한 조치에는 담당자와 완료 여부를 확인할 방법을 연결합니다.</p>
      <p><strong>관측한 사실, 근거 있는 가설, 미확인 질문을 구분</strong>하고 증거의 출처와 확보 방법을 남깁니다. 충분히 검증한 발견 사항은 정상 활동을 고려해 시험한 탐지 규칙으로 발전시킬 수 있습니다.</p>
      <p>“이 기간에 이 자료에서 조건에 맞는 활동을 찾지 못했다”는 범위를 밝힌 결과입니다. “전체 환경에 공격자가 없다”는 결론에는 조용한 검색 결과보다 훨씬 많은 근거가 필요합니다.</p></section>

      <section id="overview-9" class="review-section"><h2>9. 복습 질문과 해설</h2>
      <div class="review-item"><h3>1. 경보가 없으면 침입도 없다고 볼 수 있을까요?</h3><p><strong>해설:</strong> 먼저 센서 범위, 수집 기간, 확보 데이터와 탐지 조건을 확인해야 합니다. 경보 부재는 일치하는 활동이 없었기 때문일 수도, 관측 공백 때문일 수도 있어요.</p></div>
      <div class="review-item"><h3>2. 5985 포트로 접속을 시도하면 악성 PowerShell 실행이 증명될까요?</h3><p><strong>해설:</strong> 아닙니다. 해당 관측 조건에서 포트와 SYN은 연결 시도의 단서입니다. 실제 서비스와 연결·인증·실행·승인 여부를 각각 확인해야 합니다.</p></div>
      <div class="review-item"><h3>3. 헌팅팀이 모든 하드닝 변경을 직접 해야 할까요?</h3><p><strong>해설:</strong> 담당 운영자와 승인 경로를 확인해야 합니다. 팀이 변경을 권고하고 시스템 소유자가 적용할 수 있어요. 적용 후 효과도 확인합니다.</p></div>
      <div class="review-item"><h3>4. 서버 로그가 없어서 아무것도 못 찾았다면 어떻게 기록할까요?</h3><p><strong>해설:</strong> 해당 로그가 필요한 질문은 판단을 유보합니다. 확인한 부분과 남은 의문, 이를 해소할 증거를 구체적으로 적어야 합니다.</p></div></section>

      <section id="overview-10" class="sources-section"><h2>10. 출처와 적용 범위</h2><p>공개 자료와 자체 교육 예제를 종합한 개요입니다. 교리의 발췌문이나 승인된 조직 절차를 대신하는 자료가 아닙니다. 실제 임무의 용어·권한·작업 순서를 확인해야 합니다.</p><p><strong>출처 확인일: 2026년 11월 5일.</strong> 2017년과 2022년의 군 자료는 특정 팀과 당시 사례를 설명하며, 현재 어떤 조직의 편제도 증명하지 않습니다. NIST SP 800-61 Rev. 3은 2025년에 발행되어 Rev. 2를 대체했습니다.</p>${sources('ko')}</section>
    `
  };
  function render(lang){
    const ko=lang==='ko';
    return `<article class="overview-article" aria-label="${ko?'DCI 개요 본문':'DCI overview article'}"><div class="article-meta"><span>${ko?'기초 / 개요':'FOUNDATIONS / OVERVIEW'}</span><span>${ko?'확인일: 2026년 11월 5일':'Reviewed: 5 November 2026'}</span></div><nav class="article-toc" aria-label="${ko?'이 글의 목차':'On this page'}"><h2>${ko?'이 글에서 다룰 내용':'On this page'}</h2><ol>${toc[lang].map((t,i)=>`<li><a href="#overview-${i+1}" data-scroll="overview-${i+1}">${t}</a></li>`).join('')}</ol></nav><div class="article-body">${body[lang]()}</div></article>`;
  }
  return {render,sources};
})();
