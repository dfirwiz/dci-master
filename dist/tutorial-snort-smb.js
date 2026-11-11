/* Tutorial 01: Snort 2 rules for malicious SMB use.
   All addresses, hosts, accounts and times are fictional (lab network 10.50.0.0/24).
   The six practice PCAPs were generated for this site and every Snort output on this page was
   produced by running Snort 2.9.20 (Ubuntu 24.04 package) on them, 11 November 2026, with -U (UTC times). */
window.DCI_TUTORIAL_SNORT_SMB = (() => {
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const c = (s) => `<pre><code>${esc(s.replace(/^\n/, ''))}</code></pre>`;
  const label = (s) => `<p class="example-label">${s}</p>`;
  const tbl = (head, rows, cls = 'compact-table') => `<div class="article-table-wrap"><table class="article-table ${cls}"><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((x) => `<td>${x}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  const run = {en: 'Real output (Snort 2.9.20):', ko: '실제 출력 (Snort 2.9.20):'};
  const out = (lang, s) => `<p class="example-output-label"><strong>${run[lang]}</strong></p>` + c(s);
  const L = './assets/labs/';
  const dl = (f) => `<a href="${L}${f}" download><code>${f}</code></a>`;

  /* ---------- shared code blocks ---------- */
  const VARS = String.raw`ipvar HOME_NET [10.50.0.0/24]
ipvar EXTERNAL_NET any
portvar SMB_PORTS [139,445]
ipvar ADMIN_HOSTS [10.50.0.5]`;
  const RUN = String.raw`sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-psexec.pcap`;
  const R = {
    v1: String.raw`alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB: SMBv1 negotiate request"; flow:established,to_server; content:"|FF|SMB|72|"; offset:4; depth:5; classtype:policy-violation; sid:1000101; rev:1;)`,
    admin: String.raw`alert tcp !$ADMIN_HOSTS any -> $HOME_NET $SMB_PORTS (msg:"SMB: ADMIN$ share connect from non-admin host"; flow:established,to_server; content:"|FE|SMB"; offset:4; depth:4; content:"|03 00|"; offset:16; depth:2; content:"|5C 00|A|00|D|00|M|00|I|00|N|00|$|00|"; nocase; distance:0; classtype:policy-violation; sid:1000102; rev:1;)
alert tcp !$ADMIN_HOSTS any -> $HOME_NET $SMB_PORTS (msg:"SMB: C$ share connect from non-admin host"; flow:established,to_server; content:"|FE|SMB"; offset:4; depth:4; content:"|03 00|"; offset:16; depth:2; content:"|5C 00|C|00|$|00|"; nocase; distance:0; classtype:policy-violation; sid:1000103; rev:1;)`,
    files: String.raw`alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB: .exe file created on remote host"; flow:established,to_server; content:"|FE|SMB"; offset:4; depth:4; content:"|05 00|"; offset:16; depth:2; content:".|00|e|00|x|00|e|00|"; nocase; distance:0; classtype:suspicious-filename-detect; sid:1000104; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB: Windows executable (MZ) written"; flow:established,to_server; content:"|FE|SMB"; offset:4; depth:4; content:"|09 00|"; offset:16; depth:2; content:"MZ"; offset:116; depth:2; classtype:suspicious-filename-detect; sid:1000105; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB: PsExec service name PSEXESVC"; flow:established,to_server; content:"P|00|S|00|E|00|X|00|E|00|S|00|V|00|C|00|"; nocase; classtype:attempted-admin; sid:1000106; rev:1;)`,
    bind: String.raw`alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind SVCCTL"; flow:established,to_server; content:"|05 00 0B|"; content:"|81 BB 7A 36 44 98 F1 35 AD 32 98 F0 38 00 10 03|"; distance:0; flowbits:set,dce.svcctl; flowbits:noalert; sid:1000120; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind SAMR"; flow:established,to_server; content:"|05 00 0B|"; content:"|78 57 34 12 34 12 CD AB EF 00 01 23 45 67 89 AC|"; distance:0; flowbits:set,dce.samr; flowbits:noalert; sid:1000121; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind SRVSVC"; flow:established,to_server; content:"|05 00 0B|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; distance:0; flowbits:set,dce.srvsvc; flowbits:noalert; sid:1000122; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind ATSVC"; flow:established,to_server; content:"|05 00 0B|"; content:"|82 06 F7 1F 51 0A E8 30 07 6D 74 0B E8 CE E9 8B|"; distance:0; flowbits:set,dce.atsvc; flowbits:noalert; sid:1000123; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind ITaskSchedulerService"; flow:established,to_server; content:"|05 00 0B|"; content:"|49 59 D3 86 C9 83 44 40 B4 24 DB 36 32 31 FD 0C|"; distance:0; flowbits:set,dce.itask; flowbits:noalert; sid:1000124; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"DCERPC bind WINREG"; flow:established,to_server; content:"|05 00 0B|"; content:"|01 D0 8C 33 44 22 F1 31 AA AA 90 00 38 00 10 03|"; distance:0; flowbits:set,dce.winreg; flowbits:noalert; sid:1000125; rev:1;)`,
    ops: String.raw`alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: SVCCTL CreateServiceW - remote service creation"; flow:established,to_server; flowbits:isset,dce.svcctl; content:"|05 00 00 03 10 00 00 00|"; content:"|0C 00|"; distance:14; within:2; classtype:attempted-admin; sid:1000130; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: SAMR EnumerateUsersInDomain - user enumeration"; flow:established,to_server; flowbits:isset,dce.samr; content:"|05 00 00 03 10 00 00 00|"; content:"|0D 00|"; distance:14; within:2; classtype:attempted-recon; sid:1000131; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: SRVSVC NetrShareEnum - share enumeration"; flow:established,to_server; flowbits:isset,dce.srvsvc; content:"|05 00 00 03 10 00 00 00|"; content:"|0F 00|"; distance:14; within:2; classtype:attempted-recon; sid:1000132; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: ATSVC NetrJobAdd - remote at job"; flow:established,to_server; flowbits:isset,dce.atsvc; content:"|05 00 00 03 10 00 00 00|"; content:"|00 00|"; distance:14; within:2; classtype:attempted-admin; sid:1000133; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: SchRpcRegisterTask - remote scheduled task"; flow:established,to_server; flowbits:isset,dce.itask; content:"|05 00 00 03 10 00 00 00|"; content:"|01 00|"; distance:14; within:2; classtype:attempted-admin; sid:1000134; rev:1;)
alert tcp any any -> $HOME_NET $SMB_PORTS (msg:"SMB RPC: WINREG write to Run key - persistence"; flow:established,to_server; flowbits:isset,dce.winreg; content:"|05 00 00 03 10 00 00 00|"; content:"|06 00|"; distance:14; within:2; content:"|5C 00|R|00|u|00|n|00|"; nocase; distance:0; classtype:attempted-admin; sid:1000135; rev:1;)`,
    brute: String.raw`alert tcp $HOME_NET $SMB_PORTS -> any any (msg:"SMB: repeated logon failures - password guessing"; flow:established,to_client,no_stream; content:"|FE|SMB"; offset:4; depth:4; content:"|6D 00 00 C0 01 00|"; distance:4; within:6; detection_filter:track by_dst, count 5, seconds 60; classtype:unsuccessful-user; sid:1000140; rev:1;)`
  };
  const O = {
    benign: '(no output — 0 alerts)',
    psexec: String.raw`11/03-01:10:00.022901  [**] [1:1000102:1] SMB: ADMIN$ share connect from non-admin host [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.027201  [**] [1:1000106:1] SMB: PsExec service name PSEXESVC [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.027201  [**] [1:1000104:1] SMB: .exe file created on remote host [**] [Classification: A suspicious filename was detected] [Priority: 2] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.031501  [**] [1:1000105:1] SMB: Windows executable (MZ) written [**] [Classification: A suspicious filename was detected] [Priority: 2] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.066702  [**] [1:1000106:1] SMB: PsExec service name PSEXESVC [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.066702  [**] [1:1000130:1] SMB RPC: SVCCTL CreateServiceW - remote service creation [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445
11/03-01:10:00.088202  [**] [1:1000106:1] SMB: PsExec service name PSEXESVC [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51734 -> 10.50.0.31:445`,
    recon: String.raw`11/03-01:20:00.057302  [**] [1:1000131:1] SMB RPC: SAMR EnumerateUsersInDomain - user enumeration [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.50.0.66:51802 -> 10.50.0.10:445
11/03-01:20:00.117503  [**] [1:1000132:1] SMB RPC: SRVSVC NetrShareEnum - share enumeration [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.50.0.66:51802 -> 10.50.0.10:445`,
    remote: String.raw`11/03-01:30:00.040101  [**] [1:1000133:1] SMB RPC: ATSVC NetrJobAdd - remote at job [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51911 -> 10.50.0.31:445
11/03-01:30:00.065902  [**] [1:1000134:1] SMB RPC: SchRpcRegisterTask - remote scheduled task [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51911 -> 10.50.0.31:445
11/03-01:30:00.100303  [**] [1:1000135:1] SMB RPC: WINREG write to Run key - persistence [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.50.0.66:51911 -> 10.50.0.31:445`,
    brute: String.raw`11/03-01:40:02.644004  [**] [1:1000140:1] SMB: repeated logon failures - password guessing [**] [Classification: Unsuccessful User Privilege Gain] [Priority: 1] {TCP} 10.50.0.10:445 -> 10.50.0.66:52005
11/03-01:40:03.168704  [**] [1:1000140:1] SMB: repeated logon failures - password guessing [**] [Classification: Unsuccessful User Privilege Gain] [Priority: 1] {TCP} 10.50.0.10:445 -> 10.50.0.66:52006
... (5 more lines: ports 52007 to 52011)`,
    v1: String.raw`11/03-01:50:00.012800  [**] [1:1000101:1] SMB: SMBv1 negotiate request [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 10.50.0.66:52201 -> 10.50.0.20:445`,
    benignNoAdmin: String.raw`11/03-01:00:30.065002  [**] [1:1000103:1] SMB: C$ share connect from non-admin host [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 10.50.0.5:50220 -> 10.50.0.31:445`
  };
  const ALL = '# ===== DCI Master Tutorial 01: malicious SMB use (Snort 2.9) =====\n# --- Level 1: SMB protocol and share access ---\n' + R.v1 + '\n' + R.admin + '\n# --- Level 1: files and tool names ---\n' + R.files + '\n# --- Level 2: DCE/RPC bind (sets a flowbit, no alert) ---\n' + R.bind + '\n# --- Level 2: DCE/RPC request = interface (flowbit) + opnum ---\n' + R.ops + '\n# --- Level 3: behaviour over time ---\n' + R.brute;

  const files = ['t01-smb-benign.pcap', 't01-smb-psexec.pcap', 't01-smb-recon.pcap', 't01-smb-remote-exec.pcap', 't01-smb-bruteforce.pcap', 't01-smbv1.pcap'];
  const hosts = {
    en: tbl(['Host', 'Address', 'Role'], [['DC01', '10.50.0.10', 'Domain controller'], ['FS01', '10.50.0.20', 'File server'], ['WS031', '10.50.0.31', 'Workstation (target)'], ['WS066', '10.50.0.66', 'Compromised workstation (attacker)'], ['JUMP01', '10.50.0.5', 'Approved IT admin jump host']]),
    ko: tbl(['호스트', '주소', '역할'], [['DC01', '10.50.0.10', '도메인 컨트롤러'], ['FS01', '10.50.0.20', '파일 서버'], ['WS031', '10.50.0.31', '워크스테이션 (공격 대상)'], ['WS066', '10.50.0.66', '감염된 워크스테이션 (공격자)'], ['JUMP01', '10.50.0.5', '승인된 IT 관리용 점프 호스트']])
  };

  const sections = [
    {
      id: 's-goal',
      title: {en: 'What you will build', ko: '이 튜토리얼에서 만드는 것'},
      html: {
        en: label('All addresses, host names, accounts and times are fictional. The six practice PCAPs were generated for this site, and every alert shown here is real output from Snort 2.9.20 run on them.') +
          `<p>SMB is how Windows shares files and runs remote administration. Attackers use the very same features after they get one foothold: they copy tools to admin shares, create services to run them, list users and shares, schedule tasks and guess passwords. In this tutorial you write <strong>19 Snort 2 rules</strong> for those behaviours, set the variables they need, and test each rule against a practice PCAP until you see exactly the alerts you expect — and none on normal traffic.</p>` +
          tbl(['Attacker behaviour', 'What crosses the wire', 'Rule (sid)', 'Practice PCAP'], [
            ['Old, vulnerable protocol', 'SMBv1 negotiate <code>FF 53 4D 42 72</code>', '1000101', '<code>t01-smbv1.pcap</code>'],
            ['Admin share access', 'Tree connect to <code>\\ADMIN$</code>, <code>\\C$</code>', '1000102–103', '<code>t01-smb-psexec.pcap</code>, <code>t01-smb-benign.pcap</code>'],
            ['Tool copied and run (PsExec style)', 'Create <code>*.exe</code>, write <code>MZ</code>, service <code>PSEXESVC</code>, SVCCTL CreateServiceW', '1000104–106, 1000130', '<code>t01-smb-psexec.pcap</code>'],
            ['Reconnaissance', 'SAMR user list, SRVSVC share list', '1000131–132', '<code>t01-smb-recon.pcap</code>'],
            ['Remote execution / persistence', 'ATSVC job, Task Scheduler, registry Run key', '1000133–135', '<code>t01-smb-remote-exec.pcap</code>'],
            ['Password guessing', 'Many <code>STATUS_LOGON_FAILURE</code> replies', '1000140', '<code>t01-smb-bruteforce.pcap</code>']
          ]) +
          `<h3>Download the lab files</h3><p>${files.map(dl).join(', ')} and the finished rule file ${dl('t01-smb-local.rules')}. Put them in <code>~/smb-lab/</code>.</p>` + hosts.en,
        ko: label('모든 주소, 호스트 이름, 계정, 시각은 가상입니다. 실습 PCAP 6개는 이 사이트용으로 만들었고, 여기 나오는 경보는 모두 그 PCAP에 Snort 2.9.20을 실제로 돌린 결과입니다.') +
          `<p>SMB는 Windows가 파일을 공유하고 원격 관리를 하는 방식입니다. 공격자는 한 대를 장악한 뒤 바로 이 기능들을 그대로 씁니다. 관리 공유에 도구를 복사하고, 서비스를 만들어 실행하고, 사용자와 공유 목록을 빼내고, 예약 작업을 등록하고, 비밀번호를 추측합니다. 이 튜토리얼에서는 이런 행동을 잡는 <strong>Snort 2 룰 19개</strong>를 작성하고, 룰에 필요한 변수를 설정한 다음, 실습 PCAP으로 하나씩 시험합니다. 목표는 예상한 경보만 정확히 나오고 정상 트래픽에서는 아무것도 나오지 않는 것입니다.</p>` +
          tbl(['공격자 행동', '네트워크에 보이는 것', '룰 (sid)', '실습 PCAP'], [
            ['오래되고 취약한 프로토콜', 'SMBv1 negotiate <code>FF 53 4D 42 72</code>', '1000101', '<code>t01-smbv1.pcap</code>'],
            ['관리 공유 접근', '<code>\\ADMIN$</code>, <code>\\C$</code>에 tree connect', '1000102~103', '<code>t01-smb-psexec.pcap</code>, <code>t01-smb-benign.pcap</code>'],
            ['도구 복사 후 실행 (PsExec 방식)', '<code>*.exe</code> 생성, <code>MZ</code> 쓰기, <code>PSEXESVC</code> 서비스, SVCCTL CreateServiceW', '1000104~106, 1000130', '<code>t01-smb-psexec.pcap</code>'],
            ['정보 수집', 'SAMR 사용자 목록, SRVSVC 공유 목록', '1000131~132', '<code>t01-smb-recon.pcap</code>'],
            ['원격 실행 / 지속성', 'ATSVC 작업, 작업 스케줄러, 레지스트리 Run 키', '1000133~135', '<code>t01-smb-remote-exec.pcap</code>'],
            ['비밀번호 추측', '<code>STATUS_LOGON_FAILURE</code> 응답이 반복', '1000140', '<code>t01-smb-bruteforce.pcap</code>']
          ]) +
          `<h3>실습 파일 내려받기</h3><p>${files.map(dl).join(', ')}, 그리고 완성된 룰 파일 ${dl('t01-smb-local.rules')}. 모두 <code>~/smb-lab/</code>에 넣으세요.</p>` + hosts.ko
      }
    },
    {
      id: 's-vars',
      title: {en: 'Step 1: set the environment variables', ko: '1단계: 환경 변수 설정'},
      html: {
        en: `<p>Snort rules do not hard-code addresses. They use <strong>variables</strong> defined in <code>/etc/snort/snort.conf</code>, so the same rule works on any network. Open the file and edit Step 1 (near line 65):</p>` +
          c(`sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
sudo nano /etc/snort/snort.conf`) +
          c(VARS) +
          tbl(['Line', 'What it does', 'Why this value'], [
            ['<code>ipvar HOME_NET [10.50.0.0/24]</code>', 'The network you protect', 'Every rule here uses <code>-&gt; $HOME_NET</code> as the target. If it is wrong, nothing matches.'],
            ['<code>ipvar EXTERNAL_NET any</code>', 'Where attacks may come from', '<strong>SMB attacks come from inside.</strong> The common setting <code>!$HOME_NET</code> means “not internal”, so a rule written <code>$EXTERNAL_NET any -&gt; $HOME_NET</code> would miss WS066 → WS031. These rules use <code>any</code> as the source anyway.'],
            ['<code>portvar SMB_PORTS [139,445]</code>', 'A new port variable', '445 is SMB over TCP; 139 is SMB over NetBIOS. Defining it once means you can add a port in one place later.'],
            ['<code>ipvar ADMIN_HOSTS [10.50.0.5]</code>', 'A new address variable', 'IT jump hosts are <em>supposed</em> to use <code>C$</code> and <code>ADMIN$</code>. Rules 1000102–103 use <code>!$ADMIN_HOSTS</code> (“not an admin host”) as the source.']
          ]) +
          `<p><code>ipvar</code> holds addresses, <code>portvar</code> holds ports. Square brackets hold a list; separate items with commas and <strong>no spaces</strong>.</p>` +
          `<h3>Make sure local.rules is loaded</h3><p>Further down (Step 7) you should find this line without a <code>#</code> in front of it:</p>` +
          c(`include $RULE_PATH/local.rules`) +
          c(`grep -n "local.rules" /etc/snort/snort.conf`) +
          `<h3>Check the configuration</h3>` + c(`sudo snort -T -c /etc/snort/snort.conf`) + `<p><code>-T</code> means “test the configuration and exit”. The last lines must be:</p>` +
          out('en', `Snort successfully validated the configuration!
Snort exiting`) +
          `<p>If a rule uses a variable you forgot to define, <code>-T</code> stops with a clear message. This is what happened when <code>portvar SMB_PORTS</code> was missing:</p>` +
          out('en', `ERROR: /etc/snort/rules/local.rules(3) ***PortVar Lookup failed on '$SMB_PORTS'.
Fatal Error, Quitting..`),
        ko: `<p>Snort 룰에는 주소를 직접 적지 않습니다. <code>/etc/snort/snort.conf</code>에 정의한 <strong>변수</strong>를 써서, 같은 룰이 어느 네트워크에서나 동작하게 합니다. 파일을 열고 Step 1 부분(65번째 줄 근처)을 고칩니다.</p>` +
          c(`sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
sudo nano /etc/snort/snort.conf`) +
          c(VARS) +
          tbl(['줄', '하는 일', '이 값을 쓰는 이유'], [
            ['<code>ipvar HOME_NET [10.50.0.0/24]</code>', '보호할 네트워크', '여기 룰은 모두 대상이 <code>-&gt; $HOME_NET</code>입니다. 이 값이 틀리면 아무것도 탐지되지 않습니다.'],
            ['<code>ipvar EXTERNAL_NET any</code>', '공격이 올 수 있는 곳', '<strong>SMB 공격은 내부에서 옵니다.</strong> 흔히 쓰는 <code>!$HOME_NET</code>은 "내부가 아닌 곳"이라는 뜻이라, <code>$EXTERNAL_NET any -&gt; $HOME_NET</code>으로 쓴 룰은 WS066 → WS031 공격을 놓칩니다. 그래서 이 룰들은 출발지를 아예 <code>any</code>로 둡니다.'],
            ['<code>portvar SMB_PORTS [139,445]</code>', '새로 만드는 포트 변수', '445는 TCP 위의 SMB, 139는 NetBIOS 위의 SMB입니다. 한 곳에 정의해 두면 나중에 포트를 추가할 때 한 곳만 고치면 됩니다.'],
            ['<code>ipvar ADMIN_HOSTS [10.50.0.5]</code>', '새로 만드는 주소 변수', 'IT 점프 호스트는 원래 <code>C$</code>, <code>ADMIN$</code>를 씁니다. 1000102~103 룰은 출발지를 <code>!$ADMIN_HOSTS</code>("관리 호스트가 아닌 곳")로 둡니다.']
          ]) +
          `<p><code>ipvar</code>는 주소, <code>portvar</code>는 포트를 담습니다. 대괄호 안은 목록이고, 항목은 쉼표로 나누며 <strong>공백을 넣지 않습니다</strong>.</p>` +
          `<h3>local.rules가 읽히는지 확인</h3><p>아래쪽(Step 7)에 이 줄이 <code>#</code> 없이 있어야 합니다.</p>` +
          c(`include $RULE_PATH/local.rules`) +
          c(`grep -n "local.rules" /etc/snort/snort.conf`) +
          `<h3>설정 검사</h3>` + c(`sudo snort -T -c /etc/snort/snort.conf`) + `<p><code>-T</code>는 "설정만 검사하고 끝내라"는 뜻입니다. 마지막 줄이 이렇게 나와야 합니다.</p>` +
          out('ko', `Snort successfully validated the configuration!
Snort exiting`) +
          `<p>룰이 정의하지 않은 변수를 쓰면 <code>-T</code>가 정확한 메시지를 내고 멈춥니다. <code>portvar SMB_PORTS</code>를 빠뜨렸을 때 실제로 나온 메시지입니다.</p>` +
          out('ko', `ERROR: /etc/snort/rules/local.rules(3) ***PortVar Lookup failed on '$SMB_PORTS'.
Fatal Error, Quitting..`)
      }
    },
    {
      id: 's-bytes',
      title: {en: 'Step 2: how SMB2 looks to Snort', ko: '2단계: Snort가 보는 SMB2의 모양'},
      html: {
        en: `<p>Snort compares bytes. To write a precise rule you need to know <strong>where</strong> things sit in the packet payload. Every SMB2 message over TCP 445 starts like this (offsets count from 0 at the start of the TCP payload):</p>` +
          tbl(['Offset', 'Bytes', 'Meaning'], [
            ['0–3', '<code>00 00 01 2C</code>', 'NetBIOS session header: message length'],
            ['4–7', '<code>FE 53 4D 42</code>', 'SMB2 magic <code>|FE|SMB</code> (SMBv1 uses <code>|FF|SMB</code>)'],
            ['12–15', '<code>6D 00 00 C0</code>', 'Status (here <code>STATUS_LOGON_FAILURE</code> = 0xC000006D, little-endian)'],
            ['16–17', '<code>03 00</code>', 'Command (little-endian): 01 session setup, 03 tree connect, 05 create, 09 write'],
            ['68 →', '…', 'Command body. For WRITE the file data starts at offset 116 (4 + 112)']
          ]) +
          `<p>Two more facts explain most SMB rules:</p>` +
          `<p><strong>Names are UTF-16LE.</strong> Windows sends <code>ADMIN$</code> as <code>A 00 D 00 M 00 I 00 N 00 $ 00</code>. In a Snort content string that is <code>"A|00|D|00|M|00|I|00|N|00|$|00|"</code>. A plain <code>content:"ADMIN$"</code> never matches.</p>` +
          `<p><strong>Numbers are little-endian.</strong> Command 3 is <code>03 00</code>, not <code>00 03</code>.</p>` +
          `<p>Check it yourself in Wireshark: open <code>t01-smb-psexec.pcap</code>, filter <code>smb2.cmd == 3</code>, click the Tree Connect Request and look at the bytes pane. Or use TShark:</p>` +
          c(`tshark -r ~/smb-lab/t01-smb-psexec.pcap -Y "smb2.cmd==3 && smb2.flags.response==0" -T fields -e frame.number -e smb2.tree`) +
          out('en', `12	\\\\WS031\\ADMIN$
32	\\\\WS031\\IPC$`).replace('Snort 2.9.20', 'TShark 4.2.2'),
        ko: `<p>Snort는 바이트를 비교합니다. 정확한 룰을 쓰려면 패킷 데이터 안에서 무엇이 <strong>어디에</strong> 있는지 알아야 합니다. TCP 445 위의 SMB2 메시지는 모두 이렇게 시작합니다(오프셋은 TCP 데이터 맨 앞을 0으로 셉니다).</p>` +
          tbl(['오프셋', '바이트', '뜻'], [
            ['0~3', '<code>00 00 01 2C</code>', 'NetBIOS 세션 헤더: 메시지 길이'],
            ['4~7', '<code>FE 53 4D 42</code>', 'SMB2 표시 <code>|FE|SMB</code> (SMBv1은 <code>|FF|SMB</code>)'],
            ['12~15', '<code>6D 00 00 C0</code>', '상태값 (여기서는 <code>STATUS_LOGON_FAILURE</code> = 0xC000006D, 리틀엔디언)'],
            ['16~17', '<code>03 00</code>', '명령 (리틀엔디언): 01 session setup, 03 tree connect, 05 create, 09 write'],
            ['68 →', '…', '명령 본문. WRITE의 파일 데이터는 오프셋 116(4 + 112)에서 시작']
          ]) +
          `<p>SMB 룰 대부분은 두 가지 사실만 알면 이해됩니다.</p>` +
          `<p><strong>이름은 UTF-16LE입니다.</strong> Windows는 <code>ADMIN$</code>를 <code>A 00 D 00 M 00 I 00 N 00 $ 00</code>으로 보냅니다. Snort content 문자열로는 <code>"A|00|D|00|M|00|I|00|N|00|$|00|"</code>입니다. 그냥 <code>content:"ADMIN$"</code>라고 쓰면 절대 맞지 않습니다.</p>` +
          `<p><strong>숫자는 리틀엔디언입니다.</strong> 명령 3은 <code>00 03</code>이 아니라 <code>03 00</code>입니다.</p>` +
          `<p>직접 확인해 보세요. Wireshark에서 <code>t01-smb-psexec.pcap</code>을 열고 <code>smb2.cmd == 3</code> 필터를 건 뒤 Tree Connect Request를 클릭해 아래 바이트 창을 봅니다. TShark로도 됩니다.</p>` +
          c(`tshark -r ~/smb-lab/t01-smb-psexec.pcap -Y "smb2.cmd==3 && smb2.flags.response==0" -T fields -e frame.number -e smb2.tree`) +
          out('ko', `12	\\\\WS031\\ADMIN$
32	\\\\WS031\\IPC$`).replace('Snort 2.9.20', 'TShark 4.2.2')
      }
    },
    {
      id: 's-level1',
      title: {en: 'Step 3: Level 1 rules — protocol, shares, files', ko: '3단계: 1단계 룰 — 프로토콜, 공유, 파일'},
      html: {
        en: `<h3>SMBv1 (sid 1000101)</h3><p>SMBv1 is the protocol that EternalBlue-style exploits target. Modern Windows does not need it, so any SMBv1 negotiation deserves a look.</p>` + c(R.v1) +
          tbl(['Part', 'Meaning'], [
            ['<code>alert tcp any any -&gt; $HOME_NET $SMB_PORTS</code>', 'Header: from anywhere to an internal host on 139 or 445'],
            ['<code>flow:established,to_server</code>', 'Only after the TCP handshake, only client → server'],
            ['<code>content:"|FF|SMB|72|"; offset:4; depth:5;</code>', 'SMBv1 magic followed by command 0x72 (Negotiate), starting exactly at byte 4'],
            ['<code>classtype</code>, <code>sid</code>, <code>rev</code>', 'Category (sets priority), unique ID (1000000+ for your own rules), revision']
          ]) +
          `<h3>Admin shares from the wrong host (sid 1000102–1000103)</h3>` + c(R.admin) +
          `<p>Read it left to right: <code>|FE|SMB</code> at byte 4 (SMB2), command <code>03 00</code> at byte 16 (tree connect), then the share name in UTF-16LE anywhere after that (<code>distance:0</code>). <code>|5C 00|</code> is the backslash, so <code>\\C$</code> does not also match <code>\\ABC$</code>. <code>nocase</code> catches <code>admin$</code> too.</p>` +
          `<h3>Executable copied over SMB (sid 1000104–1000106)</h3>` + c(R.files) +
          tbl(['sid', 'Looks for', 'Why'], [
            ['1000104', 'Command 05 (create) + <code>.exe</code> in UTF-16LE', 'An executable is being created on another computer'],
            ['1000105', 'Command 09 (write) + <code>MZ</code> at byte 116', 'Every Windows program starts with <code>MZ</code>; byte 116 is where WRITE data begins'],
            ['1000106', '<code>PSEXESVC</code> in UTF-16LE anywhere', 'PsExec’s default service and file name']
          ]) +
          `<p>Now test. The commands are explained fully in Step 6; for now just run them:</p>` +
          c(RUN) + out('en', O.psexec) +
          `<p>Seven alerts from one PsExec run. <code>1000106</code> fires three times because <code>PSEXESVC</code> appears three times: in the file name, inside the CreateServiceW request and as the named pipe it opens. Rule <code>1000130</code> comes from Step 4.</p>`,
        ko: `<h3>SMBv1 (sid 1000101)</h3><p>SMBv1은 EternalBlue 같은 익스플로잇이 노리는 프로토콜입니다. 최신 Windows에는 필요 없으므로 SMBv1 협상이 보이면 확인할 가치가 있습니다.</p>` + c(R.v1) +
          tbl(['부분', '뜻'], [
            ['<code>alert tcp any any -&gt; $HOME_NET $SMB_PORTS</code>', '헤더: 어디서든 내부 호스트의 139 또는 445로'],
            ['<code>flow:established,to_server</code>', 'TCP 연결이 맺어진 뒤, 클라이언트 → 서버 방향만'],
            ['<code>content:"|FF|SMB|72|"; offset:4; depth:5;</code>', 'SMBv1 표시 뒤에 명령 0x72(Negotiate)가, 정확히 4번째 바이트부터'],
            ['<code>classtype</code>, <code>sid</code>, <code>rev</code>', '분류(우선순위를 정함), 고유 번호(직접 만든 룰은 1000000 이상), 수정 번호']
          ]) +
          `<h3>관리 호스트가 아닌 곳에서 관리 공유 접근 (sid 1000102~1000103)</h3>` + c(R.admin) +
          `<p>왼쪽부터 읽습니다. 4번째 바이트에 <code>|FE|SMB</code>(SMB2), 16번째 바이트에 명령 <code>03 00</code>(tree connect), 그 뒤 어딘가(<code>distance:0</code>)에 UTF-16LE 공유 이름. <code>|5C 00|</code>은 백슬래시라서 <code>\\C$</code>가 <code>\\ABC$</code>에까지 걸리지 않습니다. <code>nocase</code>는 <code>admin$</code>처럼 소문자로 와도 잡습니다.</p>` +
          `<h3>SMB로 실행 파일 복사 (sid 1000104~1000106)</h3>` + c(R.files) +
          tbl(['sid', '찾는 것', '이유'], [
            ['1000104', '명령 05(create) + UTF-16LE <code>.exe</code>', '다른 컴퓨터에 실행 파일을 만들고 있음'],
            ['1000105', '명령 09(write) + 116번째 바이트의 <code>MZ</code>', '모든 Windows 프로그램은 <code>MZ</code>로 시작하고, WRITE 데이터는 116번째 바이트부터'],
            ['1000106', 'UTF-16LE <code>PSEXESVC</code>', 'PsExec의 기본 서비스·파일 이름']
          ]) +
          `<p>바로 시험해 봅니다. 명령은 6단계에서 자세히 설명하니 지금은 그냥 실행하세요.</p>` +
          c(RUN) + out('ko', O.psexec) +
          `<p>PsExec 한 번에 경보 7개입니다. <code>1000106</code>이 세 번 나오는 이유는 <code>PSEXESVC</code>가 파일 이름, CreateServiceW 요청 안, 열린 네임드 파이프 이름으로 세 번 나타나기 때문입니다. <code>1000130</code>은 4단계의 룰입니다.</p>`
      }
    },
    {
      id: 's-level2',
      title: {en: 'Step 4: Level 2 rules — what was done through the named pipe', ko: '4단계: 2단계 룰 — 네임드 파이프로 무엇을 했나'},
      html: {
        en: `<p>Most remote administration goes through <strong>DCE/RPC over SMB named pipes</strong>. The client opens a pipe on <code>IPC$</code>, sends a <strong>bind</strong> that names the interface (a UUID), then sends <strong>requests</strong> that name the function (an <strong>opnum</strong>). The pipe name alone is weak evidence; the UUID + opnum says exactly what was done.</p>` +
          tbl(['Interface', 'UUID', 'Bytes on the wire (little-endian)', 'Opnum used here'], [
            ['SVCCTL (services)', '367abb81-9844-35f1-ad32-98f038001003', '<code>81 BB 7A 36 44 98 F1 35 AD 32 98 F0 38 00 10 03</code>', '12 CreateServiceW'],
            ['SAMR (accounts)', '12345778-1234-abcd-ef00-0123456789ac', '<code>78 57 34 12 34 12 CD AB EF 00 01 23 45 67 89 AC</code>', '13 EnumerateUsersInDomain'],
            ['SRVSVC (shares)', '4b324fc8-1670-01d3-1278-5a47bf6ee188', '<code>C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88</code>', '15 NetrShareEnum'],
            ['ATSVC (at jobs)', '1ff70682-0a51-30e8-076d-740be8cee98b', '<code>82 06 F7 1F 51 0A E8 30 07 6D 74 0B E8 CE E9 8B</code>', '0 NetrJobAdd'],
            ['ITaskSchedulerService', '86d35949-83c9-4044-b424-db363231fd0c', '<code>49 59 D3 86 C9 83 44 40 B4 24 DB 36 32 31 FD 0C</code>', '1 SchRpcRegisterTask'],
            ['WINREG (registry)', '338cd001-2244-31f1-aaaa-900038001003', '<code>01 D0 8C 33 44 22 F1 31 AA AA 90 00 38 00 10 03</code>', '6 BaseRegCreateKey']
          ], 'wide-table') +
          `<p>The first three parts of a UUID are stored byte-reversed: <code>367abb81</code> becomes <code>81 BB 7A 36</code>, <code>9844</code> becomes <code>44 98</code>. The last two parts stay in order. Note that LSARPC is <code>…89 AB</code> and SAMR is <code>…89 AC</code>: one byte apart.</p>` +
          `<h3>Why not <code>dce_iface</code>?</h3><p>Snort 2 has <code>dce_iface</code> and <code>dce_opnum</code> options. We tried them on these SMB2 PCAPs with dcerpc2 policies WinXP, Win7 and Win2012: <strong>0 alerts</strong>. Snort 2.9’s DCE/RPC inspection does not follow RPC inside SMB2 named pipes, so we match the bytes ourselves. (<code>dce_iface</code> still works for RPC directly over TCP 135 and SMBv1.)</p>` +
          `<h3>Two rules per action, joined by flowbits</h3><p>Step A: a bind rule notices the interface and sets a <strong>flowbit</strong> — a flag stored on this TCP connection. <code>flowbits:noalert</code> keeps it silent.</p>` + c(R.bind) +
          `<p>Step B: a request rule fires only if the flag is set and the opnum matches. <code>|05 00 00 03 10 00 00 00|</code> is the start of a DCE/RPC request (version 5.0, type 0 = request, first+last fragment, little-endian). The opnum sits 14 bytes after that pattern.</p>` + c(R.ops) +
          `<p>Test the reconnaissance and remote-execution PCAPs:</p>` +
          c(`sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-recon.pcap
sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-remote-exec.pcap`) +
          out('en', O.recon + '\n' + O.remote) +
          `<p>The recon PCAP also binds to LSARPC, but no rule watches LSARPC, so it stays silent. That is your choice to make: add rules only for actions that matter to you.</p>` +
          label('Flowbits last for the whole TCP connection. If one connection binds SAMR and later another interface, a later request with opnum 13 for the other interface would still match. Real RPC traffic also uses fragmentation and other flags; treat these rules as hunting leads, then confirm in Wireshark or Zeek <code>dce_rpc.log</code>.'),
        ko: `<p>원격 관리는 대부분 <strong>SMB 네임드 파이프 위의 DCE/RPC</strong>로 이루어집니다. 클라이언트는 <code>IPC$</code>에서 파이프를 열고, 인터페이스(UUID)를 밝히는 <strong>bind</strong>를 보낸 다음, 함수 번호(<strong>opnum</strong>)를 담은 <strong>request</strong>를 보냅니다. 파이프 이름만으로는 증거가 약합니다. UUID와 opnum을 같이 보면 정확히 무엇을 했는지 알 수 있습니다.</p>` +
          tbl(['인터페이스', 'UUID', '네트워크상 바이트 (리틀엔디언)', '여기서 쓰는 opnum'], [
            ['SVCCTL (서비스)', '367abb81-9844-35f1-ad32-98f038001003', '<code>81 BB 7A 36 44 98 F1 35 AD 32 98 F0 38 00 10 03</code>', '12 CreateServiceW'],
            ['SAMR (계정)', '12345778-1234-abcd-ef00-0123456789ac', '<code>78 57 34 12 34 12 CD AB EF 00 01 23 45 67 89 AC</code>', '13 EnumerateUsersInDomain'],
            ['SRVSVC (공유)', '4b324fc8-1670-01d3-1278-5a47bf6ee188', '<code>C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88</code>', '15 NetrShareEnum'],
            ['ATSVC (at 작업)', '1ff70682-0a51-30e8-076d-740be8cee98b', '<code>82 06 F7 1F 51 0A E8 30 07 6D 74 0B E8 CE E9 8B</code>', '0 NetrJobAdd'],
            ['ITaskSchedulerService', '86d35949-83c9-4044-b424-db363231fd0c', '<code>49 59 D3 86 C9 83 44 40 B4 24 DB 36 32 31 FD 0C</code>', '1 SchRpcRegisterTask'],
            ['WINREG (레지스트리)', '338cd001-2244-31f1-aaaa-900038001003', '<code>01 D0 8C 33 44 22 F1 31 AA AA 90 00 38 00 10 03</code>', '6 BaseRegCreateKey']
          ], 'wide-table') +
          `<p>UUID의 앞 세 부분은 바이트 순서가 뒤집혀서 저장됩니다. <code>367abb81</code>은 <code>81 BB 7A 36</code>, <code>9844</code>는 <code>44 98</code>이 됩니다. 뒤의 두 부분은 그대로입니다. LSARPC는 <code>…89 AB</code>, SAMR은 <code>…89 AC</code>로 딱 한 바이트만 다르다는 점도 기억하세요.</p>` +
          `<h3>왜 <code>dce_iface</code>를 쓰지 않나?</h3><p>Snort 2에는 <code>dce_iface</code>, <code>dce_opnum</code> 옵션이 있습니다. 이 SMB2 PCAP에 dcerpc2 정책 WinXP, Win7, Win2012로 각각 시험했지만 <strong>경보가 0개</strong>였습니다. Snort 2.9의 DCE/RPC 검사는 SMB2 네임드 파이프 안의 RPC를 따라가지 못하므로, 바이트를 직접 맞춥니다. (<code>dce_iface</code>는 TCP 135로 바로 오는 RPC와 SMBv1에서는 여전히 동작합니다.)</p>` +
          `<h3>동작 하나에 룰 두 개, flowbits로 연결</h3><p>A단계: bind 룰이 인터페이스를 알아보고 <strong>flowbit</strong>을 켭니다. flowbit은 이 TCP 연결에 붙는 표시입니다. <code>flowbits:noalert</code>가 있어서 경보는 내지 않습니다.</p>` + c(R.bind) +
          `<p>B단계: request 룰은 표시가 켜져 있고 opnum이 맞을 때만 경보를 냅니다. <code>|05 00 00 03 10 00 00 00|</code>는 DCE/RPC request의 시작입니다(버전 5.0, 종류 0 = request, 첫·마지막 조각, 리틀엔디언). opnum은 그 패턴에서 14바이트 뒤에 있습니다.</p>` + c(R.ops) +
          `<p>정보 수집 PCAP과 원격 실행 PCAP으로 시험합니다.</p>` +
          c(`sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-recon.pcap
sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-remote-exec.pcap`) +
          out('ko', O.recon + '\n' + O.remote) +
          `<p>정보 수집 PCAP은 LSARPC에도 bind하지만, LSARPC를 보는 룰이 없어서 조용합니다. 이것은 여러분이 정할 일입니다. 중요한 동작에만 룰을 추가하세요.</p>` +
          label('flowbit은 TCP 연결이 끝날 때까지 유지됩니다. 한 연결에서 SAMR에 bind한 뒤 다른 인터페이스에 bind하면, 나중의 opnum 13 요청이 다른 인터페이스 것이어도 걸릴 수 있습니다. 실제 RPC는 조각 나누기와 다른 플래그도 씁니다. 이 룰은 헌팅 단서로 쓰고, Wireshark나 Zeek <code>dce_rpc.log</code>로 확인하세요.')
      }
    },
    {
      id: 's-level3',
      title: {en: 'Step 5: Level 3 rule — password guessing over time', ko: '5단계: 3단계 룰 — 시간에 따른 비밀번호 추측'},
      html: {
        en: `<p>One failed logon is normal. Many in a short time from one host is guessing or password spraying. The server’s reply carries status <code>0xC000006D</code> (<code>6D 00 00 C0</code> on the wire) for a Session Setup (command <code>01 00</code>).</p>` + c(R.brute) +
          tbl(['Part', 'Meaning'], [
            ['<code>$HOME_NET $SMB_PORTS -&gt; any any</code>', 'Watch the <strong>server’s reply</strong>, not the request'],
            ['<code>to_client,no_stream</code>', 'Look at each packet once (explained below)'],
            ['<code>content:"|6D 00 00 C0 01 00|"; distance:4; within:6;</code>', 'Skip 4 bytes after <code>|FE|SMB</code>, then status + command'],
            ['<code>detection_filter:track by_dst, count 5, seconds 60;</code>', 'Alert only after more than 5 matches for the same destination (the guessing host) within 60 seconds']
          ]) +
          c(`sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-bruteforce.pcap | wc -l`) +
          `<p>The PCAP has 12 failed logons. With <code>count 5</code> the 6th to 12th failure alert: <strong>7 lines</strong>. Our first version had no <code>no_stream</code> and printed <strong>10</strong> — the first alert came on the 3rd failure. Snort also checks its reassembled stream, so each reply was counted twice. <code>no_stream</code> makes the count honest.</p>` + out('en', O.brute),
        ko: `<p>로그온 실패 한 번은 흔한 일입니다. 짧은 시간에 한 호스트에서 여러 번 실패하면 비밀번호 추측이나 패스워드 스프레이입니다. Session Setup(명령 <code>01 00</code>)에 대한 서버 응답에 상태 <code>0xC000006D</code>(네트워크상 <code>6D 00 00 C0</code>)가 들어 있습니다.</p>` + c(R.brute) +
          tbl(['부분', '뜻'], [
            ['<code>$HOME_NET $SMB_PORTS -&gt; any any</code>', '요청이 아니라 <strong>서버의 응답</strong>을 봄'],
            ['<code>to_client,no_stream</code>', '각 패킷을 한 번만 검사 (아래 설명)'],
            ['<code>content:"|6D 00 00 C0 01 00|"; distance:4; within:6;</code>', '<code>|FE|SMB</code> 뒤 4바이트를 건너뛰고 상태값 + 명령'],
            ['<code>detection_filter:track by_dst, count 5, seconds 60;</code>', '같은 목적지(추측하는 호스트)에 대해 60초 안에 5번을 넘겨야 경보']
          ]) +
          c(`sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-bruteforce.pcap | wc -l`) +
          `<p>이 PCAP에는 로그온 실패가 12번 있습니다. <code>count 5</code>이면 6번째부터 12번째 실패까지 경보가 나므로 <strong>7줄</strong>입니다. 처음 만든 룰에는 <code>no_stream</code>이 없었고, 그때는 <strong>10줄</strong>이 나왔습니다. 첫 경보가 3번째 실패에서 나온 것입니다. Snort가 재조립한 스트림도 한 번 더 검사해서 응답 하나를 두 번 센 것입니다. <code>no_stream</code>을 넣어야 정확히 셉니다.</p>` + out('ko', O.brute)
      }
    },
    {
      id: 's-test',
      title: {en: 'Step 6: test every rule, then check for false positives', ko: '6단계: 모든 룰 시험과 오탐 확인'},
      html: {
        en: `<p>Copy the finished rules into place, validate, then run each PCAP:</p>` +
          c(`sudo cp ~/smb-lab/t01-smb-local.rules /etc/snort/rules/local.rules
sudo snort -T -q -c /etc/snort/snort.conf && echo CONFIG OK
for f in ~/smb-lab/t01-*.pcap; do
  echo "== $f"
  sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r "$f"
done`) +
          tbl(['Option', 'Meaning'], [
            ['<code>-q</code>', 'Quiet: no banner or statistics'],
            ['<code>-U</code>', 'Print times in UTC. Without it Snort uses your computer’s time zone'],
            ['<code>-k none</code>', 'Do not drop packets with bad checksums. <strong>Always use it with PCAP files</strong>'],
            ['<code>-A console</code>', 'Print alerts on screen'],
            ['<code>-c FILE</code>', 'Configuration file'],
            ['<code>-r FILE</code>', 'Read a PCAP instead of a live interface']
          ]) +
          `<h3>Expected results</h3>` +
          tbl(['PCAP', 'Alerts', 'sids'], [
            ['<code>t01-smb-benign.pcap</code>', '0', '—'],
            ['<code>t01-smb-psexec.pcap</code>', '7', '1000102, 1000104, 1000105, 1000106 ×3, 1000130'],
            ['<code>t01-smb-recon.pcap</code>', '2', '1000131, 1000132'],
            ['<code>t01-smb-remote-exec.pcap</code>', '3', '1000133, 1000134, 1000135'],
            ['<code>t01-smb-bruteforce.pcap</code>', '7', '1000140'],
            ['<code>t01-smbv1.pcap</code>', '1', '1000101']
          ]) +
          `<h3>The benign PCAP is the most important test</h3><p><code>t01-smb-benign.pcap</code> holds a user reading <code>\\\\FS01\\Shared\\Reports\\Q3-summary.xlsx</code> and the jump host 10.50.0.5 reading a log from <code>\\\\WS031\\C$</code>. Zero alerts means your rules ignore normal work. To see why <code>ADMIN_HOSTS</code> matters, temporarily set <code>ipvar ADMIN_HOSTS [10.50.0.250]</code> and run it again:</p>` +
          out('en', O.benignNoAdmin) +
          `<p>Put <code>10.50.0.5</code> back afterwards.</p>` +
          `<h3>Save alerts to a file</h3>` +
          c(`mkdir -p ~/smb-lab/log
sudo snort -q -U -k none -A fast -l ~/smb-lab/log -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-recon.pcap
cat ~/smb-lab/log/alert`) +
          `<p><code>-A fast</code> writes one line per alert to <code>alert</code> in the <code>-l</code> folder; the folder also receives a <code>snort.log.*</code> PCAP of the alerting packets.</p>`,
        ko: `<p>완성된 룰을 넣고, 검사하고, PCAP을 하나씩 돌립니다.</p>` +
          c(`sudo cp ~/smb-lab/t01-smb-local.rules /etc/snort/rules/local.rules
sudo snort -T -q -c /etc/snort/snort.conf && echo CONFIG OK
for f in ~/smb-lab/t01-*.pcap; do
  echo "== $f"
  sudo snort -q -U -k none -A console -c /etc/snort/snort.conf -r "$f"
done`) +
          tbl(['옵션', '뜻'], [
            ['<code>-q</code>', '조용히: 배너와 통계를 출력하지 않음'],
            ['<code>-U</code>', '시각을 UTC로 출력. 없으면 컴퓨터의 시간대를 씀'],
            ['<code>-k none</code>', '체크섬이 틀린 패킷도 버리지 않음. <strong>PCAP 파일에는 항상 넣으세요</strong>'],
            ['<code>-A console</code>', '경보를 화면에 출력'],
            ['<code>-c FILE</code>', '설정 파일'],
            ['<code>-r FILE</code>', '실시간 인터페이스 대신 PCAP 읽기']
          ]) +
          `<h3>예상 결과</h3>` +
          tbl(['PCAP', '경보 수', 'sid'], [
            ['<code>t01-smb-benign.pcap</code>', '0', '—'],
            ['<code>t01-smb-psexec.pcap</code>', '7', '1000102, 1000104, 1000105, 1000106 ×3, 1000130'],
            ['<code>t01-smb-recon.pcap</code>', '2', '1000131, 1000132'],
            ['<code>t01-smb-remote-exec.pcap</code>', '3', '1000133, 1000134, 1000135'],
            ['<code>t01-smb-bruteforce.pcap</code>', '7', '1000140'],
            ['<code>t01-smbv1.pcap</code>', '1', '1000101']
          ]) +
          `<h3>정상 PCAP이 가장 중요한 시험입니다</h3><p><code>t01-smb-benign.pcap</code>에는 사용자가 <code>\\\\FS01\\Shared\\Reports\\Q3-summary.xlsx</code>를 읽는 것과, 점프 호스트 10.50.0.5가 <code>\\\\WS031\\C$</code>에서 로그를 읽는 것이 들어 있습니다. 경보 0개는 룰이 정상 업무를 무시한다는 뜻입니다. <code>ADMIN_HOSTS</code>가 왜 중요한지 보려면 잠깐 <code>ipvar ADMIN_HOSTS [10.50.0.250]</code>으로 바꾸고 다시 돌려 보세요.</p>` +
          out('ko', O.benignNoAdmin) +
          `<p>확인한 뒤에는 <code>10.50.0.5</code>로 되돌리세요.</p>` +
          `<h3>경보를 파일로 저장</h3>` +
          c(`mkdir -p ~/smb-lab/log
sudo snort -q -U -k none -A fast -l ~/smb-lab/log -c /etc/snort/snort.conf -r ~/smb-lab/t01-smb-recon.pcap
cat ~/smb-lab/log/alert`) +
          `<p><code>-A fast</code>는 <code>-l</code> 폴더의 <code>alert</code> 파일에 경보를 한 줄씩 씁니다. 같은 폴더에 경보 패킷만 모은 <code>snort.log.*</code> PCAP도 생깁니다.</p>`
      }
    },
    {
      id: 's-mistakes',
      title: {en: 'Common mistakes (all met while building this page)', ko: '자주 하는 실수 (이 페이지를 만들며 실제로 겪은 것)'},
      html: {
        en: tbl(['Symptom', 'Cause', 'Fix'], [
            ['<code>Bad escape sequence starting with "\\|00|R|00|…"</code>', 'A backslash inside <code>content</code> starts an escape', 'Write the backslash as hex: <code>|5C 00|</code>'],
            ['<code>PortVar Lookup failed on \'$SMB_PORTS\'</code>', 'Variable not defined in <code>snort.conf</code>', 'Add <code>portvar SMB_PORTS [139,445]</code>'],
            ['0 alerts on lateral movement', '<code>EXTERNAL_NET !$HOME_NET</code> with a rule source of <code>$EXTERNAL_NET</code>', 'Use <code>any</code> (or <code>$HOME_NET</code>) as the source for internal attacks. We confirmed: such a rule stayed silent on WS066 → FS01 while sid 1000101 fired'],
            ['0 alerts with <code>dce_iface</code>', 'Snort 2 does not inspect RPC inside SMB2 pipes', 'Match bind UUID bytes + opnum with flowbits (Step 4)'],
            ['Too many brute-force alerts', 'Each packet counted twice (packet + stream)', 'Add <code>no_stream</code>'],
            ['0 alerts on a PCAP that should match', 'Bad checksums dropped', 'Add <code>-k none</code>'],
            ['ASCII content never matches', 'SMB names are UTF-16LE', '<code>A|00|D|00|M|00|…</code>']
          ]) + `<p>After every change: raise <code>rev</code>, run <code>snort -T</code>, run all six PCAPs again — including the benign one.</p>`,
        ko: tbl(['증상', '원인', '해결'], [
            ['<code>Bad escape sequence starting with "\\|00|R|00|…"</code>', '<code>content</code> 안의 백슬래시가 이스케이프로 해석됨', '백슬래시를 16진수로: <code>|5C 00|</code>'],
            ['<code>PortVar Lookup failed on \'$SMB_PORTS\'</code>', '<code>snort.conf</code>에 변수가 없음', '<code>portvar SMB_PORTS [139,445]</code> 추가'],
            ['내부 이동에 경보 0개', '<code>EXTERNAL_NET !$HOME_NET</code>인데 룰 출발지가 <code>$EXTERNAL_NET</code>', '내부 공격 룰은 출발지를 <code>any</code>(또는 <code>$HOME_NET</code>)로. 실제로 그런 룰은 WS066 → FS01에서 조용했고 sid 1000101만 탐지됨을 확인'],
            ['<code>dce_iface</code>로 경보 0개', 'Snort 2는 SMB2 파이프 안의 RPC를 검사하지 못함', 'bind UUID 바이트 + opnum을 flowbits로 연결 (4단계)'],
            ['비밀번호 추측 경보가 너무 많음', '패킷과 스트림에서 두 번 셈', '<code>no_stream</code> 추가'],
            ['걸려야 할 PCAP에서 경보 0개', '체크섬 오류로 패킷이 버려짐', '<code>-k none</code> 추가'],
            ['ASCII content가 맞지 않음', 'SMB 이름은 UTF-16LE', '<code>A|00|D|00|M|00|…</code>']
          ]) + `<p>고칠 때마다 <code>rev</code>를 올리고, <code>snort -T</code>를 실행하고, 정상 PCAP을 포함해 여섯 개를 모두 다시 돌리세요.</p>`
      }
    },
    {
      id: 's-final',
      title: {en: 'Final local.rules', ko: '최종 local.rules'},
      html: {
        en: `<p>All 19 rules (6 bind rules are silent helpers). Download: ${dl('t01-smb-local.rules')}.</p>` + c(ALL) +
          `<p>In production, tune before you deploy: list every real admin and backup host in <code>ADMIN_HOSTS</code>, and expect software deployment tools to create services and copy executables too. Related pages: <a href="#fundamentals">Fundamentals</a> (SMB named pipes, UTF-16LE), <a href="#cheatsheet">Cheat sheet</a>, and <a href="#tut-zeek-hunt">Tutorial 02</a> to see the same PsExec activity in Zeek’s SMB logs.</p>`,
        ko: `<p>룰 19개 전체입니다(bind 룰 6개는 경보를 내지 않는 도우미). 내려받기: ${dl('t01-smb-local.rules')}.</p>` + c(ALL) +
          `<p>실무에 적용하기 전에 조정하세요. 실제 관리·백업 호스트를 모두 <code>ADMIN_HOSTS</code>에 넣고, 소프트웨어 배포 도구도 서비스를 만들고 실행 파일을 복사한다는 점을 예상해야 합니다. 관련 페이지: <a href="#fundamentals">기초지식</a>(SMB 네임드 파이프, UTF-16LE), <a href="#cheatsheet">치트시트</a>, 그리고 같은 PsExec 활동을 Zeek의 SMB 로그로 보는 <a href="#tut-zeek-hunt">튜토리얼 02</a>.</p>`
      }
    }
  ];

  const sources = [
    {url: 'https://www.snort.org/documents', title: 'Snort 2.9 manual: content, offset, depth, distance, within, flowbits, detection_filter, no_stream'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/', title: 'Microsoft [MS-SMB2]: SMB 2 and 3 protocol (header layout, commands, status codes)'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/', title: 'Microsoft [MS-RPCE]: Remote Procedure Call protocol extensions (bind, request, opnum)'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/', title: 'Microsoft [MS-SCMR]: Service Control Manager Remote Protocol'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/', title: 'Microsoft [MS-SAMR]: Security Account Manager Remote Protocol'},
    {url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/', title: 'Microsoft [MS-TSCH]: Task Scheduler Service Remoting Protocol'},
    {url: 'https://attack.mitre.org/techniques/T1021/002/', title: 'MITRE ATT&CK T1021.002: SMB/Windows Admin Shares'}
  ];

  return {
    id: 'tut-snort-smb',
    index: 'T01',
    title: {en: 'Snort 2 rules for malicious SMB use', ko: '악의적인 SMB 사용을 잡는 Snort 2 룰'},
    summary: {en: 'Set HOME_NET, EXTERNAL_NET and custom variables, then write and test 19 rules for SMBv1, admin shares, PsExec, RPC recon, remote tasks and password guessing.', ko: 'HOME_NET, EXTERNAL_NET과 사용자 변수를 설정하고, SMBv1, 관리 공유, PsExec, RPC 정보 수집, 원격 작업, 비밀번호 추측을 잡는 룰 19개를 작성하고 시험합니다.'},
    meta: {en: {meta: 'Tutorial 01 / Snort 2.9.20 · TShark', review: 'Tested: 11 November 2026'}, ko: {meta: '튜토리얼 01 / Snort 2.9.20 · TShark', review: '시험일: 2026년 11월 11일'}},
    sections, sources
  };
})();
