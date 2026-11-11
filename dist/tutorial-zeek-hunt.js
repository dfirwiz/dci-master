/* Tutorial 02: hunting common attacks in a PCAP with Zeek — a first-run guide for beginners.
   All addresses, hosts, accounts, domains and times are fictional. The practice PCAP was generated for
   this site. Every command output on this page was produced by Zeek 8.2.2, zeek-cut and TShark 4.2.2
   run on that PCAP on 11 November 2026 (outputs are stored verbatim in OUTS below). */
window.DCI_TUTORIAL_ZEEK_HUNT = (() => {
  const OUTS = [{"cmd": "ls", "out": "capture_loss.log\nconn.log\ndce_rpc.log\ndns.log\nfiles.log\nftp.log\nhttp.log\nknown_hosts.log\nknown_services.log\nloaded_scripts.log\nnotice.log\nntlm.log\npacket_filter.log\npe.log\nsite.zeek\nsmb_files.log\nsmb_mapping.log\nsoftware.log\nstats.log\nt02-attacks.pcap\ntelemetry.log"}, {"cmd": "zeek-cut service < conn.log | sort | uniq -c | sort -rn", "out": "    201 -\n     42 dns\n     35 http\n      8 ftp\n      7 ntlm,smb\n      2 ntlm,smb,dce_rpc\n      1 ftp-data"}, {"cmd": "zeek-cut id.orig_h < conn.log | sort | uniq -c | sort -rn", "out": "    226 203.0.113.45\n     68 10.50.0.31\n      2 10.50.0.45"}, {"cmd": "zeek-cut -u ts note msg < notice.log", "out": "2026-11-04T02:03:00+0000\tCaptureLoss::Too_Little_Traffic\tOnly observed 0 TCP ACKs and was expecting at least 1."}, {"cmd": "zeek-cut id.orig_h id.resp_h conn_state < conn.log | sort | uniq -c | sort -rn | head -5", "out": "    197 203.0.113.45\t10.50.0.80\tREJ\n     50 10.50.0.31\t10.50.0.10\tSF\n     26 203.0.113.45\t10.50.0.80\tSF\n     17 10.50.0.31\t198.51.100.77\tSF\n      3 203.0.113.45\t10.50.0.80\tRSTO"}, {"cmd": "zeek-cut id.orig_h id.resp_p < conn.log | awk '$1==\"203.0.113.45\"' | sort -u | wc -l", "out": "201"}, {"cmd": "zeek-cut id.orig_h id.resp_h id.resp_p conn_state history < conn.log | awk '$5==\"ShR\"'", "out": "203.0.113.45\t10.50.0.80\t22\tRSTO\tShR\n203.0.113.45\t10.50.0.80\t80\tRSTO\tShR\n203.0.113.45\t10.50.0.80\t21\tRSTO\tShR"}, {"cmd": "zeek-cut user_agent < http.log | sort | uniq -c | sort -rn", "out": "     16 Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n      7 Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)\n      6 curl/8.5.0\n      4 sqlmap/1.8.11#stable (https://sqlmap.org)\n      2 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"}, {"cmd": "zeek-cut id.orig_h uri status_code < http.log | grep -iE \"union|select|sleep|'|\\.\\./|;|cmd=\"", "out": "203.0.113.45\t/products.php?id=1'\t500\n203.0.113.45\t/products.php?id=1' OR '1'='1\t200\n203.0.113.45\t/products.php?id=1 UNION ALL SELECT NULL,username,password FROM users-- -\t200\n203.0.113.45\t/products.php?id=1 AND SLEEP(5)\t200\n203.0.113.45\t/download.php?file=../../../../etc/passwd\t200\n203.0.113.45\t/tools/ping.php?host=127.0.0.1;id\t200\n203.0.113.45\t/uploads/shell.php?cmd=whoami\t200\n203.0.113.45\t/uploads/shell.php?cmd=uname -a\t200\n203.0.113.45\t/uploads/shell.php?cmd=cat /var/www/config.php\t200"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h source mime_type filename seen_bytes < files.log | grep -v text/plain", "out": "2026-11-04T02:03:35+0000\t203.0.113.45\t10.50.0.80\tHTTP\ttext/x-php\tshell.php\t31\n2026-11-04T02:03:43+0000\t203.0.113.45\t10.50.0.80\tHTTP\t-\t-\t9\n2026-11-04T02:03:51+0000\t203.0.113.45\t10.50.0.80\tHTTP\ttext/x-php\t-\t35\n2026-11-04T02:10:07+0000\t203.0.113.45\t10.50.0.80\tFTP_DATA\tapplication/x-gzip\t-\t65536\n2026-11-04T02:19:07+0000\t10.50.0.45\t10.50.0.90\tHTTP\ttext/html\t-\t29\n2026-11-04T02:28:57+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:29:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:30:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:31:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:32:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:33:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:34:56+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:35:57+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:36:58+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:37:57+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:38:57+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:39:58+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:40:58+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:41:59+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:42:59+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t15\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\tSMB\tapplication/x-dosexec\tPSEXESVC.exe\t6000\n2026-11-04T02:56:32+0000\t10.50.0.31\t198.51.100.77\tHTTP\t-\t-\t900000\n2026-11-04T02:56:32+0000\t10.50.0.31\t198.51.100.77\tHTTP\ttext/json\t-\t19"}, {"cmd": "zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | awk '$4==\"ftp\"' | sort | uniq -c", "out": "      8 203.0.113.45\t10.50.0.80\t21\tftp"}, {"cmd": "zeek-cut -u ts user password command arg reply_code < ftp.log", "out": "2026-11-04T02:10:07+0000\tftpadmin\t<hidden>\tPASV\t-\t227\n2026-11-04T02:10:07+0000\tftpadmin\t<hidden>\tRETR\tftp://10.50.0.80/./db-backup.sql.gz\t226"}, {"cmd": "tshark -r t02-attacks.pcap -Y 'ftp.request.command == \"PASS\"' -T fields -e ip.src -e ftp.request.arg", "out": "203.0.113.45\t123456\n203.0.113.45\tpassword\n203.0.113.45\tadmin\n203.0.113.45\tftp123\n203.0.113.45\tletmein\n203.0.113.45\tWelcome1\n203.0.113.45\tqwerty\n203.0.113.45\tShop2026!"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h uri status_code username password < http.log | awk '$3==\"10.50.0.90\"'", "out": "2026-11-04T02:19:07+0000\t10.50.0.45\t10.50.0.90\t/admin/settings.html\t401\t-\t-\n2026-11-04T02:19:07+0000\t10.50.0.45\t10.50.0.90\t/admin/settings.html\t200\tadmin\t-"}, {"cmd": "tshark -r t02-attacks.pcap -Y http.authorization -T fields -e ip.src -e http.authbasic", "out": "10.50.0.45\tadmin:Printer123"}, {"cmd": "zeek-cut query answers < dns.log | grep -v '\\.t\\.cdn-sync'", "out": "portal.lab.example\t10.50.0.15\nupdates.cdn-sync.example\t198.51.100.77"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h host uri < http.log | grep 'api/v2' | head -3", "out": "2026-11-04T02:28:57+0000\t10.50.0.31\t198.51.100.77\tupdates.cdn-sync.example\t/api/v2/status?id=WS031-7f3a\n2026-11-04T02:29:56+0000\t10.50.0.31\t198.51.100.77\tupdates.cdn-sync.example\t/api/v2/status?id=WS031-7f3a\n2026-11-04T02:30:56+0000\t10.50.0.31\t198.51.100.77\tupdates.cdn-sync.example\t/api/v2/status?id=WS031-7f3a"}, {"cmd": "zeek-cut ts uri < http.log | awk '$2 ~ /api\\/v2/ { if (p) printf \"%.1f\\n\", $1-p; p=$1 }'", "out": "59.3\n59.2\n60.4\n60.0\n59.9\n59.8\n60.8\n61.2\n59.4\n59.8\n61.5\n59.8\n60.8\n60.3"}, {"cmd": "zeek-cut id.orig_h id.resp_h id.resp_p service conn_state < conn.log | awk '$4==\"-\" && $5==\"SF\"'", "out": "10.50.0.31\t198.51.100.77\t4444\t-\tSF"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes history < conn.log | awk '$4==4444'", "out": "2026-11-04T02:44:01+0000\t10.50.0.31\t198.51.100.77\t4444\t18.759001\t273\t53\tShADadFf"}, {"cmd": "zeek-cut id.orig_h id.resp_h username hostname success < ntlm.log | sort | uniq -c", "out": "      8 10.50.0.31\t10.50.0.10\tsvc_backup\tWS031\t-\n      1 10.50.0.31\t10.50.0.20\tsvc_backup\tWS031\t-"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h path share_type < smb_mapping.log", "out": "2026-11-04T02:48:25+0000\t10.50.0.31\t10.50.0.10\t\\\\\\\\DC01\\\\IPC$\tPIPE\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\t\\\\\\\\FS01\\\\ADMIN$\tDISK\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\t\\\\\\\\FS01\\\\IPC$\tPIPE"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h action name < smb_files.log", "out": "2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\tSMB::FILE_OPEN\tPSEXESVC.exe"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h named_pipe operation < dce_rpc.log", "out": "2026-11-04T02:48:25+0000\t10.50.0.31\t10.50.0.10\t\\\\PIPE\\\\samr\tSamrEnumerateUsersInDomain\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\t\\\\PIPE\\\\svcctl\tOpenSCManagerW\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\t\\\\PIPE\\\\svcctl\tCreateServiceW\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\t\\\\PIPE\\\\svcctl\tStartServiceW"}, {"cmd": "zeek-cut query < dns.log | awk -F. '{print $(NF-1)\".\"$NF}' | sort | uniq -c | sort -rn", "out": "     41 cdn-sync.example\n      1 lab.example"}, {"cmd": "zeek-cut qtype_name < dns.log | sort | uniq -c", "out": "      2 A\n     40 TXT"}, {"cmd": "zeek-cut query < dns.log | awk '{print length($0), $0}' | sort -rn | head -3", "out": "72 zxpgzxaleobekdrub5xdg56gcvcavnj7kohcrhro.q5gurdur.013.t.cdn-sync.example\n72 zqkrovk3rpplo3srpjmyfuop5osrsceqmuzroblp.5hkdg4pe.007.t.cdn-sync.example\n72 yxumtdgxqgnch5y2whvnar7mpzowwc5ysoojanns.pyq7tdeb.009.t.cdn-sync.example"}, {"cmd": "zeek-cut id.orig_h id.resp_h id.resp_p service orig_bytes resp_bytes < conn.log | sort -t$'\\t' -k5,5nr | head -3", "out": "10.50.0.31\t198.51.100.77\t8080\thttp\t900203\t161\n10.50.0.31\t10.50.0.20\t445\tntlm,smb,dce_rpc\t8456\t1896\n10.50.0.31\t10.50.0.10\t445\tntlm,smb,dce_rpc\t1264\t1088"}, {"cmd": "zeek-cut -u ts id.orig_h id.resp_h source mime_type filename seen_bytes < files.log | grep -vE \"text/(plain|json|html)\"", "out": "2026-11-04T02:03:35+0000\t203.0.113.45\t10.50.0.80\tHTTP\ttext/x-php\tshell.php\t31\n2026-11-04T02:03:43+0000\t203.0.113.45\t10.50.0.80\tHTTP\t-\t-\t9\n2026-11-04T02:03:51+0000\t203.0.113.45\t10.50.0.80\tHTTP\ttext/x-php\t-\t35\n2026-11-04T02:10:07+0000\t203.0.113.45\t10.50.0.80\tFTP_DATA\tapplication/x-gzip\t-\t65536\n2026-11-04T02:48:55+0000\t10.50.0.31\t10.50.0.20\tSMB\tapplication/x-dosexec\tPSEXESVC.exe\t6000\n2026-11-04T02:56:32+0000\t10.50.0.31\t198.51.100.77\tHTTP\t-\t-\t900000"}];
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const c = (s) => `<pre><code>${esc(s.replace(/^\n/, ''))}</code></pre>`;
  const label = (s) => `<p class="example-label">${s}</p>`;
  const tbl = (head, rows, cls = 'compact-table') => `<div class="article-table-wrap"><table class="article-table ${cls}"><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((x) => `<td>${x}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  const hdr = {en: 'Real output:', ko: '실제 출력:'};
  /* run(n, lang): show command n and its recorded output */
  const run = (n, lang) => c(OUTS[n].cmd) + `<p class="example-output-label"><strong>${hdr[lang]}</strong></p>` + c(OUTS[n].out || '(no output)');
  const P = 't02-attacks.pcap';
  const dl = `<a href="./assets/labs/${P}" download><code>${P}</code></a>`;

  const hostsEn = tbl(['Address', 'Role'], [['10.50.0.10', 'DC01 — domain controller and DNS server'], ['10.50.0.20', 'FS01 — file server'], ['10.50.0.31', 'WS031 — workstation'], ['10.50.0.45', 'WS045 — workstation'], ['10.50.0.80', 'WEB01 — public web/FTP server (shop.lab.example)'], ['10.50.0.90', 'Printer'], ['203.0.113.45', 'Internet address'], ['198.51.100.77', 'Internet address']]);
  const hostsKo = tbl(['주소', '역할'], [['10.50.0.10', 'DC01 — 도메인 컨트롤러 겸 DNS 서버'], ['10.50.0.20', 'FS01 — 파일 서버'], ['10.50.0.31', 'WS031 — 워크스테이션'], ['10.50.0.45', 'WS045 — 워크스테이션'], ['10.50.0.80', 'WEB01 — 외부 공개 웹/FTP 서버 (shop.lab.example)'], ['10.50.0.90', '프린터'], ['203.0.113.45', '인터넷 주소'], ['198.51.100.77', '인터넷 주소']]);

  const sections = [
    {
      id: 'h-start',
      title: {en: 'Before you start', ko: '시작하기 전에'},
      html: {
        en: label('Fictional scenario: all addresses, names, domains and times are invented. The PCAP was generated for this site; every output below is real output from Zeek 8.2.2 run on it.') +
          `<p>You have just installed Zeek and someone hands you a PCAP: “Something is wrong on our network. What happened?” This guide teaches you to answer that, one attack type at a time. You will not read packets one by one. Zeek turns the PCAP into tidy <strong>log files</strong>, and you ask each log a question.</p>` +
          `<p>Download ${dl} (1.1 MB, 1,946 packets, 4 November 2026 02:00–03:00 UTC). The network:</p>` + hostsEn +
          `<p>Eight hunts follow. Each one has the same shape: <strong>what the attack is → which log shows it → the command → the real output → how to read it</strong>.</p>` +
          tbl(['Hunt', 'Attack', 'Main log'], [
            ['1', 'Port scan', '<code>conn.log</code>'], ['2', 'Web attacks and a web shell', '<code>http.log</code>, <code>files.log</code>'],
            ['3', 'Password guessing and cleartext passwords', '<code>conn.log</code>, <code>ftp.log</code>, <code>http.log</code>'], ['4', 'C2 beaconing', '<code>dns.log</code>, <code>http.log</code>'],
            ['5', 'Reverse shell on an unusual port', '<code>conn.log</code>'], ['6', 'SMB lateral movement (PsExec)', '<code>ntlm.log</code>, <code>smb_*.log</code>, <code>dce_rpc.log</code>'],
            ['7', 'DNS tunnelling', '<code>dns.log</code>'], ['8', 'Large data upload (exfiltration)', '<code>conn.log</code>']
          ]),
        ko: label('가상 시나리오: 모든 주소, 이름, 도메인, 시각은 지어낸 것입니다. PCAP은 이 사이트용으로 만들었고, 아래 출력은 모두 Zeek 8.2.2로 실제 실행한 결과입니다.') +
          `<p>Zeek를 막 설치했는데 누군가 PCAP을 건네며 묻습니다. "네트워크에 뭔가 이상해요. 무슨 일이 있었죠?" 이 가이드는 공격 종류별로 하나씩 그 질문에 답하는 법을 알려줍니다. 패킷을 하나하나 읽지 않습니다. Zeek가 PCAP을 깔끔한 <strong>로그 파일</strong>로 바꿔 주고, 여러분은 로그마다 질문을 던집니다.</p>` +
          `<p>${dl}을 내려받으세요(1.1 MB, 패킷 1,946개, 2026년 11월 4일 02:00~03:00 UTC). 네트워크 구성은 이렇습니다.</p>` + hostsKo +
          `<p>헌팅은 8가지입니다. 모두 같은 순서로 진행합니다. <strong>어떤 공격인가 → 어느 로그에 보이나 → 명령 → 실제 출력 → 읽는 법</strong>.</p>` +
          tbl(['헌팅', '공격', '주로 보는 로그'], [
            ['1', '포트 스캔', '<code>conn.log</code>'], ['2', '웹 공격과 웹셸', '<code>http.log</code>, <code>files.log</code>'],
            ['3', '비밀번호 추측과 평문 비밀번호', '<code>conn.log</code>, <code>ftp.log</code>, <code>http.log</code>'], ['4', 'C2 비콘', '<code>dns.log</code>, <code>http.log</code>'],
            ['5', '특이한 포트의 리버스 셸', '<code>conn.log</code>'], ['6', 'SMB 횡적 이동 (PsExec)', '<code>ntlm.log</code>, <code>smb_*.log</code>, <code>dce_rpc.log</code>'],
            ['7', 'DNS 터널링', '<code>dns.log</code>'], ['8', '대용량 업로드 (데이터 유출)', '<code>conn.log</code>']
          ])
      }
    },
    {
      id: 'h-run',
      title: {en: 'Step 1: check Zeek and run it on the PCAP', ko: '1단계: Zeek 확인과 PCAP 실행'},
      html: {
        en: c(`zeek --version`) + `<p>You should see a version such as <code>zeek version 8.2.2</code>. If you get <code>command not found</code>, Zeek is installed but not on your PATH. Packages put it in <code>/opt/zeek/bin</code>:</p>` +
          c(`export PATH=$PATH:/opt/zeek/bin
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc`) +
          `<p>The first line fixes this terminal; the second makes it permanent for new terminals.</p>` +
          `<h3>Make a working folder</h3><p>Zeek writes its logs into the <strong>current folder</strong>, so always start in an empty one.</p>` +
          c(`mkdir ~/zeek-hunt
cd ~/zeek-hunt
cp ~/Downloads/t02-attacks.pcap .`) +
          `<h3>Tell Zeek which network is yours</h3><p>When Zeek reads a PCAP it does not know which addresses are internal. Some logs (<code>software.log</code>, <code>known_hosts.log</code>) and the <code>local_orig</code>/<code>local_resp</code> columns depend on it. Write one line into a file:</p>` +
          c(`echo 'redef Site::local_nets += { 10.50.0.0/24 };' > site.zeek`) +
          `<p><code>redef</code> changes a setting, <code>Site::local_nets</code> is the list of internal networks, <code>+=</code> adds to it. Keep the final semicolon.</p>` +
          `<h3>Run Zeek</h3>` + c(`zeek -C -r t02-attacks.pcap local site.zeek`) +
          tbl(['Part', 'Meaning'], [
            ['<code>-r t02-attacks.pcap</code>', '<strong>R</strong>ead this file instead of a live network card'],
            ['<code>-C</code>', 'Ignore bad checksums. Captured files often have them; without <code>-C</code> Zeek may drop packets and logs look empty'],
            ['<code>local</code>', 'Load Zeek’s recommended extra scripts: file hashes, <code>software.log</code>, <code>known_*.log</code> and more'],
            ['<code>site.zeek</code>', 'Load the file you just wrote']
          ]) + `<p>On success Zeek prints nothing. Look at what it made:</p>` + run(0, 'en') +
          `<p>Each file answers a different question. <code>loaded_scripts.log</code>, <code>packet_filter.log</code>, <code>stats.log</code>, <code>telemetry.log</code> and <code>capture_loss.log</code> describe Zeek itself; the rest describe the traffic.</p>`,
        ko: c(`zeek --version`) + `<p><code>zeek version 8.2.2</code> 같은 버전이 나와야 합니다. <code>command not found</code>가 나오면 Zeek는 설치됐지만 PATH에 없는 것입니다. 패키지는 보통 <code>/opt/zeek/bin</code>에 설치됩니다.</p>` +
          c(`export PATH=$PATH:/opt/zeek/bin
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc`) +
          `<p>첫 줄은 지금 터미널에만 적용되고, 둘째 줄은 앞으로 여는 터미널에도 계속 적용되게 합니다.</p>` +
          `<h3>작업 폴더 만들기</h3><p>Zeek는 로그를 <strong>현재 폴더</strong>에 만듭니다. 항상 빈 폴더에서 시작하세요.</p>` +
          c(`mkdir ~/zeek-hunt
cd ~/zeek-hunt
cp ~/Downloads/t02-attacks.pcap .`) +
          `<h3>내부망 알려주기</h3><p>PCAP을 읽을 때 Zeek는 어떤 주소가 내부인지 모릅니다. 일부 로그(<code>software.log</code>, <code>known_hosts.log</code>)와 <code>local_orig</code>/<code>local_resp</code> 칸이 이 정보에 따라 달라집니다. 파일에 한 줄을 적습니다.</p>` +
          c(`echo 'redef Site::local_nets += { 10.50.0.0/24 };' > site.zeek`) +
          `<p><code>redef</code>는 설정을 바꾸고, <code>Site::local_nets</code>는 내부망 목록이며, <code>+=</code>는 목록에 추가하라는 뜻입니다. 끝의 세미콜론을 빠뜨리지 마세요.</p>` +
          `<h3>Zeek 실행</h3>` + c(`zeek -C -r t02-attacks.pcap local site.zeek`) +
          tbl(['부분', '뜻'], [
            ['<code>-r t02-attacks.pcap</code>', '네트워크 카드 대신 이 파일을 <strong>읽기(r</strong>ead)'],
            ['<code>-C</code>', '체크섬 오류 무시. 캡처 파일에는 흔히 있고, <code>-C</code>가 없으면 패킷이 버려져 로그가 비어 보일 수 있음'],
            ['<code>local</code>', 'Zeek 추천 추가 스크립트: 파일 해시, <code>software.log</code>, <code>known_*.log</code> 등'],
            ['<code>site.zeek</code>', '방금 만든 파일 불러오기']
          ]) + `<p>성공하면 아무것도 출력하지 않습니다. 무엇이 만들어졌는지 봅니다.</p>` + run(0, 'ko') +
          `<p>파일마다 답하는 질문이 다릅니다. <code>loaded_scripts.log</code>, <code>packet_filter.log</code>, <code>stats.log</code>, <code>telemetry.log</code>, <code>capture_loss.log</code>는 Zeek 자신에 대한 기록이고, 나머지가 트래픽에 대한 기록입니다.</p>`
      }
    },
    {
      id: 'h-read',
      title: {en: 'Step 2: read logs with zeek-cut, then take a first look', ko: '2단계: zeek-cut으로 로그 읽기와 첫 훑어보기'},
      html: {
        en: `<p>Each log is a tab-separated table. Lines starting with <code>#</code> are headers; <code>#fields</code> names the columns. <code>zeek-cut</code> prints only the columns you name:</p>` +
          tbl(['You type', 'Meaning'], [
            ['<code>zeek-cut a b c &lt; x.log</code>', 'Print columns a, b, c of x.log'],
            ['<code>zeek-cut -u ts …</code>', 'Show the time column <code>ts</code> as a readable UTC date'],
            ['<code>| sort | uniq -c | sort -rn</code>', 'Count identical lines, biggest first. You will use this constantly'],
            ['<code>| awk \'$3=="x"\'</code>', 'Keep lines whose 3rd printed column equals x'],
            ['<code>| grep -iE "a|b"</code>', 'Keep lines containing a or b, ignoring case'],
            ['<code>| head -5</code>, <code>| wc -l</code>', 'First 5 lines; count lines']
          ]) +
          `<p>Column names you will meet everywhere: <code>id.orig_h</code> = host that <strong>started</strong> the connection, <code>id.resp_h</code> = host that <strong>answered</strong>, <code>_p</code> = port, <code>uid</code> = connection ID shared by every log about the same connection.</p>` +
          `<h3>First look: what protocols, and who talks most?</h3>` + run(1, 'en') +
          `<p><code>service</code> is the protocol Zeek <em>recognised from the content</em>, not guessed from the port. <code>-</code> means Zeek could not identify it: 201 such connections is a lot.</p>` + run(2, 'en') +
          `<p>One internet address started 226 connections. That is the first lead.</p>` + run(3, 'en') +
          `<p><code>notice.log</code> holds Zeek’s own warnings. This one is about capture quality, not an attack; with PCAP files it can be ignored. Zeek’s default notices rarely flag attacks by themselves — the hunting is your job.</p>`,
        ko: `<p>로그는 탭으로 나뉜 표입니다. <code>#</code>으로 시작하는 줄은 헤더이고, <code>#fields</code> 줄이 칸 이름입니다. <code>zeek-cut</code>은 적은 칸만 출력합니다.</p>` +
          tbl(['입력', '뜻'], [
            ['<code>zeek-cut a b c &lt; x.log</code>', 'x.log의 a, b, c 칸 출력'],
            ['<code>zeek-cut -u ts …</code>', '시간 칸 <code>ts</code>를 읽기 쉬운 UTC 날짜로'],
            ['<code>| sort | uniq -c | sort -rn</code>', '같은 줄을 세서 많은 순으로. 계속 쓰게 됩니다'],
            ['<code>| awk \'$3=="x"\'</code>', '출력한 3번째 칸이 x인 줄만'],
            ['<code>| grep -iE "a|b"</code>', '대소문자 상관없이 a 또는 b가 들어간 줄만'],
            ['<code>| head -5</code>, <code>| wc -l</code>', '앞 5줄; 줄 수 세기']
          ]) +
          `<p>어디서나 만나는 칸 이름: <code>id.orig_h</code> = 연결을 <strong>시작한</strong> 호스트, <code>id.resp_h</code> = <strong>응답한</strong> 호스트, <code>_p</code> = 포트, <code>uid</code> = 같은 연결에 대한 모든 로그가 공유하는 연결 ID.</p>` +
          `<h3>첫 훑어보기: 어떤 프로토콜이 있고 누가 가장 많이 통신하나?</h3>` + run(1, 'ko') +
          `<p><code>service</code>는 Zeek가 포트로 짐작한 것이 아니라 <em>내용을 보고 알아낸</em> 프로토콜입니다. <code>-</code>는 알아내지 못했다는 뜻인데, 201개는 많은 편입니다.</p>` + run(2, 'ko') +
          `<p>인터넷 주소 하나가 연결을 226개나 시작했습니다. 첫 단서입니다.</p>` + run(3, 'ko') +
          `<p><code>notice.log</code>는 Zeek 자신의 경고입니다. 이것은 캡처 품질에 대한 것이지 공격이 아니며, PCAP 파일에서는 무시해도 됩니다. Zeek의 기본 notice는 공격을 스스로 알려주는 경우가 드뭅니다. 찾는 것은 여러분의 몫입니다.</p>`
      }
    },
    {
      id: 'h-scan',
      title: {en: 'Hunt 1: port scan (conn.log)', ko: '헌팅 1: 포트 스캔 (conn.log)'},
      html: {
        en: `<p>A scanner knocks on many ports to see which ones answer. Closed ports reply with RST; Zeek records those connections as <code>REJ</code>.</p>` + run(4, 'en') + run(5, 'en') +
          `<p>197 rejected connections from 203.0.113.45 to WEB01, and 201 different destination ports (200 scanned ports plus the FTP data port used later). Which ports were open?</p>` + run(6, 'en') +
          tbl(['conn_state', 'Meaning'], [['<code>SF</code>', 'Normal: opened and closed properly'], ['<code>REJ</code>', 'SYN answered with RST: port closed'], ['<code>S0</code>', 'SYN with no answer: filtered or host down'], ['<code>RSTO</code>', 'Connection reset by the originator']]) +
          `<p><code>history</code> spells out what happened: <code>S</code> = SYN, <code>h</code> = SYN-ACK, <code>R</code> = RST from the originator. <code>ShR</code> means the server said “open” and the scanner immediately hung up: a <strong>half-open (SYN) scan</strong>. Ports 21, 22 and 80 are open on WEB01.</p>`,
        ko: `<p>스캐너는 여러 포트를 두드려 어느 것이 응답하는지 봅니다. 닫힌 포트는 RST로 답하고, Zeek는 그런 연결을 <code>REJ</code>로 기록합니다.</p>` + run(4, 'ko') + run(5, 'ko') +
          `<p>203.0.113.45에서 WEB01로 거부된 연결이 197개, 목적지 포트는 201종류입니다(스캔한 포트 200개 + 나중에 쓴 FTP 데이터 포트 1개). 어떤 포트가 열려 있었을까요?</p>` + run(6, 'ko') +
          tbl(['conn_state', '뜻'], [['<code>SF</code>', '정상: 제대로 열리고 닫힘'], ['<code>REJ</code>', 'SYN에 RST로 답함: 닫힌 포트'], ['<code>S0</code>', 'SYN에 답이 없음: 필터링되었거나 호스트가 꺼짐'], ['<code>RSTO</code>', '시작한 쪽이 연결을 끊음(RST)']]) +
          `<p><code>history</code>는 일어난 일을 글자로 보여줍니다. <code>S</code> = SYN, <code>h</code> = SYN-ACK, <code>R</code> = 시작한 쪽의 RST. <code>ShR</code>은 서버가 "열렸다"고 답하자 스캐너가 바로 끊었다는 뜻으로, <strong>하프 오픈(SYN) 스캔</strong>입니다. WEB01은 21, 22, 80번이 열려 있습니다.</p>`
      }
    },
    {
      id: 'h-web',
      title: {en: 'Hunt 2: web attacks and a web shell (http.log, files.log)', ko: '헌팅 2: 웹 공격과 웹셸 (http.log, files.log)'},
      html: {
        en: `<p>Attack tools often announce themselves in the User-Agent.</p>` + run(7, 'en') +
          `<p>Nikto (web scanner) and sqlmap (SQL injection tool) are clear. The 16 short <code>Mozilla/5.0 (Windows NT 10.0; Win64; x64)</code> lines are suspicious too: real browsers send a much longer string — keep it for Hunt 4. Now look for attack patterns in the URIs:</p>` + run(8, 'en') +
          tbl(['Pattern', 'Attack'], [['<code>\'</code>, <code>OR \'1\'=\'1</code>, <code>UNION SELECT</code>, <code>SLEEP(5)</code>', 'SQL injection (the <code>500</code> error on <code>id=1\'</code> tells the attacker the page is injectable)'], ['<code>../../../../etc/passwd</code>', 'Path traversal'], ['<code>;id</code>', 'Command injection'], ['<code>shell.php?cmd=</code>', 'Web shell: commands run on the server']]) +
          `<p>Zeek decodes URIs, so <code>%27</code> appears as <code>\'</code>. Where did <code>shell.php</code> come from?</p>` + run(28, 'en') +
          `<p>At 02:03:35 the attacker uploaded <code>shell.php</code> (31 bytes, <code>text/x-php</code>) to WEB01, then used it eight seconds later. The same table already shows later events: a gzip file over FTP, an executable over SMB, and 900,000 bytes sent out over HTTP.</p>`,
        ko: `<p>공격 도구는 User-Agent에 자기 이름을 드러내는 경우가 많습니다.</p>` + run(7, 'ko') +
          `<p>Nikto(웹 스캐너)와 sqlmap(SQL 인젝션 도구)은 분명합니다. 짧은 <code>Mozilla/5.0 (Windows NT 10.0; Win64; x64)</code> 16줄도 수상합니다. 진짜 브라우저는 훨씬 긴 문자열을 보냅니다. 헌팅 4에서 다시 봅니다. 이제 URI에서 공격 패턴을 찾습니다.</p>` + run(8, 'ko') +
          tbl(['패턴', '공격'], [['<code>\'</code>, <code>OR \'1\'=\'1</code>, <code>UNION SELECT</code>, <code>SLEEP(5)</code>', 'SQL 인젝션 (<code>id=1\'</code>의 <code>500</code> 오류가 공격자에게 인젝션이 된다는 걸 알려줌)'], ['<code>../../../../etc/passwd</code>', '경로 조작(path traversal)'], ['<code>;id</code>', '명령 주입'], ['<code>shell.php?cmd=</code>', '웹셸: 서버에서 명령 실행']]) +
          `<p>Zeek는 URI를 풀어서 기록하므로 <code>%27</code>이 <code>\'</code>로 보입니다. <code>shell.php</code>는 어디서 왔을까요?</p>` + run(28, 'ko') +
          `<p>02:03:35에 공격자가 <code>shell.php</code>(31바이트, <code>text/x-php</code>)를 WEB01에 올렸고, 8초 뒤 사용했습니다. 같은 표에 이후 사건도 보입니다. FTP로 받은 gzip 파일, SMB로 옮긴 실행 파일, HTTP로 내보낸 900,000바이트.</p>`
      }
    },
    {
      id: 'h-creds',
      title: {en: 'Hunt 3: password guessing and cleartext passwords', ko: '헌팅 3: 비밀번호 추측과 평문 비밀번호'},
      html: {
        en: run(10, 'en') + `<p>Eight FTP logins from the same address in seconds is guessing. <code>ftp.log</code> shows what happened after the login:</p>` + run(11, 'en') +
          `<p>Zeek logs FTP commands such as <code>RETR</code> (download) but not each failed login, and it hides passwords (<code>&lt;hidden&gt;</code>) by default. The account <code>ftpadmin</code> got in and downloaded <code>db-backup.sql.gz</code>. FTP is cleartext, so anyone on the path can read the passwords — use TShark to prove it:</p>` + run(12, 'en') +
          `<p>Seven wrong guesses, then <code>Shop2026!</code>. The same problem appears inside the network: a printer admin page using HTTP Basic authentication.</p>` + run(13, 'en') + run(14, 'en') +
          `<p>Zeek records the user name <code>admin</code> but not the password; TShark decodes the Base64 header to <code>admin:Printer123</code>. Finding: credentials crossing the network in cleartext.</p>`,
        ko: run(10, 'ko') + `<p>같은 주소에서 몇 초 사이에 FTP 로그인 8번은 비밀번호 추측입니다. 로그인 뒤 무슨 일이 있었는지는 <code>ftp.log</code>에 있습니다.</p>` + run(11, 'ko') +
          `<p>Zeek는 <code>RETR</code>(다운로드) 같은 FTP 명령은 기록하지만 실패한 로그인 하나하나는 남기지 않고, 비밀번호는 기본적으로 숨깁니다(<code>&lt;hidden&gt;</code>). <code>ftpadmin</code> 계정이 들어가 <code>db-backup.sql.gz</code>를 받았습니다. FTP는 평문이라 경로상의 누구나 비밀번호를 볼 수 있습니다. TShark로 확인합니다.</p>` + run(12, 'ko') +
          `<p>7번 틀린 뒤 <code>Shop2026!</code>로 성공했습니다. 같은 문제가 내부에도 있습니다. HTTP Basic 인증을 쓰는 프린터 관리 페이지입니다.</p>` + run(13, 'ko') + run(14, 'ko') +
          `<p>Zeek는 사용자 이름 <code>admin</code>만 기록하고 비밀번호는 기록하지 않습니다. TShark는 Base64 헤더를 풀어 <code>admin:Printer123</code>을 보여줍니다. 발견 사항: 인증 정보가 평문으로 네트워크를 지나감.</p>`
      }
    },
    {
      id: 'h-beacon',
      title: {en: 'Hunt 4: C2 beaconing (dns.log, http.log)', ko: '헌팅 4: C2 비콘 (dns.log, http.log)'},
      html: {
        en: `<p>Malware “checks in” with its command-and-control (C2) server at regular intervals. Start from the names WS031 looked up:</p>` + run(15, 'en') +
          `<p><code>portal.lab.example</code> is internal; <code>updates.cdn-sync.example</code> points to the internet address 198.51.100.77 — the server the short User-Agent talked to.</p>` + run(16, 'en') +
          `<p>Same host, same path, same ID. Now measure the time between requests (<code>awk</code> subtracts each <code>ts</code> from the previous one):</p>` + run(17, 'en') +
          `<p>Every 59–61 seconds, 15 times. People do not click that regularly; software does. Small jitter (±1.5 s) is common in C2 frameworks to look less mechanical.</p>`,
        ko: `<p>악성코드는 명령 서버(C2)에 일정한 간격으로 "보고"합니다. WS031이 조회한 이름부터 봅니다.</p>` + run(15, 'ko') +
          `<p><code>portal.lab.example</code>은 내부이고, <code>updates.cdn-sync.example</code>은 인터넷 주소 198.51.100.77을 가리킵니다. 짧은 User-Agent가 통신한 바로 그 서버입니다.</p>` + run(16, 'ko') +
          `<p>같은 호스트, 같은 경로, 같은 ID입니다. 요청 사이 간격을 재봅니다(<code>awk</code>가 각 <code>ts</code>에서 앞의 <code>ts</code>를 뺍니다).</p>` + run(17, 'ko') +
          `<p>59~61초마다 15번입니다. 사람은 이렇게 규칙적으로 클릭하지 않습니다. 프로그램이 하는 일입니다. ±1.5초 정도의 흔들림(jitter)은 덜 기계적으로 보이려고 C2 도구들이 흔히 넣습니다.</p>`
      }
    },
    {
      id: 'h-shell',
      title: {en: 'Hunt 5: reverse shell on an unusual port (conn.log)', ko: '헌팅 5: 특이한 포트의 리버스 셸 (conn.log)'},
      html: {
        en: `<p>Look for connections that completed normally (<code>SF</code>) but whose protocol Zeek could not recognise (<code>-</code>):</p>` + run(18, 'en') + run(19, 'en') +
          `<p>An internal workstation connected <strong>out</strong> to port 4444 (Metasploit’s default) and kept the session open for 19 seconds with back-and-forth data (<code>ShADadFf</code>: data both ways, then normal close). A reverse shell looks exactly like this: the victim calls the attacker. Note <code>orig_bytes</code> 273 &gt; <code>resp_bytes</code> 53 — the command output (from WS031) is larger than the commands sent to it.</p>`,
        ko: `<p>정상적으로 끝났지만(<code>SF</code>) Zeek가 프로토콜을 알아보지 못한(<code>-</code>) 연결을 찾습니다.</p>` + run(18, 'ko') + run(19, 'ko') +
          `<p>내부 워크스테이션이 4444번 포트(Metasploit 기본값)로 <strong>밖으로</strong> 연결해 19초 동안 데이터를 주고받았습니다(<code>ShADadFf</code>: 양방향 데이터 후 정상 종료). 리버스 셸이 딱 이렇게 생겼습니다. 피해 PC가 공격자에게 전화를 거는 구조입니다. <code>orig_bytes</code> 273이 <code>resp_bytes</code> 53보다 큰 점도 보세요. WS031이 보낸 명령 결과가 받은 명령보다 큽니다.</p>`
      }
    },
    {
      id: 'h-smb',
      title: {en: 'Hunt 6: SMB lateral movement (ntlm, smb_mapping, smb_files, dce_rpc)', ko: '헌팅 6: SMB 횡적 이동 (ntlm, smb_mapping, smb_files, dce_rpc)'},
      html: {
        en: `<p>From WS031 the attacker now moves to other Windows hosts. Zeek splits SMB activity over four logs.</p>` + run(20, 'en') +
          `<p>Eight NTLM logons as <code>svc_backup</code> to the DC within five seconds, then one to FS01. <code>success</code> is <code>-</code> because the server replies in this PCAP carry no SPNEGO result for Zeek to read, so judge by the count and timing: repeated attempts, then a move to a new host.</p>` + run(21, 'en') +
          `<p>Zeek doubles backslashes in logs, so <code>\\\\\\\\FS01\\\\ADMIN$</code> means <code>\\\\FS01\\ADMIN$</code>. A workstation mapping another server’s <code>ADMIN$</code> is admin-level remote access.</p>` + run(22, 'en') + run(23, 'en') +
          `<p>Put together: list users on the DC (<code>SamrEnumerateUsersInDomain</code>), copy <code>PSEXESVC.exe</code> to <code>ADMIN$</code> on FS01, then create and start a service through the <code>svcctl</code> pipe. That is PsExec. <code>files.log</code> (Hunt 2) showed the file as <code>application/x-dosexec</code>, and <code>pe.log</code> holds its executable header details. <a href="#tut-snort-smb">Tutorial 01</a> builds Snort rules for the same activity.</p>`,
        ko: `<p>공격자는 WS031에서 다른 Windows 호스트로 이동합니다. Zeek는 SMB 활동을 네 개의 로그로 나눠 기록합니다.</p>` + run(20, 'ko') +
          `<p><code>svc_backup</code> 계정으로 5초 사이 DC에 NTLM 로그온 8번, 그 뒤 FS01에 1번입니다. <code>success</code>가 <code>-</code>인 이유는 이 PCAP의 서버 응답에 Zeek가 읽을 SPNEGO 결과가 없어서입니다. 그러니 횟수와 시간으로 판단합니다. 반복 시도 후 새 호스트로 이동.</p>` + run(21, 'ko') +
          `<p>Zeek는 로그에서 백슬래시를 두 번 씁니다. <code>\\\\\\\\FS01\\\\ADMIN$</code>는 <code>\\\\FS01\\ADMIN$</code>라는 뜻입니다. 워크스테이션이 다른 서버의 <code>ADMIN$</code>를 연결하면 관리자 수준 원격 접근입니다.</p>` + run(22, 'ko') + run(23, 'ko') +
          `<p>합쳐 보면: DC에서 사용자 목록 조회(<code>SamrEnumerateUsersInDomain</code>), FS01의 <code>ADMIN$</code>에 <code>PSEXESVC.exe</code> 복사, <code>svcctl</code> 파이프로 서비스 생성과 시작. PsExec입니다. 헌팅 2의 <code>files.log</code>에서 이 파일은 <code>application/x-dosexec</code>였고, <code>pe.log</code>에 실행 파일 헤더 정보가 있습니다. 같은 활동을 Snort 룰로 잡는 방법은 <a href="#tut-snort-smb">튜토리얼 01</a>에 있습니다.</p>`
      }
    },
    {
      id: 'h-dns',
      title: {en: 'Hunt 7: DNS tunnelling (dns.log)', ko: '헌팅 7: DNS 터널링 (dns.log)'},
      html: {
        en: `<p>DNS is allowed almost everywhere, so attackers hide data inside query names. Group queries by their last two labels (the registered domain):</p>` + run(24, 'en') + run(25, 'en') + run(26, 'en') +
          `<p>41 queries to one domain, 40 of them <code>TXT</code> (normal browsing is mostly <code>A</code>/<code>AAAA</code>), and names 72 characters long made of random-looking base32 with a counter (<code>.000.</code>, <code>.001.</code> …). Each query carries a chunk of data out to whoever runs <code>cdn-sync.example</code> — the same domain as the C2 in Hunt 4.</p>`,
        ko: `<p>DNS는 거의 어디서나 허용되기 때문에 공격자가 조회 이름 안에 데이터를 숨깁니다. 조회를 마지막 두 단어(등록된 도메인)로 묶어 봅니다.</p>` + run(24, 'ko') + run(25, 'ko') + run(26, 'ko') +
          `<p>한 도메인에 조회 41번, 그중 40번이 <code>TXT</code>(일반 웹 사용은 대부분 <code>A</code>/<code>AAAA</code>)이고, 이름은 72글자의 무작위 같은 base32에 번호(<code>.000.</code>, <code>.001.</code> …)가 붙어 있습니다. 조회 하나하나가 데이터 조각을 <code>cdn-sync.example</code> 운영자에게 실어 보냅니다. 헌팅 4의 C2와 같은 도메인입니다.</p>`
      }
    },
    {
      id: 'h-exfil',
      title: {en: 'Hunt 8: large upload (conn.log)', ko: '헌팅 8: 대용량 업로드 (conn.log)'},
      html: {
        en: `<p>Sort connections by bytes sent by the originator (<code>orig_bytes</code>, the 5th column):</p>` + run(27, 'en') +
          `<p><code>sort -t$'\\t' -k5,5nr</code> means: split on tabs, sort by column 5 as a number, largest first. WS031 sent about 900 KB to the C2 address on port 8080 and received 161 bytes. Workstations normally download far more than they upload; a one-way upload to an address already linked to C2 is likely exfiltration.</p>`,
        ko: `<p>시작한 쪽이 보낸 바이트(<code>orig_bytes</code>, 5번째 칸)로 연결을 정렬합니다.</p>` + run(27, 'ko') +
          `<p><code>sort -t$'\\t' -k5,5nr</code>은 "탭으로 나누고, 5번째 칸을 숫자로, 큰 것부터 정렬"이라는 뜻입니다. WS031이 C2 주소의 8080번으로 약 900 KB를 보내고 161바이트만 받았습니다. 워크스테이션은 보통 올리는 것보다 받는 것이 훨씬 많습니다. 이미 C2와 연결된 주소로 한쪽 방향 업로드가 있으면 데이터 유출일 가능성이 큽니다.</p>`
      }
    },
    {
      id: 'h-summary',
      title: {en: 'Put it together', ko: '전체 정리'},
      html: {
        en: tbl(['Time (UTC)', 'What happened', 'Evidence'], [
            ['02:00', '203.0.113.45 SYN-scans WEB01; 21, 22, 80 open', '<code>conn.log</code> REJ ×197, ShR'],
            ['02:03', 'Nikto, sqlmap, traversal, command injection; <code>shell.php</code> uploaded and used', '<code>http.log</code>, <code>files.log</code>, <code>software.log</code>'],
            ['02:10', 'FTP password guessing, <code>ftpadmin</code> logs in, downloads DB backup', '<code>conn.log</code>, <code>ftp.log</code>, TShark'],
            ['02:19', 'Printer admin password sent in cleartext (internal)', '<code>http.log</code> username, TShark'],
            ['02:28–02:43', 'WS031 beacons every ~60 s to 198.51.100.77', '<code>dns.log</code>, <code>http.log</code>'],
            ['02:44', 'Reverse shell WS031 → 198.51.100.77:4444', '<code>conn.log</code>'],
            ['02:48', '<code>svc_backup</code> logons, SAMR user listing, PsExec to FS01', '<code>ntlm.log</code>, <code>smb_*.log</code>, <code>dce_rpc.log</code>'],
            ['02:52', 'DNS TXT tunnelling to <code>cdn-sync.example</code>', '<code>dns.log</code>'],
            ['02:56', '900 KB upload to 198.51.100.77:8080', '<code>conn.log</code>, <code>files.log</code>']
          ]) +
          `<p>The order matters: every hunt began with a broad count (<code>sort | uniq -c</code>), then narrowed to one host, one domain or one port. Use the <code>uid</code> column to jump between logs about the same connection: <code>grep CONN_UID *.log</code>.</p>` +
          tbl(['Problem', 'Fix'], [['<code>zeek: command not found</code>', '<code>export PATH=$PATH:/opt/zeek/bin</code>'], ['Logs almost empty', 'Add <code>-C</code>'], ['No <code>software.log</code> / <code>known_hosts.log</code>', 'Load <code>local</code> and <code>site.zeek</code> with <code>Site::local_nets</code>'], ['Old and new results mixed', 'Run <code>rm -f *.log</code> before running Zeek again (the PCAP is kept)'], ['Times in the wrong zone', 'Use <code>zeek-cut -u</code> for UTC']]),
        ko: tbl(['시각 (UTC)', '일어난 일', '증거'], [
            ['02:00', '203.0.113.45가 WEB01을 SYN 스캔; 21, 22, 80 열림', '<code>conn.log</code> REJ ×197, ShR'],
            ['02:03', 'Nikto, sqlmap, 경로 조작, 명령 주입; <code>shell.php</code> 업로드 후 사용', '<code>http.log</code>, <code>files.log</code>, <code>software.log</code>'],
            ['02:10', 'FTP 비밀번호 추측, <code>ftpadmin</code> 로그인 후 DB 백업 다운로드', '<code>conn.log</code>, <code>ftp.log</code>, TShark'],
            ['02:19', '프린터 관리자 비밀번호가 평문으로 전송 (내부)', '<code>http.log</code> username, TShark'],
            ['02:28~02:43', 'WS031이 약 60초마다 198.51.100.77에 비콘', '<code>dns.log</code>, <code>http.log</code>'],
            ['02:44', '리버스 셸 WS031 → 198.51.100.77:4444', '<code>conn.log</code>'],
            ['02:48', '<code>svc_backup</code> 로그온, SAMR 사용자 조회, FS01로 PsExec', '<code>ntlm.log</code>, <code>smb_*.log</code>, <code>dce_rpc.log</code>'],
            ['02:52', '<code>cdn-sync.example</code>로 DNS TXT 터널링', '<code>dns.log</code>'],
            ['02:56', '198.51.100.77:8080으로 900 KB 업로드', '<code>conn.log</code>, <code>files.log</code>']
          ]) +
          `<p>순서가 중요합니다. 모든 헌팅은 넓게 세기(<code>sort | uniq -c</code>)로 시작해서 호스트 하나, 도메인 하나, 포트 하나로 좁혀 갔습니다. 같은 연결에 대한 여러 로그를 오갈 때는 <code>uid</code> 칸을 쓰세요: <code>grep 연결UID *.log</code>.</p>` +
          tbl(['문제', '해결'], [['<code>zeek: command not found</code>', '<code>export PATH=$PATH:/opt/zeek/bin</code>'], ['로그가 거의 비어 있음', '<code>-C</code> 추가'], ['<code>software.log</code> / <code>known_hosts.log</code>가 없음', '<code>local</code>과 <code>Site::local_nets</code>가 든 <code>site.zeek</code>를 함께 불러오기'], ['이전 결과와 섞임', 'Zeek를 다시 돌리기 전에 <code>rm -f *.log</code> (PCAP은 남음)'], ['시각이 다른 시간대로 나옴', 'UTC로 보려면 <code>zeek-cut -u</code>']])
      }
    }
  ];

  const sources = [
    {url: 'https://docs.zeek.org/en/current/', title: 'Zeek documentation (installation, running on PCAPs, zeek-cut)'},
    {url: 'https://docs.zeek.org/en/current/logs/index.html', title: 'Zeek log reference: conn, dns, http, files, ftp, ntlm, smb, dce_rpc'},
    {url: 'https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html', title: 'Zeek conn.log: conn_state and history codes'},
    {url: 'https://www.wireshark.org/docs/man-pages/tshark.html', title: 'TShark manual page'},
    {url: 'https://attack.mitre.org/techniques/T1071/004/', title: 'MITRE ATT&CK T1071.004: Application Layer Protocol — DNS'},
    {url: 'https://attack.mitre.org/techniques/T1046/', title: 'MITRE ATT&CK T1046: Network Service Discovery'}
  ];

  return {
    id: 'tut-zeek-hunt',
    index: 'T02',
    title: {en: 'Hunting common attacks in a PCAP with Zeek', ko: 'Zeek로 PCAP에서 흔한 공격 찾기'},
    summary: {en: 'First run of Zeek for beginners: process a PCAP, read logs with zeek-cut, and find a port scan, web attacks, password guessing, beaconing, a reverse shell, PsExec, DNS tunnelling and exfiltration.', ko: '초보자를 위한 Zeek 첫 실행: PCAP 처리, zeek-cut으로 로그 읽기, 그리고 포트 스캔, 웹 공격, 비밀번호 추측, 비콘, 리버스 셸, PsExec, DNS 터널링, 데이터 유출 찾기.'},
    meta: {en: {meta: 'Tutorial 02 / Zeek 8.2.2 · zeek-cut · TShark', review: 'Tested: 11 November 2026'}, ko: {meta: '튜토리얼 02 / Zeek 8.2.2 · zeek-cut · TShark', review: '시험일: 2026년 11월 11일'}},
    sections, sources
  };
})();
