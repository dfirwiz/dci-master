DCI Master synthetic packet examples / 자체 제작한 교육용 패킷

Fixed time: 2026-11-01 12:00 UTC. Use this time range in Arkime, not Last hour.
고정 시각을 검색 범위에 포함하세요.

dci-winrm.pcap: 3 SYN packets to 5985, 5986, 443. No replies; this is not a completed connection. Expected 2 matches for dci-local.rules if HOME_NET includes both documentation subnets and the rule loads. This is an expectation, not an executed Snort result.

dci-http-dns.pcap: 12 packets: DNS question/answer and one HTTP connection, training.example, /training, HTTP 200, DCI lab text. No malicious payload. Expected Zeek DNS/HTTP/connection records depend on analyzer configuration. Arkime import requires your own isolated lab.

These files were generated and their packet/IP/TCP/UDP checksums checked. Snort, Zeek and Arkime were not run on them on this Windows host. See manifest.json for hashes.
실제 사고 자료가 아니며, 이 Windows 컴퓨터에서 세 도구를 실행한 결과도 아닙니다.

Added 10 November 2026 / 2026년 11월 10일 추가
dci-smb-samr.pcap: 8 packets. SMB2 session in which 192.0.2.25 opens the \samr named pipe on 198.51.100.10:445 (Create Request = packet 4). Use with dci-snort2-local.rules.
dci-smb-samr-badsum.pcap: the same session with a deliberately wrong TCP checksum on packet 4, to show why -k none matters.
dci-tcp-flags.pcap: 19 packets for the Fundamentals page: handshake, data, FIN close, RST from a closed port, half-open SYN scan, NULL, FIN, Xmas and SYN+FIN. Use with dci-tcp-flags.rules.
These three files WERE run on 10 November 2026 with Snort 2.9.20 (Ubuntu 24.04 package), tcpdump and TShark 4.2.2 on Linux; the outputs on the website are copied from those runs. HOME_NET covered 192.0.2.0/24 and 198.51.100.0/24.
Expected Snort 2.9.20 results: dci-smb-samr.pcap -> 1 alert, sid 1000003 (only with -k none for the badsum file); dci-winrm.pcap -> 2 alerts, sid 1000002; dci-tcp-flags.pcap -> sids 1000010-1000013 once each and 1000014 twice.
위 세 파일은 Linux에서 Snort 2.9.20, tcpdump, TShark 4.2.2로 실제 실행했으며, 웹사이트의 출력은 그 실행 결과입니다.

Added 11 November 2026 / 2026년 11월 11일 추가 (Tutorials 01 and 02)
t01-*.pcap (6 files) and t01-smb-local.rules: Tutorial 01, Snort 2 rules for malicious SMB use. All addresses fictional (10.50.0.0/24). Run with HOME_NET [10.50.0.0/24], EXTERNAL_NET any, portvar SMB_PORTS [139,445], ipvar ADMIN_HOSTS [10.50.0.5]. Outputs on the website come from Snort 2.9.20 (Ubuntu 24.04) runs: benign 0, psexec 7, recon 2, remote-exec 3, bruteforce 7, smbv1 1 alerts.
t02-attacks.pcap: Tutorial 02, hunting common attacks with Zeek. Outputs on the website come from Zeek 8.2.2, zeek-cut and TShark 4.2.2 runs (zeek -C -r t02-attacks.pcap local site.zeek with Site::local_nets 10.50.0.0/24).
실습 PCAP은 모두 가상 데이터이며 실제 캡처가 아닙니다. 웹사이트의 출력은 위 도구로 실제 실행한 결과입니다.
