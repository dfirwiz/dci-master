DCI Master synthetic packet examples / 자체 제작한 교육용 패킷

Fixed time: 2026-11-01 12:00 UTC. Use this time range in Arkime, not Last hour.
고정 시각을 검색 범위에 포함하세요.

dci-winrm.pcap: 3 SYN packets to 5985, 5986, 443. No replies; this is not a completed connection. Expected 2 matches for dci-local.rules if HOME_NET includes both documentation subnets and the rule loads. This is an expectation, not an executed Snort result.

dci-http-dns.pcap: 12 packets: DNS question/answer and one HTTP connection, training.example, /training, HTTP 200, DCI lab text. No malicious payload. Expected Zeek DNS/HTTP/connection records depend on analyzer configuration. Arkime import requires your own isolated lab.

These files were generated and their packet/IP/TCP/UDP checksums checked. Snort, Zeek and Arkime were not run on them on this Windows host. See manifest.json for hashes.
실제 사고 자료가 아니며, 이 Windows 컴퓨터에서 세 도구를 실행한 결과도 아닙니다.
