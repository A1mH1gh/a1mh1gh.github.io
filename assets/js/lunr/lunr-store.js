var store = [{
        "title": "[ HTB ] - RedPanda",
        "excerpt":"Java Spring Framework를 사용하는 RedPanda Website에서 사용자 입력값 미검증으로 인해 SSTI가 가능하며, 더나아가 리버스쉘을 통한 RCE까지 가능하다 1. RECONNAISSANCE Gather Victim Network Information nmap -sS -sV 10.10.11.170 Search Open Websites/Domains 1) SSTI DETECTION What is SSTI? https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#methodology { {7*7} } ${7*7} &lt;%= 7*7 %&gt; ${ {7*7} } #{7*7} *{7*7}...","categories": ["HTB_Writeup"],
        "tags": ["SSTI","RCE"],
        "url": "/htb_writeup/HTB-RedPanda/",
        "teaser": null
      },{
        "title": "[ HTB ] - Fawn",
        "excerpt":"Fawn Server offers FTP service, But Insecure Default setting and Passwrod complexity are the Attack Point. Now Let’s beggin Refer down below link https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp 1. RECONNAISSANCE Gather Victim Network Information nmap -sS -sV 10.129.154.45 FTP Service open 2. Initial Access External Remote Services - FTP Service ftp 10.129.154.45 ftp server...","categories": ["HTB_Writeup"],
        "tags": ["ftp","anonymouse login"],
        "url": "/htb_writeup/HTB-Fawn/",
        "teaser": null
      },{
        "title": "[ HTB ] - Meow",
        "excerpt":"Meow server offers telnet service, But it has Weak Credentials which easily let attacker log in, Now Let’s beggin 1. RECONNAISSANCE Gather Victim Network Information nmap -sS -sV 10.129.124.27 2. Initial Access External Remote Services - Telnet Service telnet 10.129.124.27 Target telnet server asks me credentials, hmm.. Let’s Burte Force...","categories": ["HTB_Writeup"],
        "tags": ["nmap","telnet"],
        "url": "/htb_writeup/HTB-Meow/",
        "teaser": null
      },{
        "title": "[ HTB ] - Dancing",
        "excerpt":"사진1 요약설명 1. RECONNAISSANCE Gather Victim Network Information nmap -sS -sV 10.129.1.12 445 port is open, SMB(Server Message Block) Protocol which provides shared access to files, Directory, printers on Windows. crackmapexec smb 10.129.1.12 --shares we also get OS Information via crackmapexec tool smbclient -L \\\\10.129.1.12 4 shares are here, But...","categories": ["HTB_Writeup"],
        "tags": ["SMB"],
        "url": "/htb_writeup/HTB-Dancing/",
        "teaser": null
      },{
        "title": "[ HTB ] - Appointment",
        "excerpt":"Appointment Server offers Web Service which has SQL vulnerability, Let’s beggin 1. RECONNAISSANCE Gather Victim Network Information nmap -sS -sV 10.129.134.174 Web Service open Search Open Websites/Domainsvulnerability Directory Scanning gobuster dir -w /usr/share/wordlists/dirb/common.txt -u 10.129.134.174 -o result.txt /.htaccess (Status: 403) [Size: 279] /.hta (Status: 403) [Size: 279] /.htpasswd (Status: 403)...","categories": ["HTB_Writeup"],
        "tags": ["SQL","SQLi","MaridaDB"],
        "url": "/htb_writeup/HTB-Appointement/",
        "teaser": null
      },{
        "title": "[ HTB ] - Responder",
        "excerpt":"Responder server offers two services. Web service and WinRM. this webstie has a LFI and RFI vulnerability, firstly, Web misconfiguration allows us put malicious php code, webshell, in apache access.log file, and then we can execute this just browsing a URL. and secondly, web server connects our machine via RFI,...","categories": ["HTB_Writeup"],
        "tags": ["Apache","NTLM","WinRM","Webshell"],
        "url": "/htb_writeup/HTB-Responder/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - Getting Started",
        "excerpt":"웹취약점 진단 능력 고도화를 위해 Vulnerable WebSites 에서 취약점을 찾아보자!  What?  1. demo.testfire.net 2. zero.webappsecurity.com 3. php.testsparker.com 4. aspnet.testsparker.com 5. testphp.vulnweb.com 6. testasp.vulnweb.com 7. testaspnet.vulnweb.com 8. testhtml5.vulnweb.com 9. x.x.137.97  How?  Checklist : ‘주요정보통신기반시설 취약점 점검 가이드’  Tools : ‘Chrome DevTools’, ‘Python’  Deadline : ‘2022/12/23’       Ok. Let’s do this :)  ","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-GettingStarted/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - demo.testfire.net",
        "excerpt":"RECON WAS: Apache Information Leakage 비정상 데이터 전송을 통해 웹서버 내 오류를 발생시켜 웹서버 WAS 종류 및 버전 정보를 노출시킴 https://demo.testfire.net/index.jsp?content=../../ WAS: Apache Tomcat/7.0.92 XSS URL 요청 시 스크립트 구문을 삽입하여 브라우저에서 스크립트가 실행 XSS-1 사용자 입력을 그대로 반환하는 페이지가 존재 https://demo.testfire.net/search.jsp?query=\"&gt;1234 ?query=&lt;script&gt;alert(document.cookie)&lt;/script&gt; XSS-2 비공개 설문조사 페이지는 ‘오픈소스’ 사이트에서 확인할수있었음...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-demo.test.fire.net/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - zero.webappsecurity.com",
        "excerpt":"RECON WAS: Apache Lang: JSP Information Leakage 서버 내 미존재 페이지를 접속할 경우 ‘404’ 에러코드를 반환하면서 WAS정보를 노출 http://zero.webappsecurity.com/robots.txt Apache Tomcat : 7.0.70 Admin Page Discloser 관리자페이지가 쉽게 유추가능하고 접속됨 http://zero.webappsecurity.com/admin/ Cleartext Transmission 평문통신(http)를 사용하고 있으며 중요정보(ID/PW)가 평문으로 전송되고 있음 (인코딩 및 암호화되지 않음) Position Leakage Position Leakage-1 Apache Tomcat이...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-zero.webappsecurity.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - php.testsparker.com",
        "excerpt":"RECON Server: Apache/2.2.8 (Win32) PHP/5.2.6 http://php.testsparker.com/robots.txt Position Leakage Position Leakage-1 서버의 ‘기본 파일’들이 불필요하게 외부에 공개되어 있어 2차 공격에 참고될 수 있음 http://php.testsparker.com/phpinfo.php http://php.testsparker.com/.svn/all-wcprops Position Leakage-2 개발자가 만들어둔 ‘백업 파일’에서 부분 소스코드가 노출되고 있어 2차 공격에 참고될 수 있음 http://php.testsparker.com/process.bak Path Traversal 웹서버 내 파일을 include하는 페이지가 존재 (LFI) http://php.testsparker.com/process.php?file=Generics/index.nsp...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-php.testsparker.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - aspnet.testsparker.com",
        "excerpt":"RECON OS: Windows Server WAS: IIS/8.5 Lang: ASP.NET/4.0.30319 Information Leakage 서버 에러를 유도하는 값을 전달하여 반환하는 페이지에서 서버 설정 관련 정보를 획득할 수 있으며 2차 공격으로 이어질수있음 http://aspnet.testsparker.com/Help.aspx?item=./Default.aspx http://aspnet.testsparker.com/test XSS 사용자 입력값이 고대로 반환되는 페이지가 존재 https://aspnet.testsparker.com/About.aspx?hello=test 스크립트 구문을 삽입하면 https://aspnet.testsparker.com/About.aspx?hello=visitor&lt;script&gt;alert(1)&lt;/script&gt; 스크립트 실행 Directory Indexing 서버 내 ‘디렉토리 인덱싱’이 활성화된...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-aspnet.testsparker.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - testphp.vulnweb.com",
        "excerpt":"RECON PHP 5.6.40 Nginx Ubuntu Position Leakage Position Leakage-1 Google Dork을 통해 ‘백업 파일’을 검색 site:testphp.vulnweb.com intext:\"bak\" ‘pictures’ 디렉토리 내 백업파일이 존재하고 있음 http://testphp.vulnweb.com/pictures/wp-config.bak Position Leakage-2 자동진단 툴이 아래 ‘서버 정보 파일’을 발견! http://testphp.vulnweb.com/secured/phpinfo.php 자동진단 툴이 아래 ‘백업 파일’을 발견! 부분 소스코드를 확인할수있으며 2차 공격으로 이어질수있음 http://testphp.vulnweb.com/index.bak http://testphp.vulnweb.com/index.zip Directory Indexing...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-testphp.vulnweb.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - testasp.vulnweb.com",
        "excerpt":"RECON OS: Windows Server WAS: Microsoft-IIS/8.5 Lang: ASP.NET Information Leakage 임의값을 전송하여 서버 에러를 유발시켜 서버 정보를 노출시킴 http://testasp.vulnweb.com/showforum.asp?id=asdasd Path Traversal 사용자로부터 Include 페이지를 입력받는 기능이 존재 http://testasp.vulnweb.com/Templatize.asp?item=html/about.html 서버의 내부 설정파일을 불러오는데 성공 ?item=../../../../../Windows/System32/drivers/etc/hosts SQLi ‘로그인 페이지’ 및 ‘공지사항 페이지’ 에 파라미터값을 SQL구문으로 전송할 경우 공격자가 의도한 결과를 얻어낼수있음 ex)...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-testasp.vulnweb.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - testaspnet.vulnweb.com",
        "excerpt":"RECON OS: Windows Server WAS: IIS/8.5 Lang: ASP.NET Information Leakage 서버 내 미존재 페이지에 접속할 경우 에러페이지가 반환되며 서버 정보관련 정보를 노출하고 있음 http://testaspnet.vulnweb.com/test XSS 답글을 등록하는 페이지에서 http://testaspnet.vulnweb.com/Comments.aspx 스크립트를 삽입하면 &lt;script&gt;alert(document.domain)&lt;/script&gt; 스크립트가 실행됨 SQLi SQLi-1 로그인 페이지에서 http://testaspnet.vulnweb.com/login.aspx 아래 SQLi 문구를 입력해주면 ' or '1'='1'-- Admin으로 로그인됨 로그인 시...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-testaspnet.vulnweb.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - testhtml5.vulnweb.com",
        "excerpt":"RECON WAS: Nginx/1.19.0 XSS 로그인 페이지에서 http://testhtml5.vulnweb.com/#/popular 스크립트 구문으로 로그인 하면 &lt;script&gt;alert(document.domain)&lt;/script&gt; 스크립트 실행됨 Cleartext Transmission 로그인 페이지에서 http://testhtml5.vulnweb.com/#/popular 평문통신(http)를 사용하고 있으며 중요정보(ID/PW)가 평문으로 전송되고 있음 (인코딩 및 암호화되지 않음) Insufficient Session Expiration ‘자리 비움’ 상태에서 1시간이 지나도 세션이 유지되고 있으므로 세션관리가 이루어지고 있지 않음 로그인 직후 모습 1시간 경과...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-testhtml5.vulnweb.com/",
        "teaser": null
      },{
        "title": "[ VulnWebs ] - x.x.137.97",
        "excerpt":"RECON OS: CentOS WAS: Apache/2.4.6 Lang: PHP/7.2.34 File Upload 업로드 페이지가 존재하며 http://x.x.137.97/upload.php 확장자 ‘.php’를 가지는 php코드 파일을 업로드 시도 import requests url = 'http://x.x.137.97/upload.php' files={ 'userfile': ('test.php', '&lt;?php echo \"Hello there!\" ?&gt;') } r = requests.post(url, files=files) print(r.text) 정상 업로드되었으며 특이점으로는 ‘업로드 경로’를 친절히 반환함 업로드 경로로 ‘URL 접속’할...","categories": ["VulnWebs_Writeup"],
        "tags": [],
        "url": "/vulnwebs_writeup/VulnWebs-x.x.137.97/",
        "teaser": null
      }]
