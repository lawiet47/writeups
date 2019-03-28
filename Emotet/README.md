Ever since I returned from my Portuguese "vacation"(which was cut short by bureaucracy)
I felt a bit empty and lost. So I thought what would be a better way of filling the void inside than to take a look at
some malware samples. Because most people/companies are getting infected with `Emotet` trojan these days,
I decided to take a look at an `Emotet` sample.
This post is going to be more like a "technical report" and less
like a tutorial because.. well I'm sad. Because `Emotet` is constantly evolving, the samples differ over short periods of time.

`Emotet` is a modular malware first identified in 2014 which acts as a dropper for other malwares (banking trojans like TrickBot, ransomware like Ryuk). It's a highly versatile way for the bad guys to drop their malware onto the victim host.
It is mainly distributed to the victims via e-mail. The infection vector is mostly a macro-enabled word document.

![mind_map](https://user-images.githubusercontent.com/27059441/55142405-92477900-514d-11e9-9763-fea8e2667a74.PNG)


Summaries for the files that have been analyzed.

| FileName | Inv-2019-038868-06-02-2019.doc |
| ------- | ------- |
| FileSize | 293.13 KB |
| FileType | MS Word Document|
| MD5 | 92332eaa37f3fbd6891e3dce497e5602 |
| SHA1 | b4e2063862f1fb618162c58219964d1b0609cacc |
| SHA256 | 4b9905dadf4bb37fdca57b47c5ee0369405c8141b8e521bdd55da9a5349a328e |
| SSDEEP | 6144:PG5/BnVfRFJ7KK9aHScdX9znGUEW1ZT+TveVmhjdtSm5:P2n9R/lA5dX9znGUESZTuveWdtSm5 |

| FileName | 345.exe |
| ------- | ------- |
| FileSize | 140 KB |
| FileType | MS Portable Executable Document |
| MD5 | e56a4d2452a1d2fd8840ce19428a00a3 |
| SHA1 | 0761fd555be6344c3adf1d9509f147b566088d23 |
| SHA256 | 4e4ae10ef10ea6943f1b7365f42526036aa00f4bb349479ff18d781829829380 |
| SSDEEP | 3072:A8apfaUfv0DrCztQ3BEuMIwplogqO0tAeNq1VGiuHPQy:A8apfaUfvAstQ2IwYe1E/4 |

Below is the macro-enabled word document which contains the vba script that will launch the attack.(Screenshot by https://twitter.com/harunglec)

![Image](https://user-images.githubusercontent.com/27059441/55143082-0f272280-514f-11e9-866d-3549caf235f4.png)


<h1>Technical Analysis</h1>

Below is the screenshot of the macro code extracted from the word document file. We can see typical malicious keywords/part of keywords are present which are `autoopen` and `powe`. 

![Image](https://user-images.githubusercontent.com/27059441/55143184-40075780-514f-11e9-8b93-ac272e115985.png)

After making some adjustments to the script to print us the command instead of running it we are presented with a base64 encoded powershell command.

![modified_macro_run](https://user-images.githubusercontent.com/27059441/55143359-a68c7580-514f-11e9-860e-89d68648b830.gif)

The result of the decoded code looks like this:

![Image](https://user-images.githubusercontent.com/27059441/55143426-c7ed6180-514f-11e9-9d4e-519b7c106ad9.png)


Which we can beautify into this (Thanks to https://twitter.com/harunglec again for the beautification):

![Image](https://user-images.githubusercontent.com/27059441/55143470-ddfb2200-514f-11e9-92b9-ecdc351e7f12.png)

We can clearly see that the code tries to contact domains such as `hxxp://bazee365.com`, `hxxp://giancarloraso.com` and a bunch of other IP adresses to pull randomly named files, save them to the `C:\Users\<username>\` folder as `345.exe` and run the downloaded file.

After `345.exe` has been executed, it copies itself onto two seperate locations: `C:\Windows\SysWOW64\radarneutral.exe` and `%TEMP%\7C91.tmp`(will be deleted afterwards), deletes itself from the downloaded directory, creates a process named `radarneutral.exe` and a service named `radarneutral` with the binary execution path of `C:\Windows\SysWOW64\radarneutral.exe` and then proceeds to kill its process. Keep in my mind that the name `radarneutral` may change depending on the device that the malware was executed on.

(Don't mind the "bandicam" logo this is what a broke analyst looks like)

![service_create](https://user-images.githubusercontent.com/27059441/55143526-fbc88700-514f-11e9-8288-6896d4b93ffa.gif)

Also it could be seen that malware tries to modify the registry to maintain its persistence and stay hidden as a legit windows service.

![Image](https://user-images.githubusercontent.com/27059441/55143659-3b8f6e80-5150-11e9-9729-9d25aeee5711.png)


A few seconds after it was executed this sample tries to reach out to a few IP addresses.

![Image](https://user-images.githubusercontent.com/27059441/55143701-54981f80-5150-11e9-9f60-007cc87f558f.png)


<h2>Anti-Analysis Techniques</h2>

Emotet is known to have a bunch of anti-analysis techniques up its sleeve like dynamically resolved imports, encrypted strings, inter-segment jump method(I just made the name up. Hopefully it's a thing).
`Emotet` resolves its imports by hashing their ascii names with `sdbm hash method` and then comparing them to the predefined hash values. 

![image](https://user-images.githubusercontent.com/27059441/55143758-75f90b80-5150-11e9-9592-f7b9aac54172.png)

The hashing implementation:

![Image](https://user-images.githubusercontent.com/27059441/55143913-c7a19600-5150-11e9-8735-c22249650a69.png)

Dynamically resolved API calls:

![image](https://user-images.githubusercontent.com/27059441/55143935-d38d5800-5150-11e9-8899-496963355c15.png)

![image](https://user-images.githubusercontent.com/27059441/55143958-e2740a80-5150-11e9-9e62-02669dc29f3e.png)

After the unpacking procedure `Emotet` writes it's unpacked code to 2 different sections. Then uses the assembly `jmp` instructions to jump between sections to execute the unpacked code so that
disassembly tools like IDA won't be able to generate graphs because of the external `jmp` instructions.(But it could be bypassed in this case since the `jmp` instruction simply acts as a `nop` on the most parts of the code).
This method is designed to slow the static analysis down for the analysts.

![image](https://user-images.githubusercontent.com/27059441/55144003-f7e93480-5150-11e9-8ed0-400bd0fa1111.png)

![image](https://user-images.githubusercontent.com/27059441/55144012-ff104280-5150-11e9-9363-8f725c834115.png)

The sample also has anti-debugging techniques which it achieves by using mutexes.
It creates a mutex which has a format like `PEM###` (### is a 3 digit hex number which is a result of mathematical manipulation of the process ID) and checks if a mutex with the same name already exists.
If it doesn't, malware simply spawns a copy of itself and exits.

![image](https://user-images.githubusercontent.com/27059441/55144049-118a7c00-5151-11e9-89a7-d26ee5b983fd.png)

After that malware creates another mutex as an infection marker to prevent itself from reinfecting the host. The format of the mutex's name is `Global\\M<Volume serial number>`.

![image](https://user-images.githubusercontent.com/27059441/55144066-18b18a00-5151-11e9-97e3-a5021c121162.png)

File operations (deletion, copying) is done via an old Windows API call `SHFileOperationW`.

![image](https://user-images.githubusercontent.com/27059441/55144091-2535e280-5151-11e9-8d82-f1bb68f06a8a.png)

<h2>Partial C&C communication</h2>

My employer who also provided me with the sample was strict about the malware not making any connections to its C&C.
Therefore the name "Partial C&C communication". When infecting the host, malware gathers information on the infected host such as CPU information, Running process list, Volume serial number.
After that it sends that information in an encrypted form over the network to one of the C&C addresses over the ports `995` `53` `443` `8080`.
The encryption algorithm is `AES_128_CBC`. Malware sends the encrypted information on a HTTP request. The `Cookie` value in that request contains the AES 128 bit encryption key, hash value of the message body and the actual message. If the malware can not establish a successful TCP handshake with the C&C address it randomly chooses another one from its list and tries until a connection is established.  

![image](https://user-images.githubusercontent.com/27059441/55144114-2e26b400-5151-11e9-97e9-7651463d416d.png)

![image](https://user-images.githubusercontent.com/27059441/55144152-3aab0c80-5151-11e9-9718-9fbf0db21918.png)

![DONEkey_generate](https://user-images.githubusercontent.com/27059441/55187213-7d98ce80-51a9-11e9-9e9f-74e6852c0f9a.PNG)

![DONECapture7](https://user-images.githubusercontent.com/27059441/55144554-24ea1700-5152-11e9-8bb7-bbf5b448028d.PNG)



<h1>IOC list</h1>
<h2>Files</h2>

`%SystemRoot%\SysWOW64\radarneutral.exe`

`%TEMP%\7C91.tmp`

`%APPDATA%\radarneutral\radarneutral.exe`

`%USERPROFILE%\345.exe`


<h2>Registry</h2>


`HKLM\SYSTEM\CurrentControlSet\services\radarneutral\`

`HKLM\SYSTEM\ControlSet001\services\radarneutral\`


<h2>Mutex</h2>

`PEM###`

`IESQMMUTEX_0_208`

`Global\\M<Volume_Serial_Number>`

`Global\\I<Volume_Serial_Number>`



<h2>User agent</h2>


`Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)`

`Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)`

`Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)`


<h2>Hashes</h2>


`e56a4d2452a1d2fd8840ce19428a00a3`

`92332eaa37f3fbd6891e3dce497e5602`

`f8f5a5dffa8d195b33113c79865b78e2`


`0761fd555be6344c3adf1d9509f147b566088d23`

`b4e2063862f1fb618162c58219964d1b0609cacc`

`b746082937e433dc668d800d7c41b3cee6aa0775`


`4e4ae10ef10ea6943f1b7365f42526036aa00f4bb349479ff18d781829829380`

`4b9905dadf4bb37fdca57b47c5ee0369405c8141b8e521bdd55da9a5349a328e`

`21463493562201a94f0c0f91e09aa68ac0f0d0b24c0d8e7f440a19ceed17d068`

<h2>IP list</h2>

`109.104.79.48`

`109.226.196.123`

`12.6.183.21`

`138.68.139.199`

`144.76.117.247`

`159.65.76.245`

`162.247.42.61`

`165.227.213.173`

`168.226.35.218`

`173.68.169.16`

`174.96.202.70`

`181.168.123.241`

`181.56.165.97`

`185.86.148.222`

`186.15.180.71`

`186.4.127.72`

`187.163.204.187`

`189.173.176.115`

`190.117.226.104`

`190.85.8.155`

`192.155.90.90`

`192.163.199.254`

`201.122.94.84`

`201.137.6.108`

`201.183.238.18`

`201.212.113.14`

`208.180.246.147`

`209.159.244.240`

`210.2.86.72`

`219.94.254.93`

`23.233.240.77`

`23.254.203.51`

`5.9.128.163`

`51.255.50.164`

`66.209.69.165`

`69.163.33.82`

`71.40.213.82`

`72.47.248.48`

`74.45.170.110`

`80.15.172.81`

`82.218.163.254`

`90.63.245.70`

`92.48.118.27`

`52.66.202.63`

`192.198.90.198`

`13.233.183.227`

`128.199.187.124`

`104.233.40.40`

<h2>Malicious Domains</h2>

`hxxp://bazee365.com`

`hxxp://giancarloraso.com`
