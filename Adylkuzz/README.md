After finally getting some free time I've decided to do a quick analysis of the miner called "Adylkuzz". This miner has first been identified in May 2017. Coincidentally(or not) this is the release date of The Largest Ransomware attack in the history of the Internet called WannaCry. Both WannaCry and the Adylkuzz miner used the same technique to propagate. Which was achieved by using the tools `EternalBlue` and `DoublePulsar` developed by NSA . The tools were leaked by the group called "Shadow Brokers" in 14 April 2017 and just after one month these tools were used to launch global cyber attacks. Unlike WannaCry the Adylkuzz miner causes much less noice, operates in the dark and silently mines `monero` cryptocurrency for the developers. Adylkuzz used multiple cryptocurrency addresses to avoid having too many moneros paid to a single address and mined approximately $43.000 worth of monero. The sample I am going to analyze has the below hash:

SHA256:	8200755cbedd6f15eecd8207eba534709a01957b172d7a051b9cc4769ddbf233

First Let's take a look at the behavioral analysis and see what the malware tries to do. For this we need to setup our remnux machine to capture the traffic of our windows machine. A few services has to be running in our remnux machine. So we activate them like below:

![xxxaccept_all_ips_fakedns](https://user-images.githubusercontent.com/27059441/36973171-e8ed22e8-2082-11e8-9fcd-2de81c99f562.png)

`fakeDNS` is a tool built into remnux to capture DNS traffic and send fake responses back to the machine that made the request.


![xxxinetsim_start](https://user-images.githubusercontent.com/27059441/36973187-fcb52fe6-2082-11e8-80d4-51613660775d.png)

`inetsim` is another useful tool that helps us to listen on different ports like 80:`http`, 443:`https`, 21:`ftp`. After setting up network related services we go to our windows machine and begin listening on events with `procmon` and log disk related activities with `capturebat`.
After that we execute the malware. After waiting for the malware to finish its job we turn off the services we started and begin to have a look at what we got. 

![xxxtaskkill1](https://user-images.githubusercontent.com/27059441/36973208-0caf0980-2083-11e8-9e9f-3ffcdb4561a5.PNG)

![xxxtaskkill2](https://user-images.githubusercontent.com/27059441/36973216-184a3a8a-2083-11e8-87fc-ff05605b56a1.PNG)

![xxxtaskkill3](https://user-images.githubusercontent.com/27059441/36973223-2013a9cc-2083-11e8-8d58-bfda8bc44e29.PNG)


In the procmon logs we see that malware killed a bunch of processes.

![xxxwelm_stop](https://user-images.githubusercontent.com/27059441/36973237-33f7768a-2083-11e8-8e25-e2255f6e2719.PNG)

![xxxwelm_delete](https://user-images.githubusercontent.com/27059441/36973254-3ea7bad6-2083-11e8-91ac-bf83ddbce342.PNG)


It stopped and deleted the service named `Windows Event Log Management`. After that we see that the malware added some firewall rules.

![xxxfirewall_rule4](https://user-images.githubusercontent.com/27059441/36973261-4d3676d2-2083-11e8-85d6-49968d749049.PNG)

![xxxfirewall_rule3](https://user-images.githubusercontent.com/27059441/36973264-56701172-2083-11e8-8a9b-4b8388404be5.PNG)

![xxxfirewall_rule2](https://user-images.githubusercontent.com/27059441/36973270-5ebf6db4-2083-11e8-94f5-f07047eab76c.PNG)

![xxxfirewall_rule](https://user-images.githubusercontent.com/27059441/36973283-6a4d0718-2083-11e8-9d52-4d88569744e4.PNG)



The last firewall rule is particularly interesting because it blocks the port 445 which is the port that vulnerable `SMBv1.0` protocol runs on. By doing this malware tries to minimize the chances of victim host getting exploited and in this case it actually worked because in that time the exploit code was being used in WannaCry. So by doing it Adylkuzz actually stopped the increase in the number of hosts getting infected by WannaCry.

In the procmon logs we also see that malware copied itself into another file named `wuauser.exe`:

![xxxprocmon_persistence](https://user-images.githubusercontent.com/27059441/36973297-77743c86-2083-11e8-9927-8cfc255bed93.PNG)

![xxxsame_orig](https://user-images.githubusercontent.com/27059441/36973309-8199bd4e-2083-11e8-960a-2f683d650573.PNG)


As we can see it has the same hash value with the original executable. If we take a look at the services in the victim machine we see that service named WELM is running on the system.

![xxxservices](https://user-images.githubusercontent.com/27059441/36973318-8ccb899a-2083-11e8-9a5e-0afc8e354de6.PNG)


Let's investigate this service.

![xxxservice_welm](https://user-images.githubusercontent.com/27059441/36973328-97600e80-2083-11e8-85d1-4590b42b838f.PNG)


It is beginning to get clear that this is a persistence method used by the malware. It stops and deletes the WELM service and restarts it with the malware executable as a parameter. The service will run in every startup ensuring malware's long stay in the victim host. If we check `%windir%\Fonts` directory using command line we can see that there are two executable files in the  directory. 

![xxxexefilesinfontdir](https://user-images.githubusercontent.com/27059441/36973337-a34f43aa-2083-11e8-9108-a7bc1639665b.PNG)

The `msiexev.exe` file is actually should be pulled from the C&C server but because the C&C servers are now offline this is nothing but a fake response from `inetsim`. We can also see the creation of `msiexev.exe` file in the procmon logs and tweaking of the `cmd.exe` options:

![xxxprocmon_msiexevexecreate_cmd_tweak](https://user-images.githubusercontent.com/27059441/36973356-b173ced8-2083-11e8-84a9-d38de064d445.PNG)


We also see that there is some kind of .txt file named `history.txt` which I am unsure of its purpose.

![xxxhistory_txt](https://user-images.githubusercontent.com/27059441/36973392-d72fa818-2083-11e8-98be-f242c375ce8e.PNG)

![xxxprocmon_tcp](https://user-images.githubusercontent.com/27059441/36973399-e01cc032-2083-11e8-9361-c7860d7eec4e.PNG)


We can also see the network activities in the logs...
Speaking of network Let's head over to our remnux machine to see what we captured.

![xxxfakedns_log](https://user-images.githubusercontent.com/27059441/36973407-e8605a74-2083-11e8-8851-c6b5939754b9.png)


`fakeDNS` logs shows us the DNS request made by the victim machine. The highlighted ones are made by the malware. It tries to learn the external IP address of the victim machine by querying `icanhazip.com` and send it to the C&C server which is `08.super5566.com`. The inetsim logs also show us the http requests.

![xxxurlencoded_pcap](https://user-images.githubusercontent.com/27059441/36973418-f43ea576-2083-11e8-9683-181de643c294.png)


The text is urlencoded and kind of hard to read. For decoding it I defined a simple alias which is a python one-liner:

![xxxurldecode_alias](https://user-images.githubusercontent.com/27059441/36973423-ffd90c46-2083-11e8-8cff-301670614a97.png)


To decode the text we can enter the following code:

![xxxurldecode_command](https://user-images.githubusercontent.com/27059441/36973431-08da7c58-2084-11e8-8348-55592cd00f25.png)


In decoded text we can see interesting requests that malware made:

![xxxurldecoded_pcap](https://user-images.githubusercontent.com/27059441/36973440-1261e9f0-2084-11e8-9f2f-64f5bbeba5af.png)


First the malware initializes the procedure by making a get request to the `/install/start` page. Then it queries victim's external IP and tries to pull a text file named `mine.txt`. Then it submits information about the victim machine to the C&C server and tries to pull another file named `86.exe`. Unfortunately I could not analyze any of the files that were supposed to be pulled down from the C&C server.

Ok enough about behavioral analysis. Let's do some reversing :) 

Load the binary in IDA and take a look at the Exports tab.

![xxxexports_tls](https://user-images.githubusercontent.com/27059441/36973454-2277844e-2084-11e8-8626-bf5cfbb66e35.PNG)


The binary has 19 exports. We can see interesting variable names containing keywords like `mine`, `install`, `hide`, `config`.

![xxxexport_hexdump](https://user-images.githubusercontent.com/27059441/36973461-2be96be6-2084-11e8-87c0-e077e35cfae0.PNG)


But the variables are null. Let's load the malware in OllyDbg. 

![xxxanti_debug](https://user-images.githubusercontent.com/27059441/36973471-37f43fd8-2084-11e8-8021-f73dbc2c5e97.PNG)


WTF is this? We have not even hit any breakpoints. What is going on?... Let's take a look at the sections table.

![xxxsections](https://user-images.githubusercontent.com/27059441/36973482-431a05be-2084-11e8-8152-5b525b14cd24.PNG)


We can see that this sample has `.tls` section and inside that there are `TlsCallbacks`. Thread Local Storage (TLS) Callbacks allow us to run code before the `OEP`. That is why we saw the ErrorBox before we even got to the EntryPoint. 

Let's take a look at the malware in `exeinfope` and see how it has been packed.

![xxxexeinfope](https://user-images.githubusercontent.com/27059441/36973489-4d061e50-2084-11e8-8872-a020cd9b4a75.PNG)


Aaaah..Shit... Now we see that it is packed with `VMProtect` Software. `VMprotect` is a software developed to protect executable formats. In their site they say: "Most protection systems encrypt the code and then decrypt it at the application’s startup. VMProtect doesn’t decrypt the code at all! Instead, the encrypted code runs on a virtual CPU that is markedly different from generic x86 and x64 CPUs as the command set is different for each protected file.". At this point I thought to myself "Ok..I am basically screwed". This thing has debugging checks, anti-dump tricks, it uses code mutation methods, `IAT` obfuscation techniques and lots and lots of different crap to make analysis a PAIN IN THE ASS. For all of its virtualization, mutation, encryption the packers like this are slowing down the execution of the original file and are not usually prefered amongst the malware authors but the Adylkuzz developers decided not to give a fuck. Reversing a virtualized and encrypted code completely takes a pro and is definetely not a task for a noob like me. But I am gonna try my best to make this writeup fun. 

We will need to bypass its anti-debugging tricks in order to unpack the malware. `VMProtect` uses different techniques to identify if it's running in a debugger. We can right a program that hooks the API calls that reveals the presence of a debugger but there is a nice guy that already did that for us [https://github.com/nihilus/ScyllaHide]. Let's open the plugin and tweak the options to ensure that we stay cloaked throughout the debugging procedure.

![scyllahide](https://user-images.githubusercontent.com/27059441/36973510-5a189d5c-2084-11e8-87f9-a6bce610269c.PNG)


As you can see it already has a profile for `VMProtect x86/x64` and already knows what APIs to hook if it is packed with `VMProtect`.

We also going to change the Debuggig options. Ignore the exceptions and pause at the System Breakpoint.

![xxxolly_dbg_options](https://user-images.githubusercontent.com/27059441/36973522-6624f74e-2084-11e8-8a38-0b31f6878b6f.PNG)


After changing the options we load the binary and press F9 to run it and this time we hit the system breakpoint.

![xxxtlscallback](https://user-images.githubusercontent.com/27059441/36973544-7f1b113e-2084-11e8-99f2-f23c68d307a6.PNG)


This is the `TlsCallback_0` routine which we saw in IDA. VMProtect is known for using `VirtualProtect`[https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898(v=vs.85).aspx] API for its `Memory Protection` feature. So we are going to set a breakpoint on that call.

![xxxvirtualprotectbp](https://user-images.githubusercontent.com/27059441/36973551-89b8e1e8-2084-11e8-8224-8db7b809ef52.PNG)


After we press F9 we hit our breakpoint. If we take a look at the stack we can see the call and the parameters being passed to it.

![xxxvirtualprotect_46e000](https://user-images.githubusercontent.com/27059441/36973558-914b1bd8-2084-11e8-8772-82f837849aa9.PNG)


We see that malware changes the access rights for the adress `0x0046e000` which is the starting address of the section named `.8010` and size parameter is actually the whole size of that section. If we follow that address in the dump we see that it is empty.

![xxx8010_dump](https://user-images.githubusercontent.com/27059441/36973567-9adbe1e6-2084-11e8-8d76-53207edc6453.PNG)


The same thing happens with all of other sections below is the `.text` section:

![xxxvirtualprotect_401000](https://user-images.githubusercontent.com/27059441/36973579-a4988252-2084-11e8-90f8-4cda55ee4349.PNG)


This section is also empty.

![xxxtext_dump](https://user-images.githubusercontent.com/27059441/36973595-adc78c24-2084-11e8-82bb-68dab35af056.PNG)


Usualy the sections are being emptied before anything gets written to them. After continuing the execution we see that both sections being filled.

![xxx8010_dump_filled](https://user-images.githubusercontent.com/27059441/36973611-b696a8f8-2084-11e8-8e11-5c65eede6f9c.PNG)

![xxxtext_dump_filled](https://user-images.githubusercontent.com/27059441/36973623-c007667a-2084-11e8-9f22-462b00103e96.PNG)


And we see VirtualProtect being called again with the same parameters except this time the access rights are PAGE_EXECUTE_READ. 

![xxxvirtualprotect_46e000_normal](https://user-images.githubusercontent.com/27059441/36973637-cae3c8c2-2084-11e8-9c45-68fbb2927013.PNG)

![xxxvirtualprotect_401000_normal2](https://user-images.githubusercontent.com/27059441/36973645-d2f8a866-2084-11e8-91d7-5f2a920ec234.PNG)


So now that the executable sections are filled malware is probably going to jump back to the user code. So we just have to set a final breakpoint on access on both executable sections.

![xxxmemmap_bp](https://user-images.githubusercontent.com/27059441/36973655-dcba0e30-2084-11e8-956d-c144a177bd89.PNG)


And Continue...

![xxxjump_to_oep](https://user-images.githubusercontent.com/27059441/36973692-0107fa04-2085-11e8-83b4-be02b0b54ed1.PNG)


After finding ourselves on a jump instruction we execute the jump instruction and land on the place which is near the `OEP` but is not the real `OEP`. When dealing with virtualized packers like `VMProtect` & `Themida`. finding `OEP` & reconstructing `IAT` is optional. We don't need the unpacked code to be runnable we already decrypted the sections.(That's a lie I tell myself untill I know how to do it. :/).

![xxxoep](https://user-images.githubusercontent.com/27059441/36973711-12afcdf4-2085-11e8-8068-fd9a2114774e.PNG)


Now we need tool `Scylla` to dump the process.

![scylla_dump](https://user-images.githubusercontent.com/27059441/36973720-1c677734-2085-11e8-9b90-705ea5d95c37.PNG)


Ok. After dumping the process and removing the useless overlay we got ourselves the "kind of unpacked" sample.

![xxxadylkuzz_detection_rate](https://user-images.githubusercontent.com/27059441/36973733-2849fc3e-2085-11e8-99d7-a31365d3bf2d.PNG)


As you can see the virustotal recognizes the unpacked sample. So Let's open up the binary in IDA and have a look. In the Strings subview we can see the address of the C&C it contacted.

![xxxunpacked_strings](https://user-images.githubusercontent.com/27059441/36973743-338bbb28-2085-11e8-9d9d-43c6837b80b7.PNG)


We can also see the process names which malware checks for existence during runtime.

![xxxprocess_strings](https://user-images.githubusercontent.com/27059441/36973760-40e2995e-2085-11e8-992f-963434b4111f.PNG)


And the exported variables in the exports menu are also filled with data.

![xxxexport_hexdump2](https://user-images.githubusercontent.com/27059441/36973768-4936f096-2085-11e8-9bd0-de421be6665a.PNG)


Ok we have come to and end of another writeup. I hope you enjoyed it even though I did not do a great job :( If any of you knows how to find the `OEP` or rebuild the `IAT` or general way of completely getting a runnable unpacked sample I would be very happy to hear it from you.

Thanks for your time :)
