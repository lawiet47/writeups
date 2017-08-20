
Hello, today we are going to take a look at the quick analysis of infamous Dridex banking trojan, which stole over 40 million dollars in 2015. Over the years authors of Dridex have modified its structure, code base in hopes of improving its capabilities. Which is why samples you may find might differ from another. Below is the hash value of the sample that i analyzed.

SHA256: e30b76f9454a5fd3d11b5792ff93e56c52bf5dfba6ab375c3b96e17af562f5fc

Note: I am no expert malware analyst. This writeup simply shows what methods i used to analyze this sample. Obviously different tools and techniques could be used.

So without further ado lets get started. First to get a brief overview of what this program actually does we open it with Process Hacker. In Process Hacker we see that the program creates its child process and kills itself after 1 second.

 ![birth](https://user-images.githubusercontent.com/27059441/29209375-cfb76be6-7e96-11e7-9418-74a507985601.PNG)
 
 ![rebirth](https://user-images.githubusercontent.com/27059441/29209379-d688eac6-7e96-11e7-9d44-66569524a099.PNG)
 
 ![destruct](https://user-images.githubusercontent.com/27059441/29209390-e3b11d54-7e96-11e7-8aaa-504c1fd85af7.PNG)
 
 
And we see some network activity in Wireshark as well.

![wiresharkcapt](https://user-images.githubusercontent.com/27059441/29206630-5b576432-7e8b-11e7-9ebb-b9e80723721b.PNG)
 
This technique is called Process Hallowing(one of my favorites..shhh) AKA RunPE. The purpose of this approach is to unpack the packed version of malicious payload that the malware stores in itself and inject it to another process' memory. By doing this, malware limits the risk of getting caught by not writing any malicious file to the disk. All of this activity takes places in memory. This could be done in two major different ways. One of them is iterating through the processes currently active in memory find a suitable target, hallow out the contents of that process by calling `NtUnmapViewOfSection`(https://msdn.microsoft.com/en-us/library/windows/hardware/ff567119) and inject the payload in its memory. The other one is to create a child process and do the same thing to that child process.

Our sample uses the second technique.

If we open up the program in IDA Pro we see some errors saying translation of Virtual Address failed. This is a pretty good indicator of malware being packed. After taking a look at the IAT(Import Address Table) and seeing some weird characters we are now sure that the sample is packed.

![ida_error](https://user-images.githubusercontent.com/27059441/29206649-6ae86bbc-7e8b-11e7-9cef-55acc31cb8be.PNG)
 
To confirm that the program is not packed with some third party software we open up the sample in ExeinfoPE.

![notpacked](https://user-images.githubusercontent.com/27059441/29489654-ba8802d2-852e-11e7-9f76-ae6f1784d9c5.PNG)
 
But how are we going to unpack this? Well recall that the malware created a process and wrote something in its memory. This could be achieved by Microsoft APIs `CreateProcessA`(https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx) and `WriteProcessMemory`(https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx). So that means if we focus on those we might be able to figure something out. If we take a look the documentation of `WriteProcessMemory` it says that the API is used to write the contents of the specified buffer to the specified process. So that's it. All we gotta do is to put a breakpoint on the call to the `WriteProcessMemory` and then analyze the buffer parameter.

![write_buffer](https://user-images.githubusercontent.com/27059441/29206677-93a52806-7e8b-11e7-8e6f-9f48636f7c23.PNG)

![write_buffer2](https://user-images.githubusercontent.com/27059441/29206679-9aabd1ae-7e8b-11e7-9024-9ba655dccc07.PNG)

As we can see the buffer starts with the magic letters "MZ", which means the content is an executable, which is exactly what we have been looking for. So after dumping the unpacked version we open that up in IDA Pro and take a look at the IAT. AAaaaaaannd...

![iat](https://user-images.githubusercontent.com/27059441/29206686-a60ed442-7e8b-11e7-9f8c-3ac435cf898d.PNG)

What the heck? where are the functions? is it possible for a program with no IAT to steal $40 million? No way. In this case malware uses a method to obfuscate the IAT and calls the functions in run time(It obfuscates strings too). In order to know which functions this malware used we need to know what those entries are. Okay so lets get started.
After wandering around in IDA Pro a function catches our interest.

![hint_for_decryptor](https://user-images.githubusercontent.com/27059441/29206694-afd73a3c-7e8b-11e7-98d5-26a104b8f79b.PNG)

If we take a look at the Xref table to this function we see that there are a lot of calls to it.

![xrefs_to_decryptor](https://user-images.githubusercontent.com/27059441/29206704-bc238f52-7e8b-11e7-91ef-ed8ae8d09339.PNG)
 
Now, why a function needs to be called this frequently? I don't know. Maybe it is some kind of a decoding or decrypting routine? Well today is our lucky day because that is exactly what it is.
 
![decryptor](https://user-images.githubusercontent.com/27059441/29206716-cb8c4682-7e8b-11e7-8cc1-4359b40b4336.PNG)

After peeking inside this function we see that it has 2 call commands one of them being our target function. Let's double click the function `sub_406C08` and see where it will take us.

![decryptor_call](https://user-images.githubusercontent.com/27059441/29206721-d8edf884-7e8b-11e7-8d31-f0a96369699e.PNG)
 
Hmmm that’s interesting. We see a function named `sub_406C20` is being called but right before that there is an offset being pushed to the stack. What is that?

![encryptedtext](https://user-images.githubusercontent.com/27059441/29206731-e96c4e86-7e8b-11e7-97bc-cfcb1c47fa5f.PNG)
 
Looks like senseless chunk of data. If we put a breakpoint on that call and execute it 5-6 times we begin to see the API names.

![iointerconnect](https://user-images.githubusercontent.com/27059441/29489677-328813a8-852f-11e7-8638-c1628907c14e.PNG)

![iohttpsendrequest](https://user-images.githubusercontent.com/27059441/29489680-3886bdcc-852f-11e7-8b86-b4c2ecfe0413.PNG)
 
 
At this point i thought "Ok this is the encrypted string that contains the name of the imported functions and this function decrypts these names". If we analyze further details we begin to see the first 8 bytes of the encrypted string are being moved to the ebx and ebp registers and those registers are XORed with eax and edi registers. After the XOR operation ebx and ebp registers are being moved to somewhere in the stack.

![decryption_route](https://user-images.githubusercontent.com/27059441/29206762-01f5d0d0-7e8c-11e7-9500-15b8fc979484.PNG)

If we follow those addresses we see the API names we have been searching for.

![decryptedtext](https://user-images.githubusercontent.com/27059441/29206770-0ee33030-7e8c-11e7-983c-761cd3b081ba.PNG)

Conclusion: This function iterates through the encrypted chunk of data 8 bytes at a time, XORes these values with the eax and edi registers to get the real API names. If we take a look at these registers we see that the values of them are `76 a8 28 e0` & `e6 ac 0d e8` respectively.

![ebx](https://user-images.githubusercontent.com/27059441/29489702-ae07b434-852f-11e7-8c4e-7ea61aa6406e.png)
 
So, now we now everything to decrypt the IAT ourselves. I wrote a python script. Why Python? Well, because it is easy. The script does the same thing the malware does to decrypt the imported function names. We could easily take a different approach. Like waiting until the malware decrypts all the functions names and then take a look at the strings in memory or write a IDAPython script that will execute the code and at each breakpoint retrieve the function name.

![decrypter_script](https://user-images.githubusercontent.com/27059441/29206807-3bfe4b86-7e8c-11e7-917a-d933eb23afee.PNG)

The reason I wrote the key backwards is because the registers are in little endian format. After executing the script we get what we expected.

![iat_strings](https://user-images.githubusercontent.com/27059441/29206816-486ee182-7e8c-11e7-90e5-209a4d810494.PNG)
 
Now wee see what functions malware uses. Based on this we can set breakpoints on these functions and analyze the code. Earlier we saw that malware tries to reach out to an IP address which I suspect of being a C&C server. Lets analyze. Most of the time malware uses `InternetOpen`(https://msdn.microsoft.com/en-us/library/windows/desktop/aa385096(v=vs.85).aspx) and `HttpSendRequest`(https://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx) APIs to communicate with the C&C server. After setting breakpoints on those calls we observe 4 different IP addresses that the malware tries to reach out.

![firstipaddr](https://user-images.githubusercontent.com/27059441/29206825-521fa6da-7e8c-11e7-88d6-7841cd5883c4.PNG)

![secndipaddr](https://user-images.githubusercontent.com/27059441/29206832-59b43596-7e8c-11e7-9235-1e9110fc096a.PNG)

![thirdipaddr](https://user-images.githubusercontent.com/27059441/29206841-648df9f2-7e8c-11e7-830c-14fb86f609ae.PNG)

![finalipaddr](https://user-images.githubusercontent.com/27059441/29206848-6bd45346-7e8c-11e7-81ab-3e27f2710a53.PNG)

After this we saw a weird string in the stack.

![weirdkey](https://user-images.githubusercontent.com/27059441/29207351-8bfc7bce-7e8e-11e7-8739-26517f1b6550.PNG)
 
I saw this a few times to know it is the encryption key but that's not important right now. We will come back to it in a bit.
At the breakpoint to HttpSendRequest call we will see that the message were designed to be sent to the C&C is senseless. Most of the time malware uses encryption to make sure no one intercepts the network traffic between the malware and the C&C server. This could be done with `Microsoft Crypto API`(https://msdn.microsoft.com/en-us/library/windows/desktop/aa380255(v=vs.85).aspx). Some of the functions are `CryptCreateHash`(https://msdn.microsoft.com/enus/library/windows/desktop/aa379908(v=vs.85).aspx), `CryptHashData`(https://msdn.microsoft.com/en-us/library/windows/desktop/aa380202(v=vs.85).aspx), `CrytptEncrypt`(https://msdn.microsoft.com/en-us/library/windows/desktop/aa379924(v=vs.85).aspx).
If we set a breakpoint on the call to the CryptCreateHash we will see that the AlgID parameter holds the value 0x8003. This indicates that malware uses MD5 algorithm to hash the data. After the CryptCreateHash usually CryptHashData gets called which is the case in our sample. But before it calls CryptHashData it retrieves Computer Name, User Name & Install Date from the registry. Malware achieves this with `RegQueryValue`(https://msdn.microsoft.com/en-us/library/windows/desktop/ms724909(v=vs.85).aspx). It appends 4 null bytes to the buffer containing Computer Name, User Name & Install Date. We can see that in the memory.

![cryptcreatehash](https://user-images.githubusercontent.com/27059441/29489714-018f7786-8530-11e7-85f7-f441e50ecec5.PNG)
  
After that malware writes all the data it retrieved from the victim to the memory.

![unencryptedrequest](https://user-images.githubusercontent.com/27059441/29489716-130ff65c-8530-11e7-98c6-0780baeb088e.PNG)
 
We see a hash value and programs that are currently installed on the system. If we calculate the hash value of the malware retrieved from the registry(Computer Name+User Name+Install Date+4 0x0 bytes), we get the exact same value in the memory.

![manualmd5sum](https://user-images.githubusercontent.com/27059441/29489720-297b92c0-8530-11e7-861a-d3fc6ebec4a5.PNG)
 
Then malware encrypts all of this data and sends it to the C&C server. 

![encrypted_request](https://user-images.githubusercontent.com/27059441/29489727-48889b36-8530-11e7-8765-25f03a48bfbd.PNG)
 
But how it gets encrypted? Let's find out. Majority of the malwares use RC4 encryption because of its simplicity and speed. In this case our sample does the same. But because it implements its own RC4 algorithm its really hard for us to find out the part of the program that does the encryption to retrieve the key. But if you remember we saw a weird string in the memory right after the call to the HttpSendRequest. So, I used that string as the key of the RC4 algorithm to decrypt the C&C data and I got this...

![decrypted__rc4_request](https://user-images.githubusercontent.com/27059441/29206903-a99dbf82-7e8c-11e7-8d63-c1ec866e5b4d.PNG)

This is the same data in the memory before it gets encrypted and sent to the C&C server. So the encryption algorithm is RC4 and the key is `Yhc3XUIiv2rNzgy968TWCcx6PjBvLnuyT0ofNA9lvif8EIoZrLshPJ2kYi1WFXMDsuihGkT`. Because RC4 is symmetric encryption algorithm it uses the same key for encryption and decryption. Which means the data that comes back from the C&C server will be decrypted with this key. Because of Dridex servers being offline I could not say what data will be sent back and i did not analyze the code to know what the malware does after receiving a command from C&C server :) Sorry :). Well we got this far, lets decrypt the strings as well to see what further tricks this malware uses.

![string_decryptor_hint](https://user-images.githubusercontent.com/27059441/29206914-b76d7bc0-7e8c-11e7-9ea0-eba0de2e7008.PNG)
 

We see a function gets called in the code. If we double click on that we see a familiar pattern.

![strin_decrypto_call](https://user-images.githubusercontent.com/27059441/29206927-c03e8e2e-7e8c-11e7-8ec6-381021dc4575.PNG)

This is the same pattern we saw in the IAT decryption routine. If we follow the offset in the memory we see junk data.

![encryptedstrings](https://user-images.githubusercontent.com/27059441/29206937-caa898c8-7e8c-11e7-8273-0a035af29d4a.PNG)
 
After diving into the function we see that the same algorithm used to decrypt the strings. Just because we saw this pattern I am not going to go into the details for this. Long story short, malware reads the encrypted text 8 bytes at a time and decrypts it using XOR algorithm.

![same_pattern_string_decrypto](https://user-images.githubusercontent.com/27059441/29206948-d725a258-7e8c-11e7-808c-f25afc309cca.PNG)
 
Only this time there are multiple XOR keys. First we get a set of `0xb0 0x65 0x30 0xfd` & `0xf7 0xd6 0xf0 0x8b` keys. But after a certain offset the keyset changes to 
`0xdd 0x57 0x86 0xa1` & `0x49 0x40 0x60 0xc4`. The first keyset is used to decrypt the libraries used for getting the imported functions. The second keyset is used to decrypt the hardcoded shell commands. Again I used Python to decrypt those strings.

![string_decryptor_script](https://user-images.githubusercontent.com/27059441/29206959-e06aeae4-7e8c-11e7-8c8b-b07a061b4fff.PNG)

 
After executing the script we get this output...

![decrypted_strings_libraries](https://user-images.githubusercontent.com/27059441/29206961-e9ccfafa-7e8c-11e7-9a6d-52885f0ce120.PNG)

The one above is the libraries decrypted using the first keyset. and the nne below is the shell commands decrypted using the second keyset.
 
![decrypted_strings_commands](https://user-images.githubusercontent.com/27059441/29206972-f5143cb6-7e8c-11e7-8af2-09e9e965e9ab.PNG)

Despite these shell commands being messy and kinda mashed up we can determine the logic of what the malware does.
We see that sdbinst.exe is used with parameters  /q /u "%S". This means that the malware tried to delete an .sdb file. The .sdb files are the files that contain extra information about Windows Registry. After researching some of the commands we will find out that this technique is used to bypass UAC authentication. Which means Dridex can gain Administrative privileges even if it's started by a normal user.

Note: I analyzed the code a bit more after this and i found out that there are a lot more calls to the string decryption routine. Which means there could be other encrypted strings and other set of XOR keys. But because after the second decryption malware sleeps for a long time and i did not want to wait for it. So, if you can decrypt more strings let me know.

Thanks for your attention :)

