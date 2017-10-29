Most of you must’ve already heard of the mighty “ZeuS” aka Zbot. First identified in July 2007 and is estimated to have caused damages worth US$100 million. So it’s a pretty big deal. Today we are going to take a quick look at it. The ZeuS malware mutated over the years so obviously the hashes will differ. The sample I am going to analyze have the below hash:

SHA256: 9ed85a6de31604eb431cdd7632cad0e5be54af10a16cc6ca0b886d1f92bb91b8

Note: I am no expert malware analyst. This writeup simply shows what methods i used to analyze this sample. Obviously different tools and techniques could be used.

Let’s begin. When we try to execute the malware and have a look at it in the `Process Hacker` the malware just runs for a few seconds and then exits. If we run a behavioral analysis on this sample what we get useful is that `CaptureBat` tells us that it modified and deleted some files under certain directories. One of them being a batch file called `upd25acfa62.bat` and located under `%TEMP%` directory.

![capture_bat](https://user-images.githubusercontent.com/27059441/32142944-27eb0a5c-bcb3-11e7-81ec-6226bf8788d1.png)

The file content shows us that it tries to delete the malware sample we ran.

Ok. Let’s have a look at it in IDA pro.

![junk_code1](https://user-images.githubusercontent.com/27059441/32142949-398f371a-bcb3-11e7-8c91-fcd831aee79e.PNG)

If we look at the code we will see a lot of junk code like this.

![junk_code2](https://user-images.githubusercontent.com/27059441/32142951-42b592f8-bcb3-11e7-98b3-fb62725dc41e.PNG)

We can see these API calls in almost every Windows GUI application. This is a method used by a lot of malware families like `Poison Ivy`. By implementing this pattern malware tries to bypass static analysis tools by looking like a legit Windows GUI app.

![packed_iat](https://user-images.githubusercontent.com/27059441/32142958-52da7478-bcb3-11e7-96cf-c960e60c260a.PNG)

The IAT shows this malware calls only non-suspicious APIs. We already know that this sample is packed. 

If we were to look at the strings we can’t see anything useful either.

![packed_strings](https://user-images.githubusercontent.com/27059441/32142977-b097c9f8-bcb3-11e7-92c4-ec559f3b566a.png)


A lot of malware samples are dealing with the unpacking process by decrypting  their contents, create a new process and inject the malicious content inside the newly created process. However this does not seem to be the case with “ZeuS” since we did not see it creating a new process. In this case we can say that the malware decrypts malicious content and injects it inside its own `.text` section. It makes sense because all we got in the `.text` section was boring Windows GUI API calls. So the malware must’ve implemented this method.

Let’s fire up the `Immunity Dbg` and give it our sample as an input file.
Since we know that the decrypted contents will be written into the `.text` section we can place a `Hardware on Write` breakpoint in that section. When we do that and run the sample, somewhere in the code the breakpoint gets hit.

![decryption_routine](https://user-images.githubusercontent.com/27059441/32142982-be40eaee-bcb3-11e7-9426-884eb898db8b.PNG)

When we run until exit of the current function the `.text` section gets zeroed out and we fall in the space of another function.

![new_empty_text](https://user-images.githubusercontent.com/27059441/32142998-eb4c4362-bcb3-11e7-901e-0103b67726b9.PNG)

The other function:

![decryption_routine2](https://user-images.githubusercontent.com/27059441/32143004-f5592bae-bcb3-11e7-837f-a881f57c386e.PNG)

After we run until exit of this one as well the contents of the `.text` section is filled with data.

![new_decrypted_text](https://user-images.githubusercontent.com/27059441/32143008-022abffa-bcb4-11e7-93bb-61e23bd25252.PNG)

After the decryption routine the malware must resolve the OEP in order to start executing the malicious code. Most of the time the indicators of decrypted OEP is a call to the `eax` register or an unconditional jump followed by a lot of garbage code. We are gonna look out for both.

if we run until exit of the current function after the `.text` section is decrypted we find ourselves in a place like this.

![call_to_oep](https://user-images.githubusercontent.com/27059441/32143207-2eb350f2-bcb7-11e7-93ef-19adbeac97ae.PNG)

There is the `call	eax` instruction we have been looking for. If we step into the function looks like the address is in the range of the `.text` section and we can see valid assembly instructions.

![decrypted_oep](https://user-images.githubusercontent.com/27059441/32143211-3d5df5e4-bcb7-11e7-8767-05a9bc997f09.PNG)

So we are sure this is the OEP we were searching for. Now we can dump the process with `Scylla`. For the unpacked code to be runnable we need to Fix the Dump. After doing so we got ourselves the unpacked version of malware.

![scylla_screen](https://user-images.githubusercontent.com/27059441/32143024-390234ae-bcb4-11e7-8721-accbab0732d4.PNG)

Here is the virustotal’s analysis on our unpacked sample

![zeus_unpaked_virustotal](https://user-images.githubusercontent.com/27059441/32143029-48d5ee84-bcb4-11e7-817f-1fbc2df52c49.png)

After opening the unpacked PE in IDA pro we still see that the Imports table is incomplete

![incomplete_iat](https://user-images.githubusercontent.com/27059441/32143041-877271a8-bcb4-11e7-83b0-4737c8eee3c1.png)

This means that the malware is resolving the function names during run-time. Let’s find out how. When we scroll through the functions and look at the xrefs in IDA we come across something like this

![get_api](https://user-images.githubusercontent.com/27059441/32143043-933ff32a-bcb4-11e7-8303-4b774ffdd9a8.PNG)

(I already knew what it was that’s why I renamed it). As we can see the xref count is to high for this function. This is a common technique used by malwares to resolve function names dynamically.

The `get_api` function in itself calls two functions `lib_decryptor` & `string_deobfuscator` (Again, I already knew what they were that’s why I renamed them).

![lib_decryptor](https://user-images.githubusercontent.com/27059441/32143047-a46cae2c-bcb4-11e7-8e48-925df86f3bb5.PNG)

![string_deobfuscator](https://user-images.githubusercontent.com/27059441/32143052-ae5ccdd6-bcb4-11e7-86aa-e9d1fe6660df.PNG)

The `lib_decryptor` function has a loop that goes through a certain blocks of memory and decrypts the contents then makes a call to `LoadLibraryA` or `GetModuleHandleA` to load the module.

![lib_decryptor loop](https://user-images.githubusercontent.com/27059441/32143058-bcb57694-bcb4-11e7-9bff-88e57a15bcc8.PNG)

![get_module_handle](https://user-images.githubusercontent.com/27059441/32143064-cda3d6d0-bcb4-11e7-8fec-421814cb97ba.PNG)


By placing a breakpoint in the loop we can see a certain strings appear in the memory

![decrypted_lib_advapi](https://user-images.githubusercontent.com/27059441/32143215-51c679f2-bcb7-11e7-94e5-dbd675b3d545.PNG)

![decrypted_lib_shlwapi](https://user-images.githubusercontent.com/27059441/32143224-5e2c07d4-bcb7-11e7-8cdb-35fb7c35f00b.PNG)

Here is the list of the loaded modules

![loaded_modules](https://user-images.githubusercontent.com/27059441/32143238-92cd2e5a-bcb7-11e7-86d2-bb0fd866cf8e.png)

The `string_deobfuscator` function is similar to the `lib_decryptor` function. It also has a loop that goes through a certain blocks of memory to decrypt the strings.

![string_deobfuscator loop](https://user-images.githubusercontent.com/27059441/32143244-9e67b802-bcb7-11e7-97cd-21e939fa4ad2.PNG)

By placing a breakpoint on this loop as well we come across some interesting strings.

![decrypted_strings](https://user-images.githubusercontent.com/27059441/32143253-afdb5b8e-bcb7-11e7-9e2d-837f902544ea.PNG)

Here we see that the malware tries to gather information related to the operating system.

![vmware_seeking](https://user-images.githubusercontent.com/27059441/32143254-ba0c1076-bcb7-11e7-82da-8b53298f41bd.PNG)

We can see the malware implements some anti-debugging techniques by searching for strings that tell about existence of a virtual machine in the system. It does that for `VirtualBox` too.

![vbox_seeking](https://user-images.githubusercontent.com/27059441/32143260-c6d16856-bcb7-11e7-99b3-8256ca151905.PNG)

Then we can see the contents of the .bat file that is supposed to delete the sample.

![writefilebr](https://user-images.githubusercontent.com/27059441/32143262-d0f5d4b6-bcb7-11e7-8ed1-b5f1f7672d2a.PNG)

The API resolving happens with the help of `get_api` function. After calling the `get_api` function each time the malware makes a call to the `eax` register which holds the resolved function name. Instead of locating each encrypted blob in each loop(Because different addresses used for different strings) I let the malware resolve the function names for me.

So I wrote a python script that searches for a pattern like `call   e`
and places breakpoints with conditions on those addresses with the condition being printing the value of `EAX`.

![api_scanner](https://user-images.githubusercontent.com/27059441/32143266-da5d548e-bcb7-11e7-97e8-39dd031b20b6.png)

After getting the addresses we need them to resolve to function names. That’s why I wrote a `Windbg` script. 

![windbg_script](https://user-images.githubusercontent.com/27059441/32143268-e420d662-bcb7-11e7-8cc5-b081608ed54c.png)

I know most people are gonna laugh at me for doing such a sloppy job and I know there are other ways, the right ways of doing it, like with `pykd` but I was too lazy so a went with the lazy way.

After executing the script the output is kinda messy 

![windbg_output](https://user-images.githubusercontent.com/27059441/32143273-ed2c7c0c-bcb7-11e7-9319-8d893ddbb805.png)

So we are going to beautify it

![iat_beautify](https://user-images.githubusercontent.com/27059441/32143276-f73a7e1a-bcb7-11e7-9917-9779dd35a2f3.png)

And there is our Import table

![iat](https://user-images.githubusercontent.com/27059441/32143285-135ebac0-bcb8-11e7-87ad-fbe1889ad3e1.png)


Thanks for your attention :)
