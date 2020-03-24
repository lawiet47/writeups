For a past few days/weeks we've all been quarantined inside our homes like a bunch of potatoes due to Covid-19.

So I thought I'll write about how to bypass `Windows Defender`/`MDATP` (`Microsoft Defender Advanced Threat Protection`). `Windows Defender` itself actually does a pretty good job detecting threats (both with file & fileless). With microsoft's new EDR solution MDATP (Microsoft Defender Advanced Threat Protection), defender stands strong against malware campaigns & APT attacks.
I decided to choose a phishing scenario to test the Defender. To ease the pain of managing payloads/shells I decided to go with `Cobalt Strike` as a post-expoiltation tool.
Many attack vectors can be generated on `Cobalt Strike`'s dashboard. To simulate the phishing scenario, first we need to create an office document with the macro code that'll launch the attack. This can be done easily because `Cobalt Strike` already has a bunch of them ready embedded it.
If we generate the office document with the launcher macro code and try to open it `Windows Defender` detects it almost instantly

![USED_Capture7](https://user-images.githubusercontent.com/27059441/77406474-c340a500-6dc5-11ea-80be-0bb52c268000.PNG)

![USED_Capture8](https://user-images.githubusercontent.com/27059441/77406500-ce93d080-6dc5-11ea-92f0-4bbbd9c48047.PNG)

A few seconds after the detection the malicious document is deleted. Now, the launcher macro code can be obfuscated and there are a few tools that can manage it automatically like https://github.com/bonnetn/vba-obfuscator and https://securityonline.info/macro-pack-obfuscation-ms-office/ . But none of them seemed to work to bypass `Windows Defender`.

So the strategy I followed was to combine two different approaches in one vector. The first one being a powershell payload which can also be generated on `Cobalt Strike`'s dashboard and the second one being office macros.
After generating it, we take a look at the payload and it looks something like this:

![USED_Screenshot_2020-03-23_05-32-27](https://user-images.githubusercontent.com/27059441/77406542-dc495600-6dc5-11ea-9a16-057b92bda41b.png)


Now, obviously we can't use the payload as it is because it'll be detected and blocked by many antivirus solutions as well as `Windows Defender`. One of the things we can do is to obfuscate the powershell payload. Daniel Bohannon's `Invoke-Obfuscation` tool https://github.com/danielbohannon/Invoke-Obfuscation comes in handy in many situations but no matter how many times I obfuscated the powershell payload it still got detected and blocked by `Windows Defender`. To understand the payload better & to see what's triggering the detection we can decode it to the point till it's easily readable.
There are plenty of tools which can be used to decode/encode text/binary files to & from different encoding fromats. https://gchq.github.io/CyberChef/ is just one of them. 
By decoding base64 encoded text we can see there's another base64 encoded text:

![USED_Capture](https://user-images.githubusercontent.com/27059441/77406770-36e2b200-6dc6-11ea-9c24-ed713c749aa5.PNG)

Further decoding the text and then finally unzipping the deflated payload we can see what's underneath the `Cobalt Strike`'s powershell payload.

![USED_Capture2](https://user-images.githubusercontent.com/27059441/77406816-43ffa100-6dc6-11ea-9d67-8b3eb144e095.PNG)

The part that's bothering the Defender is actually the part where `$var_code` gets assigned to yet another base64 encoded text.
By XOR'in the text blob and decoding it we can see that it's a shellcode and can actually get readable ascii characters from it like the user-agent and IP address of the `Cobalt Strike` teamserver.

![USED_Capture5](https://user-images.githubusercontent.com/27059441/77406845-5083f980-6dc6-11ea-9ba2-82cdcd4966db.PNG)

To avoid the detection we need to obfuscate the part concerning the `$var_code` variable. To do this we can use the Invoke-Obfuscation framework. 

![USED_2020-03-23 14_57_18-C__Windows_system32_cmd exe - powershell  -exec bypass](https://user-images.githubusercontent.com/27059441/77406914-6a254100-6dc6-11ea-8432-58b74fa6f6f0.png)

The number of layers of obfuscation really depends on us but I went with one as it seemed to do the trick. After obfuscating the payload which gets assigned to `$var_code` variable we need to define it as a new variable and then reassign that value to `$var_code` again. So the final payload is gonna look like something like this.

![USED_Capture12](https://user-images.githubusercontent.com/27059441/77406960-79a48a00-6dc6-11ea-886a-5cd77d3bdfb0.PNG)

At this point the obfuscated powershell payload can be used on its own to launch an attack but I wanted to go a bit further and embed it as a script file inside an office document and have vba macros launch the attack.

As I've said earlier `Cobalt Strike` already has templates to create office macros. But since most of them are easily detected (even with the automated obfuscation techniques) we'll need to write our own macro code & obfuscate it in such a way that it'll bypass the Defender's detection & protection mechanisms.

So to achieve this I decided to embed the powershell script into a `UserFom`. I've noticed that by making use of UserForms in vba macros it drops the detection rate by a pretty good amount compared to pasting the whole payload into the vba code itself. Below is in image of a UserForm wich has a label containing the whole payload in hex format.

![USED_Capture13](https://user-images.githubusercontent.com/27059441/77407003-8c1ec380-6dc6-11ea-8e9c-a313bb4765ba.PNG)

We're almost there. Now all we need is a piece of vba code to parse and execute the data specified in the UserForm. To achieve this I wrote a piece of vba code that parses and executes the contents of the powershell script.

To avoid needles attention from strings like `cmd.exe`, `/C powershell.exe`, `-ExecutionPolicy Bypass` that's going to be present in the vba code we can also obfuscate the strings. Below is an example python code that I wrote to eliminate the repetitions of ascii characters and have them referenced by their index number in an array.

![USED_Capture100](https://user-images.githubusercontent.com/27059441/77407041-9d67d000-6dc6-11ea-8f7f-636b8e0f37cc.PNG)

The final vba code is gonna look like something like this:

![USED_Capture4](https://user-images.githubusercontent.com/27059441/77407059-a5277480-6dc6-11ea-8e5c-ca2df221c716.PNG)

Alright, we're good to go. 

![USED_Capture6](https://user-images.githubusercontent.com/27059441/77407087-af497300-6dc6-11ea-8439-cc8c65c65deb.PNG)

The final result successfully executed the payload with no detection & with defender's all features turned on. No alerts on the MDATP dashboard was generated either.

![USED_Capture9](https://user-images.githubusercontent.com/27059441/77407117-b7a1ae00-6dc6-11ea-9365-340cd36ffd30.PNG)

![USED_Screenshot_2020-03-23_06-29-31](https://user-images.githubusercontent.com/27059441/77407136-bff9e900-6dc6-11ea-9f66-8e2d7e0bad13.png)
