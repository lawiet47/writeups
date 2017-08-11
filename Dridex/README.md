Merhaba, bugün 2011 de siber dünyasına tanıtılan daha sonra 2015 de 40 milyon dolar değerinde para çalan banking trojan Dridex in kısa bir analizini yapacağım. Dridex 4 senede sürekli değişdiyi için internetdeki örnekler farkındalık oluşturabilir. O yüzden benim elde etdiğim örneğin hash değeri aşağıdadır.

SHA256:	e30b76f9454a5fd3d11b5792ff93e56c52bf5dfba6ab375c3b96e17af562f5fc

NOT: Örnekleri bir çok farklı yolla analiz edebilirsiniz. Benim yöntemlerim uzman yöntemleri olmayabilir. Eğer farklı bir şekilde analiz edebiliyorsanız veya bu örnekten daha fazla bilgi çıkarabiliyorsanız fikirlerinizi bana bildirin :)

NOT2: Türkçem iyi olmayabilir elimden geldiğince doğru yazmaya çalıştım :)

İşi fazla uzatmadan hemen başlayalım. İlk önce Programı çalıştıralım. Process hacker da eğer olayı görüntülersek program çalıştıktan 1 saniye sonra kendi child process ini oluşturup kendini yok ediyor

![birth](https://user-images.githubusercontent.com/27059441/29209375-cfb76be6-7e96-11e7-9418-74a507985601.PNG)

![rebirth](https://user-images.githubusercontent.com/27059441/29209379-d688eac6-7e96-11e7-9d44-66569524a099.PNG)

![destruct](https://user-images.githubusercontent.com/27059441/29209390-e3b11d54-7e96-11e7-8aaa-504c1fd85af7.PNG)

Ayrıca Wireshark ta programın bir ip adresine ulaşmak isteğini görüyoruz

![wiresharkcapt](https://user-images.githubusercontent.com/27059441/29206630-5b576432-7e8b-11e7-9ebb-b9e80723721b.PNG)



Bu teknik malware dünyasında çok popüler bir tekniktir ve ismi Process Hallowing diğe geçer. Bu tekniğin amacı zararlı yazılımın, payload unu kendi içinde packed olarak saklaması ve yeni process oluşturup o process in içine payload un unpacked halini yerleştirerek onun belleğinden çalıştırmasıdır. Bu şekilde malware diske zararlı hiçbir şey yazmayarak gereksiz dikkat çekmiyor. Programı IDA Pro da açınca bazı hatalar alıyoruz

![ida_error](https://user-images.githubusercontent.com/27059441/29206649-6ae86bbc-7e8b-11e7-9cef-55acc31cb8be.PNG)


Programı IDA Pro da açıp biraz dolşınca anlamlı bir şey bulamadığımızı görüyoruz. IAT(Import Address Table) de anlamsız metod isimleri görünce bu programın bahsetdiyimiz tekniği kullandığından emin oluyoruz.


Packed değince akıla ilk gelen şey UPX oluyor. Maalesef Dridex in kullandığı packer algoritması custom bir algoritma, yani malware yazarlarının kendilerinin uyguladığı bir algoritma. Dolayısıyla biz bunu UPX ile çözemeyiz. ExeInfoPe veya PEID uygulamaları ile de bunu doğrulayabiliriz.

![notpacked](https://user-images.githubusercontent.com/27059441/29206673-866cf61e-7e8b-11e7-9e1c-24db17118a97.PNG)


Ama nasıl unpack edeceğiz? Process Hacker dan gördüğümüz gibi kendi child process ini oluşturup onun hafızasına bir şeyler yazıyor. Bunu C++ da Windows API larını kullanarak gerçekleştirmek mümkündür. Program da C++ da yazıldığı için biz bu API metodlarını inceleyebiliriz. "CreateProcessA" metodu yeni process oluşturmak için, "WriteProcessMemory" de belirtilen process in hafızasına belirtilen buffer ın içeriğini yazmak için kullanılır. Genelde Bunun gibi tekniklerde CreateRemoteThread API ayı kullanılıyor ama Bu program kendi child processini oluşturduğu için biz CreateProcessA API ına bakacağız. Şimdi, genel düşünecek olursak bu program kendinin unpack versiyonunu WriteProcessMemory çağrısını kullanarak yeni process in hafızasına yazacaktır. O zaman biz bu cağrıya breakpoint koyarak buffer parametresini inceleyebiliriz. 

![write_buffer](https://user-images.githubusercontent.com/27059441/29206677-93a52806-7e8b-11e7-8e6f-9f48636f7c23.PNG)

![write_buffer2](https://user-images.githubusercontent.com/27059441/29206679-9aabd1ae-7e8b-11e7-9024-9ba655dccc07.PNG)

Gördüğümüz gibi buffer parametresi exe dosyasının DOS imzası olan 0x4d 0x5a baytları (MZ) ile başlıyor. Bu da o demektir ki, yeni processin içine exe dosyası yazılıyor ve bu bizim ilgilendiğimiz unpacked exe olabilir. Bufferı yeni dosyaya kopyalıyoruz. Artık programın unpack versiyonu elimizde.

Şimdi bu programı içindeki string lere göre aratırsak anlamlı hiç bir şey bulamıyoruz. IDA Pro da açınca IAT e bakıyoruz veeeee...


![iat](https://user-images.githubusercontent.com/27059441/29206686-a60ed442-7e8b-11e7-9f8c-3ac435cf898d.PNG)


Peki ne yapacağız? bir programın IAT olmadan bu kadar fonksiyonelliği olabilir mi? Tabii ki de hayır. Programın çalışması için bu API lara ihtiyacı var. Büyük ihtimal IAT yi kendi içinde bir yerde şifreli bir şekilde tutuyor ve gerekli oldukça deşifreleyerek, gereken metodları çağırıyor. 

Programı IDA Pro da biraz incelersek bir fonksiyon dikkatimizi çekiyor.

![hint_for_decryptor](https://user-images.githubusercontent.com/27059441/29206694-afd73a3c-7e8b-11e7-98d5-26a104b8f79b.PNG)


Bunun Xref(Cross Reference) tablosuna göz atacak olursak bu metodun programın birden fazla yerinde çağrıldığını görüyoruz.

![xrefs_to_decryptor](https://user-images.githubusercontent.com/27059441/29206704-bc238f52-7e8b-11e7-91ef-ed8ae8d09339.PNG)

Bu fonksiyonun nin programda bu kadar sıklıkla kullanılması programda sürekli ihtiyaç duyulan bir fonksiyonelliğin gerçekleştirilmesinden haber veriyor olabilir. Mesela, API ları deşifrelemek? Belki de bahsetdiyimiz API deşifreleme metodu budur? Bilmiyorum, bakalım.

![decryptor](https://user-images.githubusercontent.com/27059441/29206716-cb8c4682-7e8b-11e7-8cc1-4359b40b4336.PNG)

Bu metodun içine bakacak olursak çok büyük olmadığını ve toplamda 2 fonksiyon çağrısının yapıldığı görebiliriz. bunlardan ilkinin içeriğine
bakacak olursak, deşifreleme ile ilgili bir kalıp görmüyoruz. Ama 2 ci cağrıya bakarsak içinde bir offsetin push edildiğini ve farklı bir metodun çağrıldığını görüyoruz.

![decryptor_call](https://user-images.githubusercontent.com/27059441/29206721-d8edf884-7e8b-11e7-8d31-f0a96369699e.PNG)

![encryptedtext](https://user-images.githubusercontent.com/27059441/29206731-e96c4e86-7e8b-11e7-97bc-cfcb1c47fa5f.PNG)


Offset e bakacak olursak bir sürü anlamsız yazı görüyoruz Bunun bizim aradığımız IAT olma ihtimali var. Buraya bir breakpoint koyup devamlı şekilde çalıştırdığımızda RAM de anlamlı yazılar görmeye başlıyoruz.

![iointerconnect](https://user-images.githubusercontent.com/27059441/29206747-f4f01e18-7e8b-11e7-870b-c69250b6f6ef.PNG)


Bu yazılar Windows API metodları. Demek bu şifreli Text bizim aradığımz IAT imiş. bu metodu incelediğimiz de ebx ve esi register larına parametremiz olan şifreli IAT textinin atandığını görüyoruz. Bu metodun IAT deşifreleme metodu olduğunu görmeye başlıyoruz. biraz daha incelediğimiz de bu şifreli Text in ilk 8 baytını ebx ve ebp register larına atandığını, sonra da eax ve edi register larında olan değerler le XOR landığını görüyoruz. XOR landıktan sonra ebx ve ebp registerlarındaki değerler stack de bir yere atanıyor

![decryption_route](https://user-images.githubusercontent.com/27059441/29206762-01f5d0d0-7e8c-11e7-9500-15b8fc979484.PNG)


Stack deki yeri takip edersek...

![decryptedtext](https://user-images.githubusercontent.com/27059441/29206770-0ee33030-7e8c-11e7-983c-761cd3b081ba.PNG)

...istediğimiz API isimlerini göre biliyoruz. Şimdi, ebx ve ebp registerlarını XOR layan değer eax ve edi register larında tutuluyor. Bu değerlere bakacak olursak EAX=76 a8 28 e0; EDI=e6 ac 0d e8 olduğunu görüyoruz.

![ebx_ebp_iat](https://user-images.githubusercontent.com/27059441/29206779-1998e786-7e8c-11e7-9cec-4c4f78e0460a.PNG)


Bundan sonra artık IAT deşifrelemek için kendi metodumuzu yaza biliriz. Ben hızlı ve string manipulasyon u güçlü olduğu için python kullandım ama kolayca başka metodlarla da yapıla bilirdi. Mesela process hacker da deşifreleme işi bitdikten sonra Memory deki stringlere bakıp API ları filtreleyebilirdik. 

![decrypter_script](https://user-images.githubusercontent.com/27059441/29206807-3bfe4b86-7e8c-11e7-917a-d933eb23afee.PNG)


Anahtarı tersten yazmamın sebepi şifreli textin register lara little endian olarak okunması dır. Ben de Textin her 4 baytını tersten yazmak yerine anahtarı tersten yazdım :)

Script i çalıştırdıktan sonra deşifrelenmiş API çağrılarını görebiliyoruz.

![iat_strings](https://user-images.githubusercontent.com/27059441/29206816-486ee182-7e8c-11e7-90e5-209a4d810494.PNG)


Artık programın hangi çağrıları kullandığını görebiliyoruz. Buna çağrılara göre programın farklı yerlerinde breakpoint koyarak analiz yapabiliriz. Programın C&C servera birşey göndermek istediğiniz görüyoruz. Ne olduğunu bulalım. Malware genelde C&C serverla bağlantı kurmak için InternetOpen, HttpSendRequest API larını kullanıyor. Bu programın IAT sinde de bu çağrıları görebiliriz. OllyDbg de bu çağrılarda breakpoint koyarsak zaman aralıklarıyla 4 farklı adrese ulaşılmak istediğini görebiliyoruz. 

![firstipaddr](https://user-images.githubusercontent.com/27059441/29206825-521fa6da-7e8c-11e7-88d6-7841cd5883c4.PNG)

![secndipaddr](https://user-images.githubusercontent.com/27059441/29206832-59b43596-7e8c-11e7-9235-1e9110fc096a.PNG)

![thirdipaddr](https://user-images.githubusercontent.com/27059441/29206841-648df9f2-7e8c-11e7-830c-14fb86f609ae.PNG)

![finalipaddr](https://user-images.githubusercontent.com/27059441/29206848-6bd45346-7e8c-11e7-81ab-3e27f2710a53.PNG)

Bundan sonra Stack de garip bir string görüyoruz.

![weirdkey](https://user-images.githubusercontent.com/27059441/29207351-8bfc7bce-7e8e-11e7-8739-26517f1b6550.PNG)

Henüz ne olduğunu bilmiyoruz. Devam edelim buna sonra döneriz.

HttpSendRequest çağrısında breakpoint da durup buffer parametresine bakacak olursak saçma yazılar görüyoruz. Genelde malware ler C&C server lara request gönderdiğinde şifreli şekilde gönderiyorlar. Bu şifreleme yöntemleri custom veya common olabilir. Ben yine de her zaman bir malware in içinde "Microsoft CryptoAPI" kullanılmış mı diye bakıyorum. IAT dan da gördüğümüz gibi burda kullanılmış, demek ki server a gönderilen data şifreli bir şekilde gönderiliyor. Peki nasıl şifreleniyor? Araştıralım...

Şifrelemede genelde kullanılan CryptCreateHash, CryptHashData, CrytptEncrypt metodlarına breakpoint koyarak analiz yapabilirz.

CryptCreateHash cağrısında Algorithm_ID(2ci parametre) parametresine bakarak 0x8003 değerini görebiliriz. Bu değer Hash metodunun MD5 olduğunu gösteriyor. Bundan sonra CryptHashData metodu çağrılıyor. CryptHashData çağrılmadan önce program registry den bilgisayar ismini, kullanıcı adını ve Install date bilgisi bir diziye okunuyor ve 4 adet null byte(0x00) ekleniyor. Bu "Bilgisayar Ismi+Kullanıcı Adı+install date+4bayt" kombinasyonunu CryptHashData çağrılırken bu metoda parametre olarak verildiğini görebiliriz.

![cryptcreatehash](https://user-images.githubusercontent.com/27059441/29206862-76b9c58e-7e8c-11e7-88c3-b0f0ea8ac02d.PNG)


Bu bilgilerin MD5 hash değerini biz de hesaplaya biliriz.

![manualmd5sum](https://user-images.githubusercontent.com/27059441/29206871-8232abec-7e8c-11e7-951a-f6d19f59ea94.PNG)

Sonra program bilgisayara kurulan programların isimleri RAM de bir offset e yazıyor, burda Bilgisayar a Kurulan programların listesini göre biliyoruz(Bu bilgi "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall" anahtarından çekiliyor). Son olarak biz bu bilgilerden oluşan bir formatta yazıyı RAM de görebiliyoruz

![unencryptedrequest](https://user-images.githubusercontent.com/27059441/29206884-8cb66e78-7e8c-11e7-8af0-68cf9ae8fe26.PNG)



Görüldüğü gibi burdakı hash değeri bizim hesapladığımız MD5 hash değeriyle aynı.

Sonda Bu bilgilerin hepsi şifrelenerek C&C Server a gönderiliyor. Nasıl Şifreliyor peki? Ollydbg da bu bilgi RAM a yazıldıktan sonra biraz ilerlersek, bunun bir fonksiyon çağrılmadan önce stack e push edildiğini göre biliriz. O fonksiyonun içinde biraz dolaşırsak bu bilginin yerleştiyi offsetin saçmalığa dönüştüğünü göre biliriz.

![encrypted_request](https://user-images.githubusercontent.com/27059441/29206896-a0eacfb0-7e8c-11e7-9cd3-0111c9813b97.PNG)

Bu program şifreleme yöntemini kendisi uyguladığı için biz CryptEncrypt e bir çağrı göremiyoruz. Bu yüzden şifreleme yöntemini aramak biraz uzun sürecek. Ama hatırlarsak stack te garip bir string görmüştük. Malware ler genelde şifrelemede uygulanması kolay ve hızlı olduğu için RC4 metodunu kullanıyorlar. Ben bundan yola çıkarak RAM de gördüğümüz şifrelenmiş buffer ı gördüğümüz string i anahta olarak kullanarak deşifreledim ve sonuç bu çıktı...

![decrypted__rc4_request](https://user-images.githubusercontent.com/27059441/29206903-a99dbf82-7e8c-11e7-8d63-c1ec866e5b4d.PNG)

Burda çıkan sonuç bufferın şifrelenmeden önceki halinin aynısı. Demek malware şireleme yöntemi olarak RC4 ve anahtar olarak "Yhc3XUIiv2rNzgy968TWCcx6PjBvLnuyT0ofNA9lvif8EIoZrLshPJ2kYi1WFXMDsuihGkT" string ini kullanıyor.



serverdan sonraki komutlar için cevap bekleniyor. Maalessef Dridex in server ları offline olduğu için serverdan nasıl bir cevap geldiğini ve ondan sonra programın neler yaptığını bilmiyorum :)

Buraya kadar gelmişken stringleri de deşifrelemeye çalışalım :) String lerin de IAT gibi şifrelendiğini ve çalışma zamanında deşifrelenip kullanılmalarının ihtimali büyük.
Assembly kodunda biraz daha dolaşırsak bir fonksiyona rastlıyoruz.

![string_decryptor_hint](https://user-images.githubusercontent.com/27059441/29206914-b76d7bc0-7e8c-11e7-9ea0-eba0de2e7008.PNG)


Bu fonksiyonun içinde başka bir fonksiyon çağrılıyor Ve bu kalıp bize bir yerden tanıdık geliyor...

![strin_decrypto_call](https://user-images.githubusercontent.com/27059441/29206927-c03e8e2e-7e8c-11e7-8ec6-381021dc4575.PNG)


burdaki fonksiyon aynen IAT yi deşifrelemek için çağrılan fonksiyon kalıbında, öncelikle bir şifreli offset push ediliyor daha sonra deşifreleme işlemi başlıyor. Offset e bakacak olursak beklediğimiz gibi anlaşılmaz yazılarla karşılaşıyoruz.

![encryptedstrings](https://user-images.githubusercontent.com/27059441/29206937-caa898c8-7e8c-11e7-8273-0a035af29d4a.PNG)

![same_pattern_string_decrypto](https://user-images.githubusercontent.com/27059441/29206948-d725a258-7e8c-11e7-808c-f25afc309cca.PNG)

Gördüğümüz gibi burda da stringler XOR lanıyor ve XOR işlemi için 2 anahtar var. Burda IAT deşifrelemesindeki adımlar tekrarlandığı için detayları yazmayacağım, kısacası ordaki adımları tekrarlayarak stringler deşifrelenebilirler. Burdaki tek fark XOR için kullanılan anahtarların değişmesidir.Ilk başta anahtarlar uygun olarak Anahtar1=0xb0 0x65 0x30 0xfd, Anahtar2=0xf7 0xd6 0xf0 0x8b olarak atanır. Ama belirli bir offsetden sonra Anahtar1=0xdd 0x57 0x86 0xa1, Anahtar2=0x49 0x40 0x60 0xc4 olarak değiştirilir. Bunlardan ilk anahtar çifti programın kullandığı dll leri 2ci anahtar çifti ise programın içine gömülmüş windows komutları deşifrelemek için kullanılır.

Ben yine de python scriptleri kullanarak bunları çözmeye çalıştım. 

![string_decryptor_script](https://user-images.githubusercontent.com/27059441/29206959-e06aeae4-7e8c-11e7-8c8b-b07a061b4fff.PNG)

Çalıştırıldıktan sonra çıktı...

![decrypted_strings_libraries](https://user-images.githubusercontent.com/27059441/29206961-e9ccfafa-7e8c-11e7-9a6d-52885f0ce120.PNG)

Yukarıdaki çıktı 1ci anahtar çifti kullanılarak çözülen dll ler, Aşağıdaki ise 2ci anahtar çifti kullanılarak çözülen komutlardır.

![decrypted_strings_commands](https://user-images.githubusercontent.com/27059441/29206972-f5143cb6-7e8c-11e7-8af2-09e9e965e9ab.PNG)

Burdaki komutlar biraz karışık olsa da programın ne yapmak istediğini bulabliriz. sdbinst.exe komutu /q /u "%S" parametleri ile çalıştığını görüyoruz. burda program "%S" parametresindeki bir .sdb dosyasını silmeye çalışmış. .sdb dosyaları windows registry si hakkında detaylı bilgi tutan database dosyalarıdır. Internetde biraz araştırma yapınca bunun aslında UAC bypass tekniği olduğunu öğrendim. Yani Dridex normal kullanıcı yetkileriyle bile çalıştırılsa bile kullanıcının haberi olmadan Admin yetkilerine sahip olabiliyor.


IDA Pro da programı biraz daha inceledim ve string deşifreleme metodu bir kaç yerde çağrıldığını gördüm. Belki de daha fazla stringler çıkarılabilir. Ama Programın içinde Sleep çağrıldığı için uzun bir süre beklemem lazımdı Sleep e atanan parametre yi de değiştiremediğim için vaz geçtim :) Eğer farklı stringler bulursanız yöntemini paylaşın :)




