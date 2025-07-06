# Portfolio

1)  ## Simple password manager 
Allows users to create accounts, log in, and checks the strength of passwords. uses argon2 library for hashing passwords and JSON for storage. I included this one because I think that argon2 is neat, especially because it is much more resistant than sha2 type hashing to decryption attacks through some interesting techniques like parallelism to basically load the cpu, gpu, ram and the other parts of a cracking rig.
[Link](https://github.com/364UD/Portfolio/blob/main/passgen-checker.py)


2) ## Basic network traffic monitor
This script is a minimal packet analyzer (only the basic protocols tcp and udp), as well as some encryption detection and collects the statistics at the end of the runtime. I aim to use this miniature project as a sort of framework/initial code, as I someday do want to make a wireshark-like massive project, maybe in C (depending on available libraries in C, because python has very well functioning libraries) , although currently its' low level system programming interactions with network interfaces and kernel drivers as well as their buffers make it difficult for me to understand well. I am currently learning more protocols as well as their structure so that destination nic card knows how to read and process them, starting with TCP and UDP. 
[Link](https://github.com/364UD/Portfolio/blob/main/BNTM.py)



3) ## Very Simple WHOIS lookup client
uses the socket library to query the whois server to grab basic registration details on domain names, validators library makes sure its formatted properly as most people (including me) usually do not type in https://... in full, instead just typing the domain name for example google.com. Uses port 43 to connect to the whois protocol server   
[Link](https://github.com/364UD/Portfolio/blob/main/Whois_Query.py)




## Why im interested in cryptography (Extra information):

The process of encryption often involves modular arithmetic, due to its nature in being non-linear, making it harder to decrypt information encrypted using a process involving modular arithmetic. In the case of RSA, using 2 hilariously large prime numbers in asymmetric key encryption, or in the case of ECC, using elliptic curves and their nature of being very, very odd. Since elliptic curves were used in tandem with modular arithmetic in ECC, but also being key in solving fermat's last theorem (elliptic curves over rationals Q and modular fields), it got me interested in the relationship between elliptic curves and modular arithmetic as to why they got along together. However I found the reasons elliptic curves and modular arithmetic were used together to be very different in these 2 situations.

From here I discovered the elliptic curve discrete logarithm problem (ECDLP) -> although my understanding of it is not as high level as someone who studies the field of cryptography, I think its very interesting due to its "trapdoor" nature, in where its extremely hard to reverse without specific secret information, which in the case of elliptic curve cryptography, a point on the curve when an elliptic curve is bounded by a prime field Fp (again a hilariously big prime number p that cant be brute forced, about 256 bits which is 10^77, quite funny).

As quantum computers are (probably) going to start becoming practical soon, ECC and especially RSA, will soon become defunct and be easily broken by the sheer computational power of quantum computers. After reading up on how cryptography will be affected in the quantum world, I have heard of a proprosed* encryption method to counter this, known as supersingular isogeny graphs. most elliptic curves are basic/normal, whereas some are "supersingular" (have special algebraic properties) and an isogeny is a type of morphism between 2 elliptic curves. This is as far as my understanding goes due to its extremely, extremely difficult nature of understanding and extremely high intelligence required in order to even propose a type of key exchange encryption using the properties of these elliptic curves bounded with these conditions, however I am very interested in seeing the future of cryptography and cybersecurity as a whole with the advent of practical quantum computer usage.

I am currently interested in learning what isomorphisms/cyclic groups are, though these are very hard to visualize and understand properly, at least at my age and level of mathematical understanding.
