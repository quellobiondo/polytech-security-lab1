# polytech-security-lab1
Laboratory 1 - Java security of the course on Privacy and Security 3.0

This project use gradle as build tool.

# Prepare the project for your IDE
```
# IntelliJ Idea
./gradlew idea
# Eclipse
./gradlew eclipse

```

# 1 3DES

SubModule 3DES
```
./gradlew :3DES:run -PappArgs="['-CBC','res/plainText.txt','res/encryptedText.txt','res/decryptedText.txt']"
./gradlew :3DES:run -PappArgs="['-ECB','res/plainText.txt','res/encryptedText.txt','res/decryptedText.txt']"
```

# 2 RSA
SubModule RSA
```
./gradlew :RSA:run -PappArgs="['res/clearText.txt', 'res/signedText.txt', 'res/encryptedText.txt','res/decryptedText.txt']"
```
# 3 Secure session key exchange 
SubModule BobAndAlice
```
./gradlew :BobAndAlice:run -PappArgs="['res/aliceMessage.txt', 'res/bobReceivedMessage.txt']"
```
