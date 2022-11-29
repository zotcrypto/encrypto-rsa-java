![Visitor Badge](https://visitor-badge.laobi.icu/badge?page_id=encrypto-rsa-java)

# About Project
End to End encryption (RSA) for multiple languages (cross-platform) with [double encryption](https://www.ssdd.dev/ssdd/zot/crypto/posts/rsa#doubleenc) and [double decryption methods](https://www.ssdd.dev/ssdd/zot/crypto/posts/rsa#doubledec)

| Icon |             Item              |
|:----:|:-----------------------------:|
|  🥳  |   [**Upcoming**](#Upcoming)   |
|  ⚖️  |    [**License**](#License)    |
|  📝  | [**ChangeLog**](CHANGELOG.md) |

# Usage (rust)

## Implementation
### Maven
```xml
<dependency>
  <groupId>dev.ssdd</groupId>
  <artifactId>zot_encrypto_rsa</artifactId>
  <version>0.1.0</version>
</dependency>
```

### Gradle
```java
implementation 'dev.ssdd:zot_encrypto_rsa:0.1.0'
```

## RSA


### Documentation will be published soon at our [website](https://www.ssdd.dev/zot/crypto/rsa/java)

## You can try:

```java
        EncryptoRSA rsa = EncryptoRSA.init(128);
        EncryptoRSA rsa1 = EncryptoRSA.init(128);
        byte[] msg = "abc".getBytes();
        try {
            String enc = rsa.encrypt(msg, rsa1.getZotPublicKey());
            byte[] dec = rsa1.decrypt(enc);
            assertEquals(Arrays.toString(msg), Arrays.toString(dec));

            String enc1 = rsa.encryptPkcsv1_15(msg, rsa1.getZotPublicKey());
            byte[] dec1 = rsa1.decryptPkcsv1_15(enc1);
            assertEquals(Arrays.toString(msg), Arrays.toString(dec1));

            String enc2 = rsa.doubleEncrypt(msg, rsa1.getZotPublicKey());
            byte[] dec2 = rsa1.doubleDecrypt(enc2, rsa.getZotPublicKey());
            assertEquals(Arrays.toString(msg), Arrays.toString(dec2));

            String enc3 = rsa.doubleEncryptPkcsv1_15(msg, rsa1.getZotPublicKey());
            byte[] dec3 = rsa1.doubleDecryptPkcsv1_15(enc3, rsa.getZotPublicKey());
            assertEquals(Arrays.toString(msg), Arrays.toString(dec3));

        } catch (MessageTooBigException e) {
            throw new RuntimeException(e);
        }
```

### Please raise an issue [here](https://github.com/zotcrypto/encrypto-rsa-java/issues) if the documentation isn't uploaded in long time

## Upcoming

| Supported Languages | Status              |
|---------------------|---------------------|
| Flutter             | Priority: Less      |
| Java                | Priority: Very high |
| JavaScript          | Priority: High      |

* Amazing encrypto with prevention against man in the middle attacks and AES-CBC with RSA key exchange for multiple language

## License

### Click [here](LICENSE.md)
