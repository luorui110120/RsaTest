package com.rsa;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TestMain {

    //base64 code
    static String PUCLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCirCjklIMkAxmJG0z4LHC9e2IE4C1r8jM/QpYt3NRhgrz/SDrOYyA1Rga++na3b5STpWA1Mh25XXkiTgE2a49LmcLPgVEsSqxZguCYQ/KmCOS4FVGzt9K4i1a52ins577D/eK+hu1A2JrxAUicO7tZ7MESn4Kq8imPMP81gHTY6QIDAQAB";
    static String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKKsKOSUgyQDGYkbTPgscL17YgTgLWvyMz9Cli3c1GGCvP9IOs5jIDVGBr76drdvlJOlYDUyHbldeSJOATZrj0uZws+BUSxKrFmC4JhD8qYI5LgVUbO30riLVrnaKeznvsP94r6G7UDYmvEBSJw7u1nswRKfgqryKY8w/zWAdNjpAgMBAAECgYEAkquLS12kSEoLMhXNdk4LcKzYmfDOw29jSXxuD/f1/d11Lu8fJos1tRLobjVB6O7QFbecYRpItqNS3t1aNokQbvSD6uvGJb+n2KcOAx+RS6alwJEA3qjoVOdsW65Wt0WtNv1k+t1a9M2pO4dw0/ksB7901fdAf5SySPD+OZRV8+kCQQDo5hjr0Yu0Lu+vVdkkO2dKHSnCfWCY3WOE0GW29hn/c2E6X69+p5UxTSowiB/M3tcUAiITgbyu49Ddl7A8ZBy/AkEAss7VsRdU79EJGQw26D4FHcGkLnLUlPfI+mxbClDIe2TQXsIlSCzqJlH5T4hvtFx+f8qAO+nRdvMXjMKMyNHsVwJALgCtMX9NegS/YUGyx15Yc6I5CmqbdvZb3vMO9Em+LuAKd25JCtptNLTKPZXVujDWCOS2+GVq8JydN/frXrJjnwJBAIkUnqjkjT5JkGL+hT2pBn0Yjkj5ydXm3NJ3rZgL9Jb84+4xgymBHYWBRNPfclvgqS5JTeQgznAVz5EfOZVfsoMCQCL0Zhr8rVpKAI8uiJ8DHhifyzctI0dPuf7kL7P0xVLmEgjp8UwYOXWQ2AU6Mcn1/ZXwowJ/XIqjpkrKEyXtGCc=";

    public static void main(String[] args) throws Exception
    {
        String source = "zxp";
        //InputStream publicIS = new FileInputStream("C:\\rsa_public_key.pem");
        //InputStream privateIS = new FileInputStream("C:\\pkcs8_rsa_private_key.pem");
        PublicKey publicKey = RSAUtils.loadPublicKey(PUCLIC_KEY);
        //PublicKey publicKey = RSAUtils.loadPublicKey(publicIS);
        PrivateKey privateKey = RSAUtils.loadPrivateKey(PRIVATE_KEY);
        //PrivateKey privateKey = RSAUtils.loadPrivateKey(privateIS);
        byte[] b1 = RSAUtils.encryptData(source.getBytes(), publicKey);
        System.out.println(">>>" + new String(RSAUtils.decryptData(b1, privateKey)));


        /// 打印 key
        RSAUtils.printPublicKeyInfo(publicKey);
        RSAUtils.printPrivateKeyInfo(privateKey);


        ///// e,d,n  rsa加密测试
        String strE="10001";
        String strN="8C2706E4081B4A0AD0F8CB97C21343DD";
        String strD="33C9E410F531E84CC4C3CC2F2891701D";
        System.out.println("rsaEncrypt:" + RSAUtils.rsaEncode(source, strD, strN));
        System.out.println("rsaDecrypt:" + RSAUtils.rsaDecode(RSAUtils.rsaEncode(source, strD, strN), strE, strN));


        /// 当对超过 1024字节的数据加密工具类
        String rsabase64 = RSATools.rsaEncryptBase64(source.getBytes(), PUCLIC_KEY);
        System.out.println("rsaEncryptBase64:" + rsabase64);
        System.out.println("rsaDecryptBase64:" + new String(RSATools.rsaDecryptBase64(rsabase64, PRIVATE_KEY)));

        //// 生成新的 key
        KeyPair rsaKeyPair = RSAUtils.generateRSAKeyPair();
        System.out.println("new publickey:"+RSAUtils.getPublicKeyToBase64(rsaKeyPair.getPublic()));
        System.out.println("new Privatekey:"+RSAUtils.getPrivateKeyToBase64(rsaKeyPair.getPrivate()));
    }
}
