package com.rsa;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSATools
{
    //base64 code 默认的key,方便测试;
    static String PUCLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCirCjklIMkAxmJG0z4LHC9e2IE4C1r8jM/QpYt3NRhgrz/SDrOYyA1Rga++na3b5STpWA1Mh25XXkiTgE2a49LmcLPgVEsSqxZguCYQ/KmCOS4FVGzt9K4i1a52ins577D/eK+hu1A2JrxAUicO7tZ7MESn4Kq8imPMP81gHTY6QIDAQAB";
    static String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKKsKOSUgyQDGYkbTPgscL17YgTgLWvyMz9Cli3c1GGCvP9IOs5jIDVGBr76drdvlJOlYDUyHbldeSJOATZrj0uZws+BUSxKrFmC4JhD8qYI5LgVUbO30riLVrnaKeznvsP94r6G7UDYmvEBSJw7u1nswRKfgqryKY8w/zWAdNjpAgMBAAECgYEAkquLS12kSEoLMhXNdk4LcKzYmfDOw29jSXxuD/f1/d11Lu8fJos1tRLobjVB6O7QFbecYRpItqNS3t1aNokQbvSD6uvGJb+n2KcOAx+RS6alwJEA3qjoVOdsW65Wt0WtNv1k+t1a9M2pO4dw0/ksB7901fdAf5SySPD+OZRV8+kCQQDo5hjr0Yu0Lu+vVdkkO2dKHSnCfWCY3WOE0GW29hn/c2E6X69+p5UxTSowiB/M3tcUAiITgbyu49Ddl7A8ZBy/AkEAss7VsRdU79EJGQw26D4FHcGkLnLUlPfI+mxbClDIe2TQXsIlSCzqJlH5T4hvtFx+f8qAO+nRdvMXjMKMyNHsVwJALgCtMX9NegS/YUGyx15Yc6I5CmqbdvZb3vMO9Em+LuAKd25JCtptNLTKPZXVujDWCOS2+GVq8JydN/frXrJjnwJBAIkUnqjkjT5JkGL+hT2pBn0Yjkj5ydXm3NJ3rZgL9Jb84+4xgymBHYWBRNPfclvgqS5JTeQgznAVz5EfOZVfsoMCQCL0Zhr8rVpKAI8uiJ8DHhifyzctI0dPuf7kL7P0xVLmEgjp8UwYOXWQ2AU6Mcn1/ZXwowJ/XIqjpkrKEyXtGCc=";




    public static String rsaEncryptBase64(byte[] inbytes){
        return rsaEncryptBase64(inbytes, PUCLIC_KEY);
    }
    public static String rsaEncryptBase64(byte[] inbytes, String publicStr){

        PublicKey publicKey = RSAUtils.loadPublicKey(publicStr);
        String md5Hex = MD5Utils.md5Hex(inbytes);
        md5Hex = md5Hex.substring(0, md5Hex.length()/2);
        AESUtils aes = new AESUtils(md5Hex);
        byte[] b1 = RSAUtils.encryptData(md5Hex.getBytes(), publicKey);
        byte[] outbytes = Utils.intToByteArray(b1.length);
        outbytes = Utils.byteMerger(outbytes, b1);
        byte[] aes_endata = aes.encryptData(inbytes);
        outbytes = Utils.byteMerger(outbytes, aes_endata);
        return Base64Utils.encode(outbytes);


    }

    public static byte[] rsaDecryptBase64(String base64Data){
        return rsaDecryptBase64(base64Data, PRIVATE_KEY);
    }
    public static byte[] rsaDecryptBase64(String base64Data, String privateStr){
        PrivateKey publicKey = RSAUtils.loadPrivateKey(privateStr);
        byte[] endataBytes = Base64Utils.decode(base64Data);
        int rsaEndataLen = Utils.byteArrayToInt(endataBytes);
        byte[] rsaEndataBytes = Utils.subByte(endataBytes, 4, rsaEndataLen);
        byte[] aesEndataBytes = Utils.subByte(endataBytes, 4 + rsaEndataLen, endataBytes.length - 4 - rsaEndataLen);
        String md5Hex =  new String(RSAUtils.decryptData(rsaEndataBytes, publicKey));
        AESUtils aes = new AESUtils(md5Hex);

        byte[] aesDedataBytes = aes.decryptData(aesEndataBytes);
        if(null != aesDedataBytes){
            String newMd5Hex = MD5Utils.md5Hex(aesDedataBytes);
            newMd5Hex = newMd5Hex.substring(0, newMd5Hex.length()/2);
            if(newMd5Hex.equals(md5Hex)){
                return aesDedataBytes;
            }
        }
        return null;
    }


}