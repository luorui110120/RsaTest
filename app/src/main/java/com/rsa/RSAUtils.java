package com.rsa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public final class RSAUtils
{
    private static String RSA = "RSA";
    private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding"; // Android端加密算法,方便 让 android 与java 相互保持一致;


    /**
     * 随机生成RSA密钥对(默认密钥长度为1024)
     *
     * @return
     */
    public static KeyPair generateRSAKeyPair()
    {
        return generateRSAKeyPair(1024);
    }

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength
     *            密钥长度，范围：512～2048<br>
     *            一般1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength)
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥加密 <br>
     * 每次加密的字节数，不能超过密钥的长度值减去11
     *
     * @param data
     *            需加密数据的byte数据
     * @param pubKeys
     *            公钥
     * @return 加密后的byte型数据
     */
    public static byte[] encryptData(byte[] data, PublicKey publicKey)
    {
        try
        {
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            // 编码前设定编码方式及密钥
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 传入编码数据并返回编码结果
            return cipher.doFinal(data);
        } catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用私钥解密
     *
     * @param encryptedData
     *            经过encryptedData()加密返回的byte数据
     * @param privateKey
     *            私钥
     * @return
     */
    public static byte[] decryptData(byte[] encryptedData, PrivateKey privateKey)
    {
        try
        {
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e)
        {
            return null;
        }
    }

    /**
     * 通过公钥byte[](publicKey.getEncoded())将公钥还原，适用于RSA算法
     *
     * @param keyBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getPublicKey(byte[] keyBytes) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 通过私钥byte[]将公钥还原，适用于RSA算法
     *
     * @param keyBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 使用N、e值还原公钥
     *
     * @param modulus
     * @param publicExponent
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getPublicKey(String modulus, String publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        BigInteger bigIntModulus = new BigInteger(modulus);
        BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 使用N、d值还原私钥
     *
     * @param modulus
     * @param privateExponent
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String modulus, String privateExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        BigInteger bigIntModulus = new BigInteger(modulus);
        BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr
     *            公钥数据字符串
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public static PublicKey loadPublicKey(String publicKeyStr)
    {
        try
        {
            byte[] buffer = Base64Utils.decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e)
        {
            Utils.logdebug("无此算法");
        } catch (InvalidKeySpecException e)
        {
            Utils.logdebug("公钥非法");
        } catch (NullPointerException e)
        {
            Utils.logdebug("公钥数据为空");
        }
        return null;
    }

    /**
     * 从字符串中加载私钥<br>
     * 加载时使用的是PKCS8EncodedKeySpec（PKCS#8编码的Key指令）。
     *
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(String privateKeyStr)
    {
        try
        {
            byte[] buffer = Base64Utils.decode(privateKeyStr);
            // X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e)
        {
            Utils.logdebug("无此算法");
        } catch (InvalidKeySpecException e)
        {
            Utils.logdebug("私钥非法");
        } catch (NullPointerException e)
        {
            Utils.logdebug("私钥数据为空");
        }
        return null;
    }

    /**
     * 从文件中输入流中加载公钥
     *
     * @param in
     *            公钥输入流
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public static PublicKey loadPublicKey(InputStream in) throws Exception
    {
        try
        {
            return loadPublicKey(readKey(in));
        } catch (IOException e)
        {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e)
        {
            throw new Exception("公钥输入流为空");
        }
    }

    /**
     * 从文件中加载私钥
     *
     * @param keyFileName
     *            私钥文件名
     * @return 是否成功
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(InputStream in) throws Exception
    {
        try
        {
            return loadPrivateKey(readKey(in));
        } catch (IOException e)
        {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e)
        {
            throw new Exception("私钥输入流为空");
        }
    }

    /**
     * 读取密钥信息
     *
     * @param in
     * @return
     * @throws IOException
     */
    private static String readKey(InputStream in) throws IOException
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null)
        {
            if (readLine.charAt(0) == '-')
            {
                continue;
            } else
            {
                sb.append(readLine);
                sb.append('\r');
            }
        }

        return sb.toString();
    }

    /**
     * 打印公钥信息
     *
     * @param publicKey
     */
    public static void printPublicKeyInfo(PublicKey publicKey)
    {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        Utils.logdebug("----------RSAPublicKey----------");
        Utils.logdebug("N.length=" + rsaPublicKey.getModulus().bitLength());
        Utils.logdebug("N=" + rsaPublicKey.getModulus().toString(16));
        Utils.logdebug("E.length=" + rsaPublicKey.getPublicExponent().bitLength());
        Utils.logdebug("E=" + rsaPublicKey.getPublicExponent().toString(16));
        Utils.logdebug("key:" + Base64Utils.encode(rsaPublicKey.getEncoded()));
    }

    public static String getPublicKeyToBase64(PublicKey publicKey){
        return Base64Utils.encode(publicKey.getEncoded());
    }

    /**
     * 打印私钥信息
     *
     * @param privateKey
     */
    public static void printPrivateKeyInfo(PrivateKey privateKey)
    {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        Utils.logdebug("----------RSAPrivateKey ----------");
        Utils.logdebug("N.length=" + rsaPrivateKey.getModulus().bitLength());
        Utils.logdebug("N=" + rsaPrivateKey.getModulus().toString(16));
        Utils.logdebug("D.length=" + rsaPrivateKey.getPrivateExponent().bitLength());
        Utils.logdebug("D=" + rsaPrivateKey.getPrivateExponent().toString(16));
        Utils.logdebug("key:" + Base64Utils.encode(rsaPrivateKey.getEncoded()));

    }
    public static String getPrivateKeyToBase64(PrivateKey privateKey){
        return Base64Utils.encode(privateKey.getEncoded());
    }

    /////////// 和 c语言通用的 rsa

    //创建密钥对生成器，指定加密和解密算法为RSA
    public String[] Skey_RSA(int keylen){//输入密钥长度
        String[] output = new String[5]; //用来存储密钥的e n d p q
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keylen); //指定密钥的长度，初始化密钥对生成器
            KeyPair kp = kpg.generateKeyPair(); //生成密钥对
            RSAPublicKey  puk = (RSAPublicKey)kp.getPublic();
            RSAPrivateCrtKey prk = (RSAPrivateCrtKey)kp.getPrivate();
            BigInteger e = puk.getPublicExponent();
            BigInteger n = puk.getModulus();
            BigInteger d = prk.getPrivateExponent();
            BigInteger p = prk.getPrimeP();
            BigInteger q = prk.getPrimeQ();

            output[0] = e.toString(16);
            output[1] = n.toString(16);
            output[2] = d.toString(16);
            output[3] = p.toString(16);
            output[4] = q.toString(16);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return output;
    }

    //加密 在RSA公钥中包含有两个整数信息：e和n。对于明文数字m,计算密文的公式是m的e次方再与n求模。   服务端代码
    public static String rsaEncode(String strPlain, String strD, String strN) {
        if (strN.length() % 2 != 0) {
            strN = "0" + strN;
        }
        int rsalen = strN.length() / 2;
        String Strformat = String.format("%%0%dx", rsalen * 2);
        StringBuffer sb = new StringBuffer();
        try {
            BigInteger d = new BigInteger(strD, 16);
            BigInteger n = new BigInteger(strN, 16);
            int len = strPlain.length();
            for (int i = 0; i < len; i += rsalen) {
                String strSub = strPlain.substring(i, i + rsalen > len ? len : i + rsalen);
                String strHex = String.format("%x", new BigInteger(1, strSub.getBytes("UTF-8")));
                //         System.out.println("encode hex[" + strHex.length() + "]:" + strHex);
                BigInteger m = new BigInteger(strHex, 16);
                BigInteger c = m.modPow(d, n);
                sb.append(String.format(Strformat, c));
            }

            return sb.toString();
        } catch (NumberFormatException ex) {
            ex.printStackTrace();
        } catch (UnsupportedEncodingException e1) {
            e1.printStackTrace();
        }

        return null;
    }


    //解密 这个在客户端的代码

    public static String rsaDecode(String strCipher, String strE, String strN){
        if (strN.length() % 2 != 0) {
            strN = "0" + strN;
        }
        int rsalen = strN.length() / 2;
        StringBuffer sbDec = new StringBuffer();
        BigInteger e = new BigInteger(strE, 16);//获取私钥的参数d,n
        BigInteger n = new BigInteger(strN, 16);

        int len = strCipher.length();
        for (int i = 0; i < len; i += rsalen * 2) {
            String strSub = strCipher.substring(i, i + rsalen * 2 > len ? len : i + rsalen * 2);
            BigInteger c = new BigInteger(strSub, 16);
            BigInteger m = c.modPow(e,n);//解密明文

            String strHex = m.toString(16);
            //在hex前面补零
            if (strHex.length() % 2 != 0) {
//		        System.out.println("decode len:" + strHex.length());
                strHex = "0" + strHex;
            }
            //    System.out.println("decode hex[" + strHex.length() + "]:" + strHex);

            for (int j = 0; j < strHex.length(); j += 2) {
                sbDec.append((char)Integer.parseInt(strHex.substring(j, j + 2), 16));
            }
        }

        return sbDec.toString();
    }

}
