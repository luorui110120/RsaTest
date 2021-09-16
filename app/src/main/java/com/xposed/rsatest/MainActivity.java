package com.xposed.rsatest;


import android.app.Activity;
import android.os.Bundle;

import com.rsa.RSATest;
import com.rsa.RSAUtils;
import com.rsa.Utils;

import java.security.PrivateKey;
import java.security.PublicKey;

import static com.rsa.Utils.byteToHexString;


public class MainActivity extends Activity {
    //base64 code
    static String PUCLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfRTdcPIH10gT9f31rQuIInLwe" + "\r"
            + "7fl2dtEJ93gTmjE9c2H+kLVENWgECiJVQ5sonQNfwToMKdO0b3Olf4pgBKeLThra" + "\r"
            + "z/L3nYJYlbqjHC3jTjUnZc0luumpXGsox62+PuSGBlfb8zJO6hix4GV/vhyQVCpG" + "\r"
            + "9aYqgE7zyTRZYX9byQIDAQAB" + "\r";
    static String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ9FN1w8gfXSBP1/" + "\r"
            + "fWtC4gicvB7t+XZ20Qn3eBOaMT1zYf6QtUQ1aAQKIlVDmyidA1/BOgwp07Rvc6V/" + "\r"
            + "imAEp4tOGtrP8vedgliVuqMcLeNONSdlzSW66alcayjHrb4+5IYGV9vzMk7qGLHg" + "\r"
            + "ZX++HJBUKkb1piqATvPJNFlhf1vJAgMBAAECgYA736xhG0oL3EkN9yhx8zG/5RP/" + "\r"
            + "WJzoQOByq7pTPCr4m/Ch30qVerJAmoKvpPumN+h1zdEBk5PHiAJkm96sG/PTndEf" + "\r"
            + "kZrAJ2hwSBqptcABYk6ED70gRTQ1S53tyQXIOSjRBcugY/21qeswS3nMyq3xDEPK" + "\r"
            + "XpdyKPeaTyuK86AEkQJBAM1M7p1lfzEKjNw17SDMLnca/8pBcA0EEcyvtaQpRvaL" + "\r"
            + "n61eQQnnPdpvHamkRBcOvgCAkfwa1uboru0QdXii/gUCQQDGmkP+KJPX9JVCrbRt" + "\r"
            + "7wKyIemyNM+J6y1ZBZ2bVCf9jacCQaSkIWnIR1S9UM+1CFE30So2CA0CfCDmQy+y" + "\r"
            + "7A31AkB8cGFB7j+GTkrLP7SX6KtRboAU7E0q1oijdO24r3xf/Imw4Cy0AAIx4KAu" + "\r"
            + "L29GOp1YWJYkJXCVTfyZnRxXHxSxAkEAvO0zkSv4uI8rDmtAIPQllF8+eRBT/deD" + "\r"
            + "JBR7ga/k+wctwK/Bd4Fxp9xzeETP0l8/I+IOTagK+Dos8d8oGQUFoQJBAI4Nwpfo" + "\r"
            + "MFaLJXGY9ok45wXrcqkJgM+SN6i8hQeujXESVHYatAIL/1DgLi+u46EFD69fw0w+" + "\r" + "c7o0HLlMsYPAzJw="
            + "\r";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String source = "zxp";

        PublicKey publicKey = RSAUtils.loadPublicKey(PUCLIC_KEY);
        PrivateKey privateKey = RSAUtils.loadPrivateKey(PRIVATE_KEY);
        RSAUtils.printPublicKeyInfo(publicKey);
        byte[] b1 = RSAUtils.encryptData(source.getBytes(), publicKey);
        System.out.println("rsa encrypt："+byteToHexString(b1));
        String indata= "96619D9486FDFCD441C05FE1A531FCCDF49FE713182CD33888B329D161B8A51A4676010C4E336806803649695E88F2E8DF901A8237531DF9ADCD5633C97F65667C70EC6B837E8D97C4B16E301B4A05B832ECBA2D052D60FDE37194F87EBE33BEC213B15EA8AC9843F42E08929372C0E05F5BDFF173D06A4D4FA7EA339BDCA40A";
        System.out.println(">>>" + new String(RSAUtils.decryptData(Utils.hexStringToByte(indata), privateKey)));
        try {
            RSATest.main(null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
