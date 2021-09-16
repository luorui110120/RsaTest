package com.rsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Utils {
    public static byte[] gzip(byte[] content) throws IOException {
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        GZIPOutputStream gos=new GZIPOutputStream(baos);

        ByteArrayInputStream bais=new ByteArrayInputStream(content);
        byte[ ] buffer=new byte[1024];
        int n;
        while((n=bais.read(buffer))!=-1){
            gos.write(buffer, 0, n);
        }
        gos.flush();
        gos.close();
        return baos.toByteArray();
    }

    public static byte[] unGzip(byte[] content) throws IOException{
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        GZIPInputStream gis=new GZIPInputStream(new ByteArrayInputStream(content));
        byte[] buffer=new byte[1024];
        int n;
        while((n=gis.read(buffer))!=-1){
            baos.write(buffer, 0, n);
        }

        return baos.toByteArray();
    }

    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer(bytes.length);
        String sTemp;
        for (int i = 0; i < bytes.length; i++) {
            sTemp = Integer.toHexString(0xFF & bytes[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }
    public static byte[] hexStringToByte(String hex) {
        int len = (hex.length() / 2);
        byte[] result = new byte[len];
        char[] achar = hex.toCharArray();
        for (int i = 0; i < len; i++) {
            int pos = i * 2;
            result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
        }
        return result;
    }
    private static byte toByte(char c) {
        byte b = (byte) "0123456789ABCDEF".indexOf(c);
        return b;
    }
    public static void logdebug(Object str) {
        Boolean a = true;
        if (a) {
            System.out.println(str);
        }
    }
}
