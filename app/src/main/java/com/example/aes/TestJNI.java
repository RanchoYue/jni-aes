package com.example.aes;

public class TestJNI {

    static {
        System.loadLibrary("native-lib");
    }

    public static native void log();

    public native String encrypt(String plainText);

    public native String decrypt(String cipherText);

    public native String getKeyValue();

    public native String getIv();

}
