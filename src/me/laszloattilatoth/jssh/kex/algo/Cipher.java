package me.laszloattilatoth.jssh.kex.algo;

public record Cipher(String name, int nameId, long blockSize, long keyLen, long ivLen, long authLen, long flags) {
    // flags are used to map the name to the actual algorithms
    public static int FLAG_CBC = 1;
    public static int FLAG_CHACHAPOLY = 1 << 1; // unused, exists in OpenSSH
    public static int FLAG_AES_CTR = 1 << 2;
    public static int FLAG_3DES = 1 << 3;
    public static int FLAG_AES = 1 << 4;
}
