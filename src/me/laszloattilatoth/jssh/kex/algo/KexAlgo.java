package me.laszloattilatoth.jssh.kex.algo;

public record KexAlgo(String name, int nameId, Digest digestId) {
    public enum Digest {
        SHA1,
    }
}
