package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.transportlayer.TransportLayerException;

public class KexException extends TransportLayerException {
    public KexException(String s) {
        super(s);
    }
}
