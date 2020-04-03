package me.laszloattilatoth.jssh.transportlayer;

import me.laszloattilatoth.jssh.proxy.Side;
import me.laszloattilatoth.jssh.proxy.SshProxy;

import java.io.InputStream;
import java.io.OutputStream;

public class ClientSideTransportLayer extends TransportLayer {
    public ClientSideTransportLayer(SshProxy proxy, InputStream is, OutputStream os) {
        super(proxy, is, os, Side.CLIENT);
    }
}
