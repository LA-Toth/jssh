package me.laszloattilatoth.jssh.transportlayer;

import me.laszloattilatoth.jssh.proxy.*;

import java.io.InputStream;
import java.io.OutputStream;

public class ClientSideTransportLayer extends TransportLayer {
    public ClientSideTransportLayer(SshProxy proxy, InputStream is, OutputStream os) {
        super(proxy, is, os, Side.CLIENT);
    }
}
