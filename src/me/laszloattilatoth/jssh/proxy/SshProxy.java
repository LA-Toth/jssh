package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.threading.SshThread;

import java.io.*;
import java.net.Socket;
import java.util.Date;

public class SshProxy extends SshThread {
    private TransportLayer transportLayer;
    public SshProxy(Config config, Socket s, InputStream is, OutputStream os) {
        super(config, s, is, os);
        this.transportLayer = new TransportLayer(config, is, os);
    }

    @Override
    public void run() {
        try {
            this.transportLayer.start();
        } catch (TransportLayerException e) {
            e.printStackTrace();
        }
    }
}
