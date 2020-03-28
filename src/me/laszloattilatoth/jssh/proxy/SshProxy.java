package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.threading.SshThread;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.logging.Level;

public class SshProxy extends SshThread {
    private TransportLayer transportLayer;

    public SshProxy(Config config, Socket s, InputStream is, OutputStream os) {
        super(config, s, is, os);
        this.transportLayer = new TransportLayer(this, is, os);
    }

    @Override
    public void run() {
        try {
            this.transportLayer.start();
        } catch (TransportLayerException e) {
            logger.severe(String.format("TransportLayerException occurred; message='%s'", e.getMessage()));
            Util.logExceptionWithBacktrace(logger, e, Level.INFO);
        }
    }
}
