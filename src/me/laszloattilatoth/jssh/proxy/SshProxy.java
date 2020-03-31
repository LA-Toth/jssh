package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.threading.SshThread;
import me.laszloattilatoth.jssh.transportlayer.ClientSideTransportLayer;
import me.laszloattilatoth.jssh.transportlayer.TransportLayer;
import me.laszloattilatoth.jssh.transportlayer.TransportLayerException;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.logging.Level;

public class SshProxy extends SshThread {
    private TransportLayer transportLayer;

    public SshProxy(Config config, Socket s, InputStream is, OutputStream os) {
        super(config, s, is, os);
        this.transportLayer = new ClientSideTransportLayer(this, is, os);
    }

    @Override
    public void run() {
        logger.info(String.format("Starting proxy instance; client_address='%s:%d', client_local='%s:%d'",
                socket.getInetAddress().getHostAddress(), socket.getPort(),
                socket.getLocalAddress().getHostAddress(), socket.getLocalPort()));
        try {
            this.main();
        } catch (TransportLayerException e) {
            logger.severe(String.format("TransportLayerException occurred; message='%s'", e.getMessage()));
            Util.logExceptionWithBacktrace(logger, e, Level.INFO);
        } finally {
            logger.info("Ending proxy instance;");
        }
    }

    private void main() throws TransportLayerException {
        this.transportLayer.start();
    }

    public void shouldQuit() {}
}
