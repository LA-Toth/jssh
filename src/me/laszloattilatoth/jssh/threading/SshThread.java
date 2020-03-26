package me.laszloattilatoth.jssh.threading;

import me.laszloattilatoth.jssh.Config;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public abstract class SshThread implements Runnable {
    protected final Config config;
    protected final InputStream inputStream;
    protected final OutputStream outputStream;
    protected final Socket socket;

    public SshThread(Config config, Socket s, InputStream is, OutputStream os) {
        this.config = config;
        this.socket = s;
        this.inputStream = is;
        this.outputStream = os;
    }

    public final Socket getSocket() {
        return socket;
    }

    @Override
    public abstract void run();
}
