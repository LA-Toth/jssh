package me.laszloattilatoth.jssh.threading;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public abstract class SshThread implements Runnable {
    private static final AtomicInteger previousSshThreadId = new AtomicInteger();
    protected final Config config;
    protected final InputStream inputStream;
    protected final OutputStream outputStream;
    protected final Socket socket;
    protected final int sshThreadId;
    protected final String name;

    protected final Logger logger;

    public SshThread(Config config, Socket s, InputStream is, OutputStream os) {
        this.config = config;
        this.socket = s;
        this.inputStream = is;
        this.outputStream = os;
        this.sshThreadId = previousSshThreadId.incrementAndGet();
        this.name = "SshThread:" + this.sshThreadId;
        this.logger = createLogger();
    }

    private Logger createLogger() {
        Logger logger = Logger.getLogger(getName());
        logger.setLevel(Util.logLevel);
        return logger;
    }

    public final Config getConfig() {
        return config;
    }

    public final Socket getSocket() {
        return socket;
    }

    public final int getSshThreadId() {
        return sshThreadId;
    }

    public final String getName() {
        return name;
    }

    public final Logger getLogger() {
        return logger;
    }

    @Override
    public abstract void run();
}
