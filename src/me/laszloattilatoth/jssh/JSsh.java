package me.laszloattilatoth.jssh;

import me.laszloattilatoth.jssh.proxy.SshProxy;
import me.laszloattilatoth.jssh.threading.SshThreadPool;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JSsh {
    private Config config;
    private Logger logger;

    JSsh(Config config) {
        this.config = config;
        this.logger = Logger.getGlobal();
    }

    int run() {
        logger.info(() -> "Starting JSSH;");
        SshThreadPool threadPool = new SshThreadPool(config.getThreadCount());
        int result;

        try (ServerSocket server = new ServerSocket(config.getPort(), 10, config.getHostAddress())) {
            while (true) {
                threadPool.cleanup();
                if (threadPool.canStartThread()) {
                    Socket connection = null;
                    try {
                        connection = server.accept();
                    } catch (IOException ex) {
                        Util.logExceptionWithBacktrace(logger, ex, Level.SEVERE);
                        continue;
                    }
                    try {
                        SshProxy proxy = new SshProxy(config, connection, connection.getInputStream(), connection.getOutputStream());
                        threadPool.startThread(proxy);
                    } catch (Throwable e) {
                        Util.logThrowable(logger, e, Level.INFO);
                    }
                } else {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                    }
                }
            }
        } catch (IOException ex) {
            Util.logExceptionWithBacktrace(logger, ex, Level.SEVERE);

            result = 1;
        }
        logger.info(() -> String.format("Ending JSSH; return_value='%d'", result));
        return result;
    }
}
