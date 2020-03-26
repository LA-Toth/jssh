package me.laszloattilatoth.jssh;

import me.laszloattilatoth.jssh.proxy.SshProxy;
import me.laszloattilatoth.jssh.threading.SshThreadPool;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class JSsh {
    private Config config;

    JSsh(Config config) {
        this.config = config;
    }

    int run() {
        SshThreadPool threadPool = new SshThreadPool(config.getThreadCount());

        try (ServerSocket server = new ServerSocket(config.getPort(), 10, config.getHostAddress())) {
            while (true) {
                threadPool.cleanup();
                if (threadPool.canStartThread()) {
                    try {
                        Socket connection = server.accept();
                        SshProxy proxy = new SshProxy(config, connection, connection.getInputStream(), connection.getOutputStream());
                        threadPool.startThread(proxy);
                    } catch (IOException ex) {
                        // ignore
                    }
                } else {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                    }
                }
            }
        } catch (IOException ex) {
            System.err.println(ex);
            return 1;
        }
    }
}
