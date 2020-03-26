package me.laszloattilatoth.jssh;

import java.net.InetAddress;

public class Config {

    private InetAddress host;
    private int port;
    private int threads;

    private Config(InetAddress host, int port) {
        this.host = host;
        this.port = port;

        threads = 5;
    }

    public static Config create(InetAddress host, int port, String fileName) {

        return new Config(host, port);
    }

    public InetAddress getHostAddress() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public int getThreadCount() {
        return threads;
    }
}
