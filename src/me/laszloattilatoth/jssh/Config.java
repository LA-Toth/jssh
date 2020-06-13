package me.laszloattilatoth.jssh;

import java.net.InetAddress;
import java.util.Map;

public class Config {
    private final InetAddress host;
    private final int port;
    private final int threads;
    private final String hostKeyDir;

    private final Map<String, String> configMap = Map.of(
            "client_kex_algorithms", "diffie-hellman-group14-sha1",
            "client_hostkey_algorithms", "ssh-rsa",
            "client_encryption_algorithms", "aes128-ctr",
            "client_mac_algorithms", "hmac-sha1",
            "client_compression_algorithms", "none"
    );

    private Config(InetAddress host, int port) {
        this.host = host;
        this.port = port;

        threads = 5;
        hostKeyDir = "d:\\ssh";
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

    public String getHostKeyDir() {
        return hostKeyDir;
    }

    public String getValue(String key) {
        return configMap.getOrDefault(key, null);
    }
}
