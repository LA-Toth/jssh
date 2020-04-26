package me.laszloattilatoth.jssh;

import java.net.InetAddress;
import java.util.Map;

public class Config {

    private final InetAddress host;
    private final int port;
    private final int threads;
    private final Map<String, String> configMap = Map.of(
            "client_kex_algorithms", "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "client_hostkey_algorithms", "ssh-rsa",
            "client_encryption_algorithms", "aes128-ctr,aes192-ctr,aes256-ctr",
            "client_mac_algorithms", "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            "client_compression_algorithms", "none"
    );

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

    public String getValue(String key) {
        return configMap.getOrDefault(key, null);
    }
}
