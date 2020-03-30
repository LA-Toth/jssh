package me.laszloattilatoth.jssh.proxy;

public interface PacketHandler {
    void handle(Packet packet) throws TransportLayerException;
}
