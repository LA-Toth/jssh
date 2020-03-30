package me.laszloattilatoth.jssh.transportlayer;

import me.laszloattilatoth.jssh.proxy.Packet;

public interface PacketHandler {
    void handle(Packet packet) throws TransportLayerException;
}
