package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.proxy.Packet;
import me.laszloattilatoth.jssh.proxy.Side;
import me.laszloattilatoth.jssh.transportlayer.TransportLayer;

import java.lang.ref.WeakReference;

public class KeyExchange {
    private final WeakReference<TransportLayer> transportLayer;
    private final Side side;
    private Config config;

    public KeyExchange(TransportLayer transportLayer) {
        this.transportLayer = new WeakReference<>(transportLayer);
        this.config = transportLayer.getConfig();
        this.side = transportLayer.side;
    }

    public void processMsgKexInit(Packet packet) {

    }
}
