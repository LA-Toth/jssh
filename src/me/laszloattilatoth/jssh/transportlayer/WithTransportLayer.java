package me.laszloattilatoth.jssh.transportlayer;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.kex.KexException;
import me.laszloattilatoth.jssh.proxy.Constant;
import me.laszloattilatoth.jssh.proxy.Packet;
import me.laszloattilatoth.jssh.proxy.Side;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Objects;
import java.util.logging.Logger;

public class WithTransportLayer {
    protected final WeakReference<TransportLayer> transportLayer;
    protected final Side side;
    protected final Config config;
    protected final Logger logger;

    public WithTransportLayer(TransportLayer transportLayer) {
        this.transportLayer = new WeakReference<>(transportLayer);
        this.side = transportLayer.side;
        this.config = transportLayer.getConfig();
        this.logger = transportLayer.getLogger();
    }

    protected void sendDisconnectMsg(long reasonCode, String reason) throws TransportLayerException {
        sendSingleDisconnectMsg(Objects.requireNonNull(transportLayer.get()), reasonCode, reason);
        // TODO: terminate other side, too
    }

    private void sendSingleDisconnectMsg(TransportLayer t, long reasonCode, String reason) throws TransportLayerException {
        Packet packet = new Packet();
        try {
            packet.writeByte(Constant.SSH_MSG_DISCONNECT);
            packet.writeUint32(reasonCode);
            packet.writeString(reason);
            packet.writeString("");
        } catch (Packet.BufferEndReachedException e) {
            logger.severe(() -> String.format("Unable to create SSH_MSG_DISCONNECT message; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }

        try {
            t.writePacket(packet);
        } catch (IOException e) {
            logger.severe(() -> String.format("Unable to send (write) SSH_MSG_DISCONNECT message; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }
    }
}
