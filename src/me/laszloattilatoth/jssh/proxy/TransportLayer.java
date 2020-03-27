package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import org.apache.commons.codec.binary.Hex;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Based on RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol
 */
public class TransportLayer {
    private Config config;
    private DataInputStream dataInputStream = null;
    private DataOutputStream dataOutputStream = null;

    protected BufferedInputStream inputStream;
    protected BufferedOutputStream outputStream;

    private int macLength = 0;

    public TransportLayer(Config config, InputStream is, OutputStream os) {
        this.config = config;
        this.inputStream = new BufferedInputStream(is);
        this.outputStream = new BufferedOutputStream(os);
    }


    /**
     * Starts the layer, aka. send / receive SSH-2.0... string
     */
    public void start() throws TransportLayerException {
        writeVersionString();
        readVersionString();

        this.dataInputStream = new DataInputStream(this.inputStream);
        this.dataOutputStream = new DataOutputStream(this.outputStream);

        try {
            byte[] packet = readPacket();
            System.out.println(Hex.encodeHex(packet));
            printBytes(packet);
        } catch (IOException e) {
            e.printStackTrace();
            throw new TransportLayerException("Unable to read packet");
        }
    }

    private void writeVersionString() {
        try {
            Writer out = new OutputStreamWriter(outputStream);
            out.write("SSH-2.0-JSSH\r\n");
            out.flush();
            this.outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void readVersionString() throws TransportLayerException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));

        try {
            String idString = reader.readLine();
            while (!idString.startsWith("SSH-"))
                idString = reader.readLine();

            System.out.println("Remote ID String: " + idString);

            if (!idString.startsWith("SSH-2.0")) {
                System.out.println("Unsupported SSH protocol");
                throw new TransportLayerException("Unsupported SSH protocol");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] readPacket() throws IOException {
        int packetLength = dataInputStream.readInt();
        byte paddingLength = dataInputStream.readByte();

        byte[] result = dataInputStream.readNBytes(packetLength - paddingLength - 1);
        dataInputStream.readNBytes(paddingLength);
        if (macLength > 0)
            dataInputStream.readNBytes(macLength);

        return result;
    }

    private long readUint32() throws IOException {
        long ch1 = dataInputStream.read();
        long ch2 = dataInputStream.read();
        long ch3 = dataInputStream.read();
        long ch4 = dataInputStream.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + ch4);
    }

    private void printBytes(byte[] bytes) {
        int offset = 0;
        while (offset < bytes.length) {
            System.out.print(String.format("%04x: ", offset));
            for (int i=0;i!=16;++i) {
                if (offset + i < bytes.length)
                System.out.print(String.format("%02x ", bytes[offset+i]));
                else
                    System.out.print("   ");
            }

            System.out.print(" ");
            for (int i=0;i!=16;++i) {
                int idx = offset +i;
                if (idx < bytes.length) {
                    if (bytes[idx] >= 32 && bytes[idx] <= 126)
                    System.out.print(String.format("%c", bytes[idx]));
                    else
                        System.out.print(".");
                }


            }
            System.out.println();
            offset += 16;
        }
    }

}
