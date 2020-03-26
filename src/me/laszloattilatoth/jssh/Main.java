package me.laszloattilatoth.jssh;

import org.apache.commons.cli.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Main {
    public static void main(String[] args) {
        Options options = new Options();
        String host = "127.0.0.1";
        int port = 2222;

        options.addOption("b", "bind", true, "Bind address (IPv4)");
        options.addOption("p", "port", true, "Port number");
        options.addOption(Option.builder("c").longOpt("config").hasArg().desc("Configuration file name").build());
        options.addOption(Option.builder("h").longOpt("help").desc("Print help").build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            e.printStackTrace();
            System.exit(1);
        }

        if (cmd.hasOption('h') || cmd.hasOption('f')) {
            String header = "An SSH proxy";
            String footer = "\nPoC";

            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("jssh", header, options, footer, true);
            System.exit(0);
        }

        if (cmd.hasOption('b'))
            host = cmd.getOptionValue('b');

        if (cmd.hasOption('p')) {
            try {
                port = Integer.parseInt(cmd.getOptionValue('p'));
                if (port < 1 || port > 65535) {
                    System.out.println("The specified port is not in 1..65535 range");
                    System.exit(1);
                }
            } catch (NumberFormatException e) {
                System.out.println("Specified port number is not an integer");
                System.exit(1);
            }
        }

        System.out.println(host);
        System.out.println(port);


        InetAddress address = null;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println(address);
        JSsh ssh = new JSsh(Config.create(address, port, cmd.getOptionValue('c')));


        System.exit(ssh.run());
    }
}
