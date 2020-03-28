package me.laszloattilatoth.jssh;

import me.laszloattilatoth.jssh.threading.SshThreadPool;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Util {
    public static final String LOG_FORMAT = "%1$tY:%1$tm:%1$tdT:%1$tH:%1$tM:%1$tS%1$tz %3$s [%4$-7s] %5$s%n";
    public static Level logLevel = Level.ALL;

    public static String threadName() {
        return Thread.currentThread().getName();
    }

    public static Logger sshLogger() {
        return ((SshThreadPool.SshThreadPoolThread) Thread.currentThread()).logger();
    }

    public static void logBytes(Logger logger, byte[] bytes) {
        if (!logger.isLoggable(Level.FINE))
            return;

        int offset = 0;
        while (offset < bytes.length) {
            StringBuilder builder = new StringBuilder();
            builder.append(String.format("data line 0x%04x: ", offset));
            for (int i = 0; i != 16; ++i) {
                if (offset + i < bytes.length)
                    builder.append(String.format("%02x ", bytes[offset + i]));
                else
                    builder.append("   ");
            }

            builder.append(" ");
            for (int i = 0; i != 16; ++i) {
                int idx = offset + i;
                if (idx < bytes.length) {
                    if (bytes[idx] >= 32 && bytes[idx] <= 126)
                        builder.append(String.format("%c", bytes[idx]));
                    else
                        builder.append(".");
                } else
                    break;
            }

            logger.fine(builder::toString);
            offset += 16;
        }
    }

    public static void logBytes(byte[] bytes) {
        logBytes(sshLogger(), bytes);
    }

    public static void logThrowable(Logger logger, Throwable exc, Level level, boolean withBacktrace) {
        if (!logger.isLoggable(level))
            return;

        int id = System.identityHashCode(exc);

        if (withBacktrace) {
            logger.log(level, String.format("Exception occurred (or Throwable), backtrace follows; id='%d', message='%s', class='%s'", id, exc.getMessage(), exc.getClass().getName()));

            StackTraceElement[] trace = exc.getStackTrace();
            for (StackTraceElement elem : trace) {
                logger.log(level, String.format("exception(%d): %s", id, elem));
            }
        } else
            logger.log(level, String.format("Exception occurred (or Throwable); id='%d', message='%s', class='%s'", id, exc.getMessage(), exc.getClass().getName()));
    }

    public static void logThrowable(Logger logger, Throwable exc, Level level) {
        logThrowable(logger, exc, level, false);
    }

    public static void logThrowableWithBacktrace(Logger logger, Throwable exc, Level level) {
        logThrowable(logger, exc, level, true);
    }

    public static void logException(Logger logger, Exception exc, Level level) {
        logThrowable(logger, exc, level);
    }

    public static void logExceptionWithBacktrace(Logger logger, Exception exc, Level level) {
        logThrowableWithBacktrace(logger, exc, level);
    }

    public static void logException(Logger logger, Exception exc, Level level, boolean withBacktace) {
        logThrowable(logger, exc, level, withBacktace);
    }
}
