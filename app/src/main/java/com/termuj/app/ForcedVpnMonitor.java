package com.termuj.app;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import androidx.annotation.Nullable;

import com.termuj.shared.logger.Logger;

import java.io.FileDescriptor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Detects whether the kernel-level "require VPN" lock is enabled for a uid, and gets notified the
 * moment it is added or removed, without polling.
 *
 * Both the per-app lock ({@code ConnectivityManager#setRequireVpnForUids}, e.g. set from a shell with
 * {@code service call connectivity ...}) and the Always-on VPN "Block connections without VPN"
 * lockdown are implemented by netd as policy routing rules of type {@code prohibit} with a uid range
 * ({@code ip rule: 14000: from all ... uidrange A-B prohibit}), one for IPv4 and one for IPv6. The
 * lock counts as enabled when a prohibit rule covering the uid exists for both families.
 *
 * State is read with a NETLINK_ROUTE RTM_GETRULE dump, and changes are received by joining the
 * RTNLGRP_IPV4_RULE / RTNLGRP_IPV6_RULE multicast groups: the kernel pushes RTM_NEWRULE /
 * RTM_DELRULE as soon as netd changes a rule. Apps may not bind() netlink sockets (SELinux), so the
 * socket is bound implicitly by sending the first request.
 */
final class ForcedVpnMonitor {

    interface Listener {
        /** {@code null} means the state can't be determined. Called on the monitor thread. */
        void onForcedVpnStateChanged(@Nullable Boolean forced);
    }

    private static final String LOG_TAG = "ForcedVpnMonitor";

    private static final int NETLINK_ROUTE = 0;
    private static final int SOL_NETLINK = 270;
    private static final int NETLINK_ADD_MEMBERSHIP = 1;
    private static final int RTNLGRP_IPV4_RULE = 8;
    private static final int RTNLGRP_IPV6_RULE = 19;

    private static final int NLMSG_HDRLEN = 16;
    private static final int NLMSG_ERROR = 2;
    private static final int NLMSG_DONE = 3;
    private static final int NLM_F_REQUEST = 0x1;
    private static final int NLM_F_DUMP = 0x300;
    private static final int RTM_NEWRULE = 32;
    private static final int RTM_DELRULE = 33;
    private static final int RTM_GETRULE = 34;

    private static final int FIB_RULE_HDRLEN = 12;
    private static final int FR_ACT_PROHIBIT = 8;
    private static final int FRA_UID_RANGE = 20;
    private static final int NLA_TYPE_MASK = 0x3fff;

    private static final int BUFFER_SIZE = 128 * 1024;

    private ForcedVpnMonitor() {}

    /** One-shot query of whether the "require VPN" lock is enabled for uid, {@code null} if unknown. */
    @Nullable
    static Boolean queryForced(int uid) {
        try {
            return hasProhibitRule(OsConstants.AF_INET, uid) && hasProhibitRule(OsConstants.AF_INET6, uid);
        } catch (ErrnoException | RuntimeException e) {
            Logger.logStackTraceWithMessage(LOG_TAG, "Failed to read routing rules", e);
            return null;
        }
    }

    /** Start a daemon thread that reports the initial state and every change of it to listener. */
    static void start(int uid, Listener listener) {
        Thread thread = new Thread(() -> monitor(uid, listener), "ForcedVpnMonitor");
        thread.setDaemon(true);
        thread.start();
    }

    private static void monitor(int uid, Listener listener) {
        FileDescriptor fd = null;
        try {
            fd = openSocket();
            // Implicitly bind the socket (bind() is denied for apps), then subscribe to rule changes.
            sendDumpRequest(fd, OsConstants.AF_INET);
            readDump(fd, uid);
            Os.setsockoptInt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, RTNLGRP_IPV4_RULE);
            Os.setsockoptInt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, RTNLGRP_IPV6_RULE);
        } catch (ErrnoException | RuntimeException e) {
            Logger.logStackTraceWithMessage(LOG_TAG, "Failed to subscribe to routing rule changes", e);
            closeQuietly(fd);
            listener.onForcedVpnStateChanged(null);
            return;
        }

        // Read the state only after subscribing, so no change can be missed in between.
        Boolean state = queryForced(uid);
        Logger.logInfo(LOG_TAG, "Initial forced VPN state for uid " + uid + ": " + state);
        listener.onForcedVpnStateChanged(state);

        byte[] buf = new byte[BUFFER_SIZE];
        while (true) {
            boolean recheck;
            try {
                int n = Os.read(fd, buf, 0, buf.length);
                recheck = n > 0 && containsRelevantRuleChange(buf, n, uid);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EINTR) continue;
                if (e.errno == OsConstants.ENOBUFS) {
                    // Socket buffer overflowed (e.g. while the app was frozen): events were lost.
                    recheck = true;
                } else {
                    Logger.logStackTraceWithMessage(LOG_TAG, "Routing rule monitor failed", e);
                    closeQuietly(fd);
                    listener.onForcedVpnStateChanged(null);
                    return;
                }
            }

            if (!recheck) continue;
            Boolean newState = queryForced(uid);
            if (!Objects.equals(newState, state)) {
                Logger.logInfo(LOG_TAG, "Forced VPN state for uid " + uid + " changed: " + state + " -> " + newState);
                state = newState;
                listener.onForcedVpnStateChanged(newState);
            }
        }
    }

    private static boolean hasProhibitRule(int family, int uid) throws ErrnoException {
        FileDescriptor fd = openSocket();
        try {
            sendDumpRequest(fd, family);
            return readDump(fd, uid);
        } finally {
            closeQuietly(fd);
        }
    }

    private static FileDescriptor openSocket() throws ErrnoException {
        // SOCK_CLOEXEC so that shells started by the app don't inherit the socket.
        return Os.socket(OsConstants.AF_NETLINK, OsConstants.SOCK_RAW | OsConstants.SOCK_CLOEXEC, NETLINK_ROUTE);
    }

    private static void sendDumpRequest(FileDescriptor fd, int family) throws ErrnoException {
        ByteBuffer b = ByteBuffer.allocate(NLMSG_HDRLEN + FIB_RULE_HDRLEN).order(ByteOrder.nativeOrder());
        b.putInt(NLMSG_HDRLEN + FIB_RULE_HDRLEN); // nlmsg_len
        b.putShort((short) RTM_GETRULE);         // nlmsg_type
        b.putShort((short) (NLM_F_REQUEST | NLM_F_DUMP));
        b.putInt(1);                             // nlmsg_seq
        b.putInt(0);                             // nlmsg_pid
        b.put((byte) family);                    // struct fib_rule_hdr, rest zero
        byte[] msg = b.array();
        Os.write(fd, msg, 0, msg.length);
    }

    /** Read a dump reply until NLMSG_DONE, returning whether a prohibit rule covers uid. */
    private static boolean readDump(FileDescriptor fd, int uid) throws ErrnoException {
        byte[] buf = new byte[BUFFER_SIZE];
        boolean found = false;
        while (true) {
            int n = Os.read(fd, buf, 0, buf.length);
            ByteBuffer b = ByteBuffer.wrap(buf, 0, n).order(ByteOrder.nativeOrder());
            int off = 0;
            while (off + NLMSG_HDRLEN <= n) {
                int len = b.getInt(off);
                int type = b.getShort(off + 4) & 0xffff;
                if (len < NLMSG_HDRLEN || off + len > n) break;
                if (type == NLMSG_DONE) return found;
                if (type == NLMSG_ERROR) {
                    int err = b.getInt(off + NLMSG_HDRLEN);
                    if (err != 0) throw new ErrnoException("RTM_GETRULE", -err);
                } else if (type == RTM_NEWRULE && isProhibitRuleCoveringUid(b, off, len, uid)) {
                    found = true;
                }
                off += align(len);
            }
        }
    }

    private static boolean containsRelevantRuleChange(byte[] buf, int n, int uid) {
        ByteBuffer b = ByteBuffer.wrap(buf, 0, n).order(ByteOrder.nativeOrder());
        int off = 0;
        while (off + NLMSG_HDRLEN <= n) {
            int len = b.getInt(off);
            int type = b.getShort(off + 4) & 0xffff;
            if (len < NLMSG_HDRLEN || off + len > n) break;
            if ((type == RTM_NEWRULE || type == RTM_DELRULE) && isProhibitRuleCoveringUid(b, off, len, uid))
                return true;
            off += align(len);
        }
        return false;
    }

    private static boolean isProhibitRuleCoveringUid(ByteBuffer b, int msgOff, int msgLen, int uid) {
        int hdr = msgOff + NLMSG_HDRLEN;
        if (msgLen < NLMSG_HDRLEN + FIB_RULE_HDRLEN) return false;
        int action = b.get(hdr + 7) & 0xff;
        if (action != FR_ACT_PROHIBIT) return false;

        int end = msgOff + msgLen;
        int a = hdr + FIB_RULE_HDRLEN;
        while (a + 4 <= end) {
            int alen = b.getShort(a) & 0xffff;
            int atype = b.getShort(a + 2) & NLA_TYPE_MASK;
            if (alen < 4 || a + alen > end) break;
            if (atype == FRA_UID_RANGE && alen >= 12) {
                long start = b.getInt(a + 4) & 0xffffffffL;
                long stop = b.getInt(a + 8) & 0xffffffffL;
                long u = uid & 0xffffffffL;
                return start <= u && u <= stop;
            }
            a += align(alen);
        }
        return false;
    }

    private static int align(int len) {
        return (len + 3) & ~3;
    }

    private static void closeQuietly(@Nullable FileDescriptor fd) {
        if (fd == null) return;
        try {
            Os.close(fd);
        } catch (ErrnoException ignored) {
        }
    }

}
