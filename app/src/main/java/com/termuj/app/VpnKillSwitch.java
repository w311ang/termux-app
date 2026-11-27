package com.termuj.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import androidx.annotation.NonNull;

import com.termuj.R;
import com.termuj.shared.logger.Logger;
import com.termuj.shared.settings.preferences.TermuxAppSharedPreferences;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Kills every other process running under the app's uid (all shells and programs started from
 * the terminal, and plugins sharing the uid) as soon as the app's default network stops going
 * through a VPN, so that they can not keep talking to the outside network directly.
 *
 * The kill is triggered by a VPN -> non-VPN transition (or loss of the VPN network). In addition,
 * while the setting is enabled and no VPN is active, {@link #shouldBlockExecution(Context)} makes
 * {@link TermuxService} refuse to start any new session or command, so with no VPN at app start
 * not even the shell is started.
 *
 * The {@link TermuxAppSharedPreferences#shouldKillProcessesOnVpnDisconnect()} setting is read at
 * the moment of the transition, so toggling it takes effect immediately.
 *
 * This is a reactive measure: there is a short window (normally milliseconds) between the VPN
 * going away and the processes being killed. For a leak-proof setup also enable the system's
 * "Block connections without VPN" (lockdown) option.
 */
public final class VpnKillSwitch {

    private static final String LOG_TAG = "VpnKillSwitch";

    private static boolean sStarted;

    private final Context mContext;
    private final ConnectivityManager mConnectivityManager;

    /** Only accessed from the callback handler thread. */
    private Network mCurrentDefault;
    private boolean mCurrentDefaultIsVpn;

    private VpnKillSwitch(Context context, ConnectivityManager connectivityManager) {
        mContext = context.getApplicationContext();
        mConnectivityManager = connectivityManager;
    }

    public static synchronized void start(@NonNull Context context) {
        if (sStarted) return;

        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            Logger.logError(LOG_TAG, "ConnectivityManager not available, VPN kill switch disabled");
            return;
        }

        try {
            new VpnKillSwitch(context, cm).register();
            sStarted = true;
        } catch (RuntimeException e) {
            Logger.logStackTraceWithMessage(LOG_TAG, "Failed to register default network callback", e);
        }

        final Context appContext = context.getApplicationContext();
        ForcedVpnMonitor.start(Process.myUid(), forced -> onForcedVpnStateChanged(appContext, forced));
    }



    /*
     * Forced VPN ("require VPN" lock for the app uid, see ForcedVpnMonitor) warnings.
     *
     * Warnings are shown as dialogs in TermuxActivity while it is visible. A warning raised while it
     * is not visible is kept and shown when the user comes back to it; the app never brings itself
     * to the foreground.
     */

    /** Shows a warning dialog. Implemented by the visible TermuxActivity. */
    public interface WarningPresenter {
        void showVpnWarning(int titleResId, int messageResId);
    }

    private static final Handler sMainHandler = new Handler(Looper.getMainLooper());

    /** Last known forced VPN state, {@code null} if unknown. */
    private static volatile Boolean sForcedVpn;
    /** The user chose to start anyway without forced VPN; don't ask again for this process. */
    private static volatile boolean sForcedVpnMissingAcknowledged;

    /** Main thread only. */
    private static WarningPresenter sWarningPresenter;
    private static final Set<Integer> sPendingWarnings = new LinkedHashSet<>();
    private static final int WARNING_FORCED_VPN_REMOVED = 0;
    private static final int WARNING_LEAK_AFTER_DISCONNECT = 1;

    /** Called on the main thread when TermuxActivity becomes visible ({@code presenter}) or hidden ({@code null}). */
    public static void setWarningPresenter(WarningPresenter presenter) {
        sWarningPresenter = presenter;
        if (presenter == null) return;
        for (int warning : sPendingWarnings)
            showWarning(presenter, warning);
        sPendingWarnings.clear();
    }

    /**
     * Whether to ask the user before starting the first shell: the kill switch is enabled, a VPN is
     * active, but the kernel "require VPN" lock is not enabled for the app, and the user hasn't
     * already chosen to start anyway.
     */
    public static boolean shouldWarnForcedVpnMissing(@NonNull Context context) {
        if (sForcedVpnMissingAcknowledged || !isKillSwitchEnabled(context)) return false;
        return Boolean.FALSE.equals(ForcedVpnMonitor.queryForced(Process.myUid()));
    }

    public static void acknowledgeForcedVpnMissing() {
        sForcedVpnMissingAcknowledged = true;
    }

    private static void onForcedVpnStateChanged(Context context, Boolean forced) {
        Boolean previous = sForcedVpn;
        sForcedVpn = forced;
        if (Boolean.TRUE.equals(previous) && Boolean.FALSE.equals(forced) && isKillSwitchEnabled(context)) {
            Logger.logInfo(LOG_TAG, "Forced VPN was removed for the app uid");
            raiseWarning(WARNING_FORCED_VPN_REMOVED);
        }
    }

    private static void raiseWarning(int warning) {
        sMainHandler.post(() -> {
            if (sWarningPresenter != null)
                showWarning(sWarningPresenter, warning);
            else
                sPendingWarnings.add(warning);
        });
    }

    private static void showWarning(WarningPresenter presenter, int warning) {
        if (warning == WARNING_FORCED_VPN_REMOVED)
            presenter.showVpnWarning(R.string.title_forced_vpn_removed, R.string.msg_forced_vpn_removed);
        else if (warning == WARNING_LEAK_AFTER_DISCONNECT)
            presenter.showVpnWarning(R.string.title_vpn_leak_possible, R.string.msg_vpn_leak_possible);
    }

    private static boolean isKillSwitchEnabled(Context context) {
        TermuxAppSharedPreferences preferences = TermuxAppSharedPreferences.build(context);
        return preferences != null && preferences.shouldKillProcessesOnVpnDisconnect();
    }

    /**
     * Whether starting a new process (terminal session, background task, plugin command) must be
     * refused: the kill switch is enabled and the app's default network does not go through a VPN.
     */
    public static boolean shouldBlockExecution(@NonNull Context context) {
        TermuxAppSharedPreferences preferences = TermuxAppSharedPreferences.build(context);
        if (preferences == null || !preferences.shouldKillProcessesOnVpnDisconnect()) return false;
        return !isVpnActive(context);
    }

    /** Whether the default network of the app's uid currently goes through a VPN. */
    public static boolean isVpnActive(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        Network network = cm.getActiveNetwork();
        if (network == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private void register() {
        // Deliver callbacks on a dedicated thread, so a busy main thread can not delay the kill.
        HandlerThread thread = new HandlerThread("VpnKillSwitch");
        thread.start();
        Handler handler = new Handler(thread.getLooper());

        ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                // Before API 26 onCapabilitiesChanged() is not guaranteed to follow, so query them.
                onDefaultNetworkCapabilities(network, mConnectivityManager.getNetworkCapabilities(network));
            }

            @Override
            public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities caps) {
                onDefaultNetworkCapabilities(network, caps);
            }

            @Override
            public void onLost(@NonNull Network network) {
                if (!network.equals(mCurrentDefault)) return;
                boolean wasVpn = mCurrentDefaultIsVpn;
                mCurrentDefault = null;
                mCurrentDefaultIsVpn = false;
                if (wasVpn) onVpnDisconnected("VPN default network lost");
            }
        };

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mConnectivityManager.registerDefaultNetworkCallback(callback, handler);
        } else {
            // No Handler overload before API 26: re-post onto our thread to keep state single threaded.
            mConnectivityManager.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    handler.post(() -> callback.onAvailable(network));
                }

                @Override
                public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities caps) {
                    handler.post(() -> callback.onCapabilitiesChanged(network, caps));
                }

                @Override
                public void onLost(@NonNull Network network) {
                    handler.post(() -> callback.onLost(network));
                }
            });
        }
        Logger.logDebug(LOG_TAG, "Registered default network callback");
    }

    private void onDefaultNetworkCapabilities(Network network, NetworkCapabilities caps) {
        if (caps == null) return;
        boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        boolean wasVpn = mCurrentDefaultIsVpn;
        mCurrentDefault = network;
        mCurrentDefaultIsVpn = isVpn;
        if (wasVpn && !isVpn) onVpnDisconnected("default network no longer goes through a VPN");
    }

    private void onVpnDisconnected(String reason) {
        TermuxAppSharedPreferences preferences = TermuxAppSharedPreferences.build(mContext);
        if (preferences == null || !preferences.shouldKillProcessesOnVpnDisconnect()) {
            Logger.logInfo(LOG_TAG, "VPN disconnected (" + reason + "), kill switch is turned off");
            return;
        }

        // kill(-1, sig) signals every process the caller is allowed to signal, except init and the
        // caller itself. For an app that is exactly the other processes of its own uid.
        try {
            Os.kill(-1, OsConstants.SIGKILL);
        } catch (ErrnoException e) {
            // ESRCH just means there was no other process to kill.
            if (e.errno != OsConstants.ESRCH)
                Logger.logStackTraceWithMessage(LOG_TAG, "kill(-1, SIGKILL) failed", e);
        }

        Logger.logInfo(LOG_TAG, "VPN disconnected (" + reason + "), killed all app processes");
        Logger.showToast(mContext, mContext.getString(R.string.msg_vpn_kill_switch_triggered), true);

        // Without the kernel "require VPN" lock, traffic could have left directly in the window
        // between the VPN going down and the kill above.
        Boolean forced = ForcedVpnMonitor.queryForced(Process.myUid());
        if (Boolean.FALSE.equals(forced)) {
            Logger.logInfo(LOG_TAG, "Forced VPN was not enabled when the VPN disconnected");
            raiseWarning(WARNING_LEAK_AFTER_DISCONNECT);
        }
    }

}
