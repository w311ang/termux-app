package com.termuj.app;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import androidx.annotation.NonNull;

import com.termuj.R;
import com.termuj.shared.logger.Logger;
import com.termuj.shared.settings.preferences.TermuxAppSharedPreferences;

/**
 * Kills every other process running under the app's uid (all shells and programs started from
 * the terminal, and plugins sharing the uid) as soon as the app's default network stops going
 * through a VPN, so that they can not keep talking to the outside network directly.
 *
 * It only reacts to a VPN -> non-VPN transition (or loss of the VPN network). Starting the app
 * without any VPN does nothing, so the default-on setting does not get in the way of users that
 * never use a VPN.
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
    }

}
