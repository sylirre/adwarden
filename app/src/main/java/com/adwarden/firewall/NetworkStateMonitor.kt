// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.firewall

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import android.content.Context
import javax.inject.Inject
import javax.inject.Singleton

/** Transport codes shared with the native firewall (0 other / 1 wifi / 2 cellular). */
object Transport {
    const val OTHER = 0
    const val WIFI = 1
    const val CELLULAR = 2
}

data class NetworkState(
    val transport: Int = Transport.OTHER,
    val metered: Boolean = true,
    val roaming: Boolean = false,
)

/**
 * Observes the active network via a [ConnectivityManager.NetworkCallback] and
 * emits the transport / metered / roaming state used by the firewall to pick a
 * per-app policy.
 */
@Singleton
class NetworkStateMonitor @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val connectivity =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    val state: Flow<NetworkState> = callbackFlow {
        fun emit(caps: NetworkCapabilities?) {
            trySend(toState(caps))
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                emit(caps)
            }

            override fun onLost(network: Network) {
                trySend(NetworkState())
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivity.registerNetworkCallback(request, callback)
        // Seed with the current active network.
        emit(connectivity.getNetworkCapabilities(connectivity.activeNetwork))

        awaitClose { connectivity.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged()

    private fun toState(caps: NetworkCapabilities?): NetworkState {
        if (caps == null) return NetworkState()
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
            else -> Transport.OTHER
        }
        val metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val roaming = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
        return NetworkState(transport, metered, roaming)
    }
}
