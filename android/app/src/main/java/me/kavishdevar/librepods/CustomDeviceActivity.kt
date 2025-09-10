/*
 * LibrePods - AirPods liberated from Apple’s ecosystem
 *
 * Copyright (C) 2025 LibrePods contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package me.kavishdevar.librepods

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.os.Bundle
import android.os.ParcelUuid
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import me.kavishdevar.librepods.screens.AccessibilitySettingsScreen
import me.kavishdevar.librepods.screens.EqualizerSettingsScreen
import me.kavishdevar.librepods.ui.theme.LibrePodsTheme
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

@Suppress("PrivatePropertyName")
class CustomDevice : ComponentActivity() {
    private val TAG = "AirPodsAccessibilitySettings"
    private var socket: BluetoothSocket? = null
    private val deviceAddress = "28:2D:7F:C2:05:5B"
    private val uuid: ParcelUuid = ParcelUuid.fromString("00000000-0000-0000-0000-00000000000")

    // Data states
    private val isConnected = mutableStateOf(false)
    private val leftAmplification = mutableFloatStateOf(1.0f)
    private val leftTone = mutableFloatStateOf(1.0f)
    private val leftAmbientNoiseReduction = mutableFloatStateOf(0.5f)
    private val leftConversationBoost = mutableStateOf(false)
    private val leftEQ = mutableStateOf(FloatArray(8) { 50.0f })

    private val rightAmplification = mutableFloatStateOf(1.0f)
    private val rightTone = mutableFloatStateOf(1.0f)
    private val rightAmbientNoiseReduction = mutableFloatStateOf(0.5f)
    private val rightConversationBoost = mutableStateOf(false)
    private val rightEQ = mutableStateOf(FloatArray(8) { 50.0f })

    private val singleMode = mutableStateOf(false)
    private val amplification = mutableFloatStateOf(1.0f)
    private val balance = mutableFloatStateOf(0.5f)

    private val retryCount = mutableIntStateOf(0)
    private val showRetryButton = mutableStateOf(false)
    private val maxRetries = 3

    private var debounceJob: Job? = null

    // Phone and Media EQ state
    private val phoneMediaEQ = mutableStateOf(FloatArray(8) { 50.0f })

    @SuppressLint("MissingPermission")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            LibrePodsTheme {
                val navController = rememberNavController()

                NavHost(navController = navController, startDestination = "main") {
                    composable("main") {
                        AccessibilitySettingsScreen(
                            navController = navController,
                            isConnected = isConnected.value,
                            leftAmplification = leftAmplification,
                            leftTone = leftTone,
                            leftAmbientNoiseReduction = leftAmbientNoiseReduction,
                            leftConversationBoost = leftConversationBoost,
                            rightAmplification = rightAmplification,
                            rightTone = rightTone,
                            rightAmbientNoiseReduction = rightAmbientNoiseReduction,
                            rightConversationBoost = rightConversationBoost,
                            singleMode = singleMode,
                            amplification = amplification,
                            balance = balance,
                            showRetryButton = showRetryButton.value,
                            onRetry = { CoroutineScope(Dispatchers.IO).launch { connectL2CAP() } },
                            onSettingsChanged = { sendAccessibilitySettings() }
                        )
                    }
                    composable("eq") {
                        EqualizerSettingsScreen(
                            navController = navController,
                            leftEQ = leftEQ,
                            rightEQ = rightEQ,
                            singleMode = singleMode,
                            onEQChanged = { sendAccessibilitySettings() },
                            phoneMediaEQ = phoneMediaEQ
                        )
                    }
                }
            }
        }

        // Connect automatically
        CoroutineScope(Dispatchers.IO).launch { connectL2CAP() }
    }

    override fun onDestroy() {
        super.onDestroy()
        socket?.close()
    }

    @SuppressLint("MissingPermission")
    private suspend fun connectL2CAP() {
        retryCount.intValue = 0
        // Close any existing socket
        socket?.close()
        socket = null
        while (retryCount.intValue < maxRetries) {
            try {
                Log.d(TAG, "Starting L2CAP connection setup, attempt ${retryCount.intValue + 1}")
                HiddenApiBypass.addHiddenApiExemptions("Landroid/bluetooth/BluetoothSocket;")
                val manager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
                val device: BluetoothDevice = manager.adapter.getRemoteDevice(deviceAddress)
                socket = createBluetoothSocket(device)

                withTimeout(5000L) {
                    socket?.connect()
                }

                withContext(Dispatchers.Main) {
                    isConnected.value = true
                    showRetryButton.value = false
                    Log.d(TAG, "L2CAP connection established successfully")
                }

                // Read current settings
                readCurrentSettings()

                // Start listening for responses
                listenForData()

                return
            } catch (e: Exception) {
                Log.e(TAG, "Failed to connect, attempt ${retryCount.intValue + 1}: ${e.message}")
                retryCount.intValue++
                if (retryCount.intValue < maxRetries) {
                    delay(2000) // Wait 2 seconds before retry
                }
            }
        }

        // After max retries
        withContext(Dispatchers.Main) {
            isConnected.value = false
            showRetryButton.value = true
            Log.e(TAG, "Failed to connect after $maxRetries attempts")
        }
    }

    private fun createBluetoothSocket(device: BluetoothDevice): BluetoothSocket {
        val type = 3 // L2CAP
        val constructorSpecs = listOf(
            arrayOf(device, type, true, true, 31, uuid),
            arrayOf(device, type, 1, true, true, 31, uuid),
            arrayOf(type, 1, true, true, device, 31, uuid),
            arrayOf(type, true, true, device, 31, uuid)
        )

        val constructors = BluetoothSocket::class.java.declaredConstructors
        Log.d(TAG, "BluetoothSocket has ${constructors.size} constructors")

        var lastException: Exception? = null
        var attemptedConstructors = 0

        for ((index, params) in constructorSpecs.withIndex()) {
            try {
                Log.d(TAG, "Trying constructor signature #${index + 1}")
                attemptedConstructors++
                return HiddenApiBypass.newInstance(BluetoothSocket::class.java, *params) as BluetoothSocket
            } catch (e: Exception) {
                Log.e(TAG, "Constructor signature #${index + 1} failed: ${e.message}")
                lastException = e
            }
        }

        val errorMessage = "Failed to create BluetoothSocket after trying $attemptedConstructors constructor signatures"
        Log.e(TAG, errorMessage)
        throw lastException ?: IllegalStateException(errorMessage)
    }

    private fun readCurrentSettings() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "Sending read settings command: 0A1800")
                val readCommand = byteArrayOf(0x0A, 0x18, 0x00)
                socket?.outputStream?.write(readCommand)
                socket?.outputStream?.flush()
                Log.d(TAG, "Read settings command sent")
            } catch (e: IOException) {
                Log.e(TAG, "Failed to send read command: ${e.message}")
            }
        }
    }

    private fun listenForData() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val buffer = ByteArray(1024)
                Log.d(TAG, "Started listening for incoming data")
                while (socket?.isConnected == true) {
                    val bytesRead = socket?.inputStream?.read(buffer)
                    if (bytesRead != null && bytesRead > 0) {
                        val data = buffer.copyOfRange(0, bytesRead)
                        Log.d(TAG, "Received data: ${data.joinToString(" ") { "%02X".format(it) }}")
                        parseSettingsResponse(data)
                    } else if (bytesRead == -1) {
                        Log.d(TAG, "Connection closed by remote device")
                        withContext(Dispatchers.Main) {
                            isConnected.value = false
                        }
                        // Attempt to reconnect
                        connectL2CAP()
                        break
                    }
                }
            } catch (e: IOException) {
                Log.e(TAG, "Connection lost: ${e.message}")
                withContext(Dispatchers.Main) {
                    isConnected.value = false
                }
                // Close socket
                socket?.close()
                socket = null
                // Attempt to reconnect
                connectL2CAP()
            }
        }
    }

    private fun parseSettingsResponse(data: ByteArray) {
        if (data.size < 2 || data[0] != 0x0B.toByte()) {
            Log.d(TAG, "Not a settings response")
            return
        }

        val settingsData = data.copyOfRange(1, data.size)
        if (settingsData.size < 100) { // 25 floats * 4 bytes
            Log.e(TAG, "Settings data too short: ${settingsData.size} bytes")
            return
        }

        val buffer = ByteBuffer.wrap(settingsData).order(ByteOrder.LITTLE_ENDIAN)

        // Global enabled
        val enabled = buffer.float
        Log.d(TAG, "Parsed enabled: $enabled")

        // Left bud
        val newLeftEQ = leftEQ.value.copyOf()
        for (i in 0..7) {
            newLeftEQ[i] = buffer.float
            Log.d(TAG, "Parsed left EQ${i+1}: ${newLeftEQ[i]}")
        }
        leftEQ.value = newLeftEQ
        if (singleMode.value) rightEQ.value = newLeftEQ

        leftAmplification.floatValue = buffer.float
        Log.d(TAG, "Parsed left amplification: ${leftAmplification.floatValue}")
        leftTone.floatValue = buffer.float
        Log.d(TAG, "Parsed left tone: ${leftTone.floatValue}")
        if (singleMode.value) rightTone.floatValue = leftTone.floatValue
        val leftConvFloat = buffer.float
        leftConversationBoost.value = leftConvFloat > 0.5f
        Log.d(TAG, "Parsed left conversation boost: $leftConvFloat (${leftConversationBoost.value})")
        if (singleMode.value) rightConversationBoost.value = leftConversationBoost.value
        leftAmbientNoiseReduction.floatValue = buffer.float
        Log.d(TAG, "Parsed left ambient noise reduction: ${leftAmbientNoiseReduction.floatValue}")
        if (singleMode.value) rightAmbientNoiseReduction.floatValue = leftAmbientNoiseReduction.floatValue

        // Right bud
        val newRightEQ = rightEQ.value.copyOf()
        for (i in 0..7) {
            newRightEQ[i] = buffer.float
            Log.d(TAG, "Parsed right EQ${i+1}: ${newRightEQ[i]}")
        }
        rightEQ.value = newRightEQ

        rightAmplification.floatValue = buffer.float
        Log.d(TAG, "Parsed right amplification: ${rightAmplification.floatValue}")
        rightTone.floatValue = buffer.float
        Log.d(TAG, "Parsed right tone: ${rightTone.floatValue}")
        val rightConvFloat = buffer.float
        rightConversationBoost.value = rightConvFloat > 0.5f
        Log.d(TAG, "Parsed right conversation boost: $rightConvFloat (${rightConversationBoost.value})")
        rightAmbientNoiseReduction.floatValue = buffer.float
        Log.d(TAG, "Parsed right ambient noise reduction: ${rightAmbientNoiseReduction.floatValue}")

        Log.d(TAG, "Settings parsed successfully")

        // Update single mode values if in single mode
        if (singleMode.value) {
            val avg = (leftAmplification.floatValue + rightAmplification.floatValue) / 2
            amplification.floatValue = avg.coerceIn(0f, 1f)
            val diff = rightAmplification.floatValue - leftAmplification.floatValue
            balance.floatValue = (0.5f + diff / (2 * avg)).coerceIn(0f, 1f)
        }
    }

    private fun sendAccessibilitySettings() {
        if (!isConnected.value || socket == null) {
            Log.w(TAG, "Not connected, cannot send settings")
            return
        }

        debounceJob?.cancel()
        debounceJob = CoroutineScope(Dispatchers.IO).launch {
            delay(100)
            try {
                val buffer = ByteBuffer.allocate(103).order(ByteOrder.LITTLE_ENDIAN) // 3 header + 100 data bytes

                buffer.put(0x12)
                buffer.put(0x18)
                buffer.put(0x00)
                buffer.putFloat(1.0f) // enabled

                // Left bud
                for (eq in leftEQ.value) {
                    buffer.putFloat(eq)
                }
                buffer.putFloat(leftAmplification.floatValue)
                buffer.putFloat(leftTone.floatValue)
                buffer.putFloat(if (leftConversationBoost.value) 1.0f else 0.0f)
                buffer.putFloat(leftAmbientNoiseReduction.floatValue)

                // Right bud
                for (eq in rightEQ.value) {
                    buffer.putFloat(eq)
                }
                buffer.putFloat(rightAmplification.floatValue)
                buffer.putFloat(rightTone.floatValue)
                buffer.putFloat(if (rightConversationBoost.value) 1.0f else 0.0f)
                buffer.putFloat(rightAmbientNoiseReduction.floatValue)

                val packet = buffer.array()
                Log.d(TAG, "Packet length: ${packet.size}")
                socket?.outputStream?.write(packet)
                socket?.outputStream?.flush()
                Log.d(TAG, "Accessibility settings sent: ${packet.joinToString(" ") { "%02X".format(it) }}")
            } catch (e: IOException) {
                Log.e(TAG, "Failed to send accessibility settings: ${e.message}")
                withContext(Dispatchers.Main) {
                    isConnected.value = false
                }
                // Close socket
                socket?.close()
                socket = null
            }
        }
    }
}
