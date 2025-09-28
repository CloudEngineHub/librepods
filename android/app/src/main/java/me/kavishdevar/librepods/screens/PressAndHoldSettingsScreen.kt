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

@file:OptIn(ExperimentalStdlibApi::class, ExperimentalEncodingApi::class)

package me.kavishdevar.librepods.screens

import android.content.Context
import android.util.Log
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import androidx.navigation.NavController
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import dev.chrisbanes.haze.materials.ExperimentalHazeMaterialsApi
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.composables.StyledIconButton
import me.kavishdevar.librepods.composables.StyledScaffold
import me.kavishdevar.librepods.constants.StemAction
import me.kavishdevar.librepods.services.ServiceManager
import me.kavishdevar.librepods.utils.AACPManager
import kotlin.experimental.and
import kotlin.io.encoding.ExperimentalEncodingApi

@Composable
fun RightDivider() {
    HorizontalDivider(
        thickness = 1.dp,
        color = Color(0x40888888),
        modifier = Modifier
            .padding(start = 72.dp, end = 20.dp)
    )
}

@Composable
fun RightDividerNoIcon() {
    HorizontalDivider(
        thickness = 1.dp,
        color = Color(0x40888888),
        modifier = Modifier
            .padding(start = 20.dp, end = 20.dp)
    )
}

@ExperimentalHazeMaterialsApi
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LongPress(navController: NavController, name: String) {
    val isDarkTheme = isSystemInDarkTheme()
    val textColor = if (isDarkTheme) Color.White else Color.Black

    val modesByte = ServiceManager.getService()!!.aacpManager.controlCommandStatusList.find {
        it.identifier == AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS
    }?.value?.takeIf { it.isNotEmpty() }?.get(0)

    if (modesByte != null) {
        Log.d("PressAndHoldSettingsScreen", "Current modes state: ${modesByte.toString(2)}")
        Log.d("PressAndHoldSettingsScreen", "Off mode: ${(modesByte and 0x01) != 0.toByte()}")
        Log.d("PressAndHoldSettingsScreen", "Transparency mode: ${(modesByte and 0x02) != 0.toByte()}")
        Log.d("PressAndHoldSettingsScreen", "Noise Cancellation mode: ${(modesByte and 0x04) != 0.toByte()}")
        Log.d("PressAndHoldSettingsScreen", "Adaptive mode: ${(modesByte and 0x08) != 0.toByte()}")
    }
    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val prefKey = if (name.lowercase() == "left") "left_long_press_action" else "right_long_press_action"
    val longPressActionPref = sharedPreferences.getString(prefKey, StemAction.CYCLE_NOISE_CONTROL_MODES.name)
    Log.d("PressAndHoldSettingsScreen", "Long press action preference ($prefKey): $longPressActionPref")
    var longPressAction by remember { mutableStateOf(StemAction.valueOf(longPressActionPref ?: StemAction.CYCLE_NOISE_CONTROL_MODES.name)) }
    val backdrop = rememberLayerBackdrop()
    StyledScaffold(
        title = name,
        navigationButton = {
            StyledIconButton(
                onClick = { navController.popBackStack() },
                icon = "􀯶",
                darkMode = isDarkTheme,
                backdrop = backdrop
            )
        }
    ) { spacerHeight ->
        val backgroundColor = if (isDarkTheme) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
        Column (
          modifier = Modifier
              .layerBackdrop(backdrop)
              .fillMaxSize()
              .padding(top = 8.dp)
              .padding(horizontal = 16.dp)
        ) {
            Spacer(modifier = Modifier.height(spacerHeight))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(backgroundColor, RoundedCornerShape(28.dp)),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                LongPressActionElement(
                    name = stringResource(R.string.noise_control),
                    selected = longPressAction == StemAction.CYCLE_NOISE_CONTROL_MODES,
                    onClick = {
                        longPressAction = StemAction.CYCLE_NOISE_CONTROL_MODES
                        sharedPreferences.edit { putString(prefKey, StemAction.CYCLE_NOISE_CONTROL_MODES.name)}
                    },
                    isFirst = true,
                    isLast = false
                )
                RightDividerNoIcon()
                LongPressActionElement(
                    name = stringResource(R.string.digital_assistant),
                    selected = longPressAction == StemAction.DIGITAL_ASSISTANT,
                    onClick = {
                        longPressAction = StemAction.DIGITAL_ASSISTANT
                        sharedPreferences.edit { putString(prefKey, StemAction.DIGITAL_ASSISTANT.name)}
                    },
                    isFirst = false,
                    isLast = true
                )
            }

            if (longPressAction == StemAction.CYCLE_NOISE_CONTROL_MODES) {
                Spacer(modifier = Modifier.height(32.dp))
                Text(
                    text = stringResource(R.string.noise_control),
                    style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor.copy(alpha = 0.6f),
                    ),
                    fontFamily = FontFamily(Font(R.font.sf_pro)),
                    modifier = Modifier
                        .padding(horizontal = 18.dp)
                )

                Spacer(modifier = Modifier.height(8.dp))

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(backgroundColor, RoundedCornerShape(28.dp)),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    val offListeningModeValue = ServiceManager.getService()!!.aacpManager.controlCommandStatusList.find {
                        it.identifier == AACPManager.Companion.ControlCommandIdentifiers.ALLOW_OFF_OPTION
                    }?.value?.takeIf { it.isNotEmpty() }?.get(0)
                    val offListeningMode = offListeningModeValue == 1.toByte()
                    ListeningModeElement(
                        name = stringResource(R.string.off),
                        enabled = offListeningMode,
                        resourceId =  R.drawable.noise_cancellation,
                        isFirst = true)
                    if (offListeningMode) RightDivider()
                    ListeningModeElement(
                        name = stringResource(R.string.transparency),
                        resourceId = R.drawable.transparency,
                        isFirst = !offListeningMode)
                    RightDivider()
                    ListeningModeElement(
                        name = stringResource(R.string.adaptive),
                        resourceId = R.drawable.adaptive)
                    RightDivider()
                    ListeningModeElement(
                        name = stringResource(R.string.noise_cancellation),
                        resourceId = R.drawable.noise_cancellation,
                        isLast = true)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.press_and_hold_noise_control_description),
                    style = TextStyle(
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Light,
                        color = textColor.copy(alpha = 0.6f),
                        fontFamily = FontFamily(Font(R.font.sf_pro))
                    ),
                    modifier = Modifier
                        .padding(horizontal = 18.dp)
                )
            }
        }
    }
    Log.d("PressAndHoldSettingsScreen", "Current byte: ${ServiceManager.getService()!!.aacpManager.controlCommandStatusList.find {
        it.identifier == AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS
    }?.value?.takeIf { it.isNotEmpty() }?.get(0)?.toString(2)}")
}

@Composable
fun ListeningModeElement(name: String, enabled: Boolean = true, resourceId: Int, isFirst: Boolean = false, isLast: Boolean = false) {
    val bit = when (name) {
        "Off" -> 0x01
        "Transparency" -> 0x02
        "Noise Cancellation" -> 0x04
        "Adaptive" -> 0x08
        else -> -1
    }
    val context = LocalContext.current

    val currentByteValue = ServiceManager.getService()!!.aacpManager.controlCommandStatusList.find {
        it.identifier == AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS
    }?.value?.takeIf { it.isNotEmpty() }?.get(0)

    val savedByte = context.getSharedPreferences("settings", Context.MODE_PRIVATE).getInt("long_press_byte",
        0b0101
    )
    val byteValue = currentByteValue ?: (savedByte and 0xFF).toByte()

    val isChecked = (byteValue.toInt() and bit) != 0
    val checked = remember { mutableStateOf(isChecked) }

    Log.d("PressAndHoldSettingsScreen", "ListeningModeElement: $name, checked: ${checked.value}, byteValue: ${byteValue.toInt()}, in bits: ${byteValue.toInt().toString(2)}")
    val darkMode = isSystemInDarkTheme()
    val textColor = if (darkMode) Color.White else Color.Black
    val desc = when (name) {
        "Off" -> "Turns off noise management"
        "Noise Cancellation" -> "Blocks out external sounds"
        "Transparency" -> "Lets in external sounds"
        "Adaptive" -> "Dynamically adjust external noise"
        else -> ""
    }

    fun countEnabledModes(byteValue: Int): Int {
        var count = 0
        if ((byteValue and 0x01) != 0) count++
        if ((byteValue and 0x02) != 0) count++
        if ((byteValue and 0x04) != 0) count++
        if ((byteValue and 0x08) != 0) count++

        Log.d("PressAndHoldSettingsScreen", "Byte: ${byteValue.toString(2)} Enabled modes: $count")
        return count
    }

    fun valueChanged(value: Boolean = !checked.value) {
        val latestByteValue = ServiceManager.getService()!!.aacpManager.controlCommandStatusList.find {
            it.identifier == AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS
        }?.value?.takeIf { it.isNotEmpty() }?.get(0)

        val currentValue = (latestByteValue?.toInt() ?: byteValue.toInt()) and 0xFF

        Log.d("PressAndHoldSettingsScreen", "Current value: $currentValue (binary: ${Integer.toBinaryString(currentValue)}), bit: $bit, value: $value")

        if (!value) {
            val newValue = currentValue and bit.inv()

            Log.d("PressAndHoldSettingsScreen", "Bit to disable: $bit, inverted: ${bit.inv()}, after AND: ${Integer.toBinaryString(newValue)}")

            val modeCount = countEnabledModes(newValue)

            Log.d("PressAndHoldSettingsScreen", "After disabling, enabled modes count: $modeCount")

            if (modeCount < 2) {
                Log.d("PressAndHoldSettingsScreen", "Cannot disable $name mode - need at least 2 modes enabled")
                return
            }

            val updatedByte = newValue.toByte()

            Log.d("PressAndHoldSettingsScreen", "Sending updated byte: ${updatedByte.toInt() and 0xFF} (binary: ${Integer.toBinaryString(updatedByte.toInt() and 0xFF)})")

            ServiceManager.getService()!!.aacpManager.sendControlCommand(
                AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS.value,
                updatedByte
            )

            context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit {
                putInt("long_press_byte", newValue)}

            checked.value = false
            Log.d("PressAndHoldSettingsScreen", "Updated: $name, enabled: false, byte: ${updatedByte.toInt() and 0xFF}, bits: ${Integer.toBinaryString(updatedByte.toInt() and 0xFF)}")
        } else {
            val newValue = currentValue or bit
            val updatedByte = newValue.toByte()

            ServiceManager.getService()!!.aacpManager.sendControlCommand(
                AACPManager.Companion.ControlCommandIdentifiers.LISTENING_MODE_CONFIGS.value,
                updatedByte
            )

            context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit {
                putInt("long_press_byte", newValue)
            }

            checked.value = true
            Log.d("PressAndHoldSettingsScreen", "Updated: $name, enabled: true, byte: ${updatedByte.toInt() and 0xFF}, bits: ${newValue.toString(2)}")
        }
    }

    val shape = when {
        isFirst -> RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
        isLast -> RoundedCornerShape(bottomStart = 28.dp, bottomEnd = 28.dp)
        else -> RoundedCornerShape(0.dp)
    }
    var backgroundColor by remember { mutableStateOf(if (darkMode) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)) }
    val animatedBackgroundColor by animateColorAsState(targetValue = backgroundColor, animationSpec = tween(durationMillis = 500))
    if (!enabled) {
        valueChanged(false)
    } else {
        Row(
            modifier = Modifier
                .height(72.dp)
                .background(animatedBackgroundColor, shape)
                .pointerInput(Unit) {
                    detectTapGestures(
                        onPress = {
                            backgroundColor = if (darkMode) Color(0x40888888) else Color(0x40D9D9D9)
                            tryAwaitRelease()
                            backgroundColor = if (darkMode) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
                            valueChanged()
                        },
                    )
                }
                .padding(horizontal = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Icon(
                painter = painterResource(resourceId),
                contentDescription = "Icon",
                tint = Color(0xFF007AFF),
                modifier = Modifier
                    .height(48.dp)
                    .wrapContentWidth()
            )
            Column (
                modifier = Modifier
                    .weight(1f)
                    .padding(vertical = 2.dp)
                    .padding(start = 8.dp)
            )
            {
                Text(
                    name,
                    fontSize = 16.sp,
                    color = textColor,
                    fontFamily = FontFamily(Font(R.font.sf_pro)),
                )
                Text (
                    desc,
                    fontSize = 14.sp,
                    color = textColor.copy(alpha = 0.6f),
                    fontFamily = FontFamily(Font(R.font.sf_pro)),
                )
            }

            val floatAnimateState by animateFloatAsState(
                targetValue = if (checked.value) 1f else 0f,
                animationSpec = tween(durationMillis = 300)
            )
            Text(
                text = "􀆅",
                style = TextStyle(
                    fontSize = 20.sp,
                    fontFamily = FontFamily(Font(R.font.sf_pro)),
                    color = Color(0xFF007AFF).copy(alpha = floatAnimateState),
                ),
                modifier = Modifier.padding(end = 4.dp)
            )
        }
    }
}

@Composable
fun LongPressActionElement(
    name: String,
    selected: Boolean,
    onClick: () -> Unit,
    isFirst: Boolean = false,
    isLast: Boolean = false
) {
    val darkMode = isSystemInDarkTheme()
    val shape = when {
        isFirst -> RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
        isLast -> RoundedCornerShape(bottomStart = 28.dp, bottomEnd = 28.dp)
        else -> RoundedCornerShape(0.dp)
    }
    var backgroundColor by remember { mutableStateOf(if (darkMode) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)) }
    val animatedBackgroundColor by animateColorAsState(targetValue = backgroundColor, animationSpec = tween(durationMillis = 500))
    Row(
        modifier = Modifier
            .height(55.dp)
            .background(animatedBackgroundColor, shape)
            .pointerInput(Unit) {
                detectTapGestures(
                    onPress = {
                        backgroundColor = if (darkMode) Color(0x40888888) else Color(0x40D9D9D9)
                        tryAwaitRelease()
                        backgroundColor = if (darkMode) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
                        onClick()
                    }
                )
            }
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            name,
            fontSize = 16.sp,
            fontFamily = FontFamily(Font(R.font.sf_pro)),
            modifier = Modifier
                .weight(1f)
                .padding(start = 4.dp)
        )
        val floatAnimateState by animateFloatAsState(
            targetValue = if (selected) 1f else 0f,
            animationSpec = tween(durationMillis = 300)
        )
        Text(
            text = "􀆅",
            style = TextStyle(
                fontSize = 20.sp,
                fontFamily = FontFamily(Font(R.font.sf_pro)),
                color = Color(0xFF007AFF).copy(alpha = floatAnimateState)
            ),
            modifier = Modifier.padding(end = 4.dp)
        )
    }
}
