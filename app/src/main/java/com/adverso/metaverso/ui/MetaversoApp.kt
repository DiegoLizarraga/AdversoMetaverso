package com.adverso.metaverso.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.ui.components.MetaverseBackdrop
import com.adverso.metaverso.ui.components.NoticeStrip
import com.adverso.metaverso.ui.screens.CodexScreen
import com.adverso.metaverso.ui.screens.MementosScreen
import com.adverso.metaverso.ui.screens.NavScreen
import com.adverso.metaverso.ui.screens.PalaceDetailScreen
import com.adverso.metaverso.ui.screens.PalacesScreen
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Black
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.rememberSkewShape

/** Las acciones que la interfaz necesita del mundo real (permisos, servicios). */
class MetaversoActions(
    val toggleNavigator: () -> Unit,
    val toggleBlocking: () -> Unit,
    val toggleHijack: () -> Unit,
    val setThreshold: (Int) -> Unit,
    val openTrafficAccess: () -> Unit,
    val shareCard: (String) -> Unit,
    val resetRun: () -> Unit,
)

private sealed interface Destination {
    data object Nav : Destination
    data object Palaces : Destination
    data object Mementos : Destination
    data object Codex : Destination
    data class Palace(val uid: Int) : Destination
}

private val tabs = listOf(
    Destination.Nav to "NAV",
    Destination.Palaces to "PALACIOS",
    Destination.Mementos to "MEMENTOS",
    Destination.Codex to "CÓDICE",
)

@Composable
fun MetaversoApp(
    actions: MetaversoActions,
    hasTrafficAccess: Boolean,
) {
    val pulse by Metaverse.pulse.collectAsStateWithLifecycle()
    val active by Metaverse.navigatorActive.collectAsStateWithLifecycle()
    val palaces by Metaverse.palaces.collectAsStateWithLifecycle()
    val shadows by Metaverse.shadows.collectAsStateWithLifecycle()
    val events by Metaverse.events.collectAsStateWithLifecycle()
    val notice by Metaverse.notice.collectAsStateWithLifecycle()
    val blocking by Metaverse.settings.blockingEnabledFlow.collectAsStateWithLifecycle()
    val hijack by Metaverse.settings.hijackResolversFlow.collectAsStateWithLifecycle()
    val threshold by Metaverse.settings.thresholdFlow.collectAsStateWithLifecycle()
    val stolen by Metaverse.settings.stolenFlow.collectAsStateWithLifecycle()
    val pacted by Metaverse.settings.pactsFlow.collectAsStateWithLifecycle()

    var destination by remember { mutableStateOf<Destination>(Destination.Nav) }
    var lastTab by remember { mutableStateOf<Destination>(Destination.Nav) }

    BackHandler(enabled = destination is Destination.Palace) {
        destination = lastTab
    }

    Box(Modifier.fillMaxSize().background(P5Black)) {
        MetaverseBackdrop(
            intensity = pulse.alert / 100f,
            modifier = Modifier.fillMaxSize(),
        )

        Column(Modifier.fillMaxSize().systemBarsPadding()) {
            if (notice != null) {
                NoticeStrip(
                    message = notice!!,
                    onDismiss = { Metaverse.notice(null) },
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                )
            }

            AnimatedContent(
                targetState = destination,
                modifier = Modifier.weight(1f),
                transitionSpec = {
                    val forward = targetState is Destination.Palace
                    (
                        slideInHorizontally(tween(240)) { full -> if (forward) full / 3 else -full / 3 } +
                            fadeIn(tween(200))
                        ) togetherWith (
                        slideOutHorizontally(tween(200)) { full -> if (forward) -full / 5 else full / 5 } +
                            fadeOut(tween(160))
                        )
                },
                label = "destination",
            ) { current ->
                when (current) {
                    Destination.Nav -> NavScreen(
                        pulse = pulse,
                        active = active,
                        blocking = blocking,
                        hijack = hijack,
                        threshold = threshold,
                        hasTrafficAccess = hasTrafficAccess,
                        palaces = palaces,
                        actions = actions,
                        modifier = Modifier.fillMaxSize(),
                    )

                    Destination.Palaces -> PalacesScreen(
                        palaces = palaces,
                        onOpen = { uid ->
                            lastTab = Destination.Palaces
                            destination = Destination.Palace(uid)
                        },
                        modifier = Modifier.fillMaxSize(),
                    )

                    Destination.Mementos -> MementosScreen(
                        events = events,
                        modifier = Modifier.fillMaxSize(),
                    )

                    Destination.Codex -> CodexScreen(
                        shadows = shadows,
                        stolen = stolen,
                        pacted = pacted,
                        onSteal = { Metaverse.settings.steal(it) },
                        onSeal = { Metaverse.settings.seal(it) },
                        onRelease = { Metaverse.settings.release(it) },
                        modifier = Modifier.fillMaxSize(),
                    )

                    is Destination.Palace -> PalaceDetailScreen(
                        palace = palaces[current.uid],
                        shadows = shadows.values.filter { it.uids.contains(current.uid) },
                        stolen = stolen,
                        pacted = pacted,
                        onBack = { destination = lastTab },
                        onSteal = { Metaverse.settings.steal(it) },
                        onSeal = { Metaverse.settings.seal(it) },
                        onRelease = { Metaverse.settings.release(it) },
                        onShareCard = actions.shareCard,
                        onStealAll = { uid ->
                            // Robar todo: cada Sombra de este Palacio que no sea
                            // simple infraestructura pasa a la lista negra.
                            shadows.values
                                .filter { it.uids.contains(uid) && it.score >= 40 }
                                .forEach { Metaverse.settings.steal(it.domain) }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }

            BottomTabs(
                current = destination,
                onSelect = { target ->
                    lastTab = target
                    destination = target
                },
            )
        }
    }
}

@Composable
private fun BottomTabs(
    current: Destination,
    onSelect: (Destination) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(P5Black)
            .padding(horizontal = 10.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        tabs.forEach { (target, label) ->
            val selected = current == target ||
                (target == Destination.Palaces && current is Destination.Palace)
            Box(
                Modifier
                    .weight(1f)
                    .clip(rememberSkewShape(lean = 9.dp))
                    .background(if (selected) P5Red else P5Ink)
                    .clickable { onSelect(target) }
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    style = Ink.label,
                    color = if (selected) P5White else P5Bone,
                    maxLines = 1,
                )
            }
        }
    }
}
