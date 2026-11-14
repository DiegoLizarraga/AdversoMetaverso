package com.adverso.metaverso

import android.app.Application
import com.adverso.metaverso.core.Metaverse

class MetaversoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // El servicio de VPN y la interfaz comparten este estado; se instala
        // aquí para que exista antes de que cualquiera de los dos arranque.
        Metaverse.install(this)
    }
}
