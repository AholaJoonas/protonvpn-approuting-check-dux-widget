import QtQuick
import qs.Common
import qs.DCommon.Widgets
import qs.Modules.Plugins

PluginSettings {
    id: root
    pluginId: "vpnRoutes"

    SliderSetting {
        settingKey: "refreshSec"
        label: "Refresh interval"
        description: "How often to re-check sockets while the bar is visible"
        defaultValue: 10
        minimum: 3
        maximum: 60
        unit: "s"
    }

    ToggleSetting {
        settingKey: "showLabel"
        label: "Show text next to the icon"
        description: "Off = icon only (colour still shows the state)"
        defaultValue: true
    }

    ToggleSetting {
        settingKey: "restartAll"
        label: "Restart button on every app"
        description: "Off = only on apps that are routed wrong. Overrides live in restart.json in the plugin folder."
        defaultValue: false
    }
}
