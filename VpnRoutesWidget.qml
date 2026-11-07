import QtQuick
import Quickshell
import Quickshell.Io
import qs.Common
import qs.Services
import qs.DCommon.Widgets
import qs.Modules.Plugins

PluginComponent {
    id: root

    layerNamespacePlugin: "vpn-routes"

    property int refreshSec: Number(pluginData.refreshSec ?? 10)
    property bool showLabel: pluginData.showLabel ?? true
    property bool restartAll: pluginData.restartAll ?? false
    property var report: null
    property string armedKey: ""        // first click arms, second click restarts
    property string restartingKey: ""

    readonly property string scriptPath: Qt.resolvedUrl("vpn-routes.py").toString().replace(/^file:\/\//, "")
    readonly property bool vpnUp: report?.vpn?.up ?? false
    readonly property int issues: report?.issues ?? 0
    readonly property int leaks: report?.leaks ?? 0

    readonly property string pillIcon: !report ? "vpn_lock"
        : !vpnUp ? "vpn_key_off"
        : leaks > 0 ? "gpp_bad"
        : issues > 0 ? "warning"
        : "vpn_lock"
    readonly property color pillColor: !report || !vpnUp ? Theme.surfaceVariantText
        : leaks > 0 ? Theme.error
        : issues > 0 ? Theme.warning
        : Theme.primary
    readonly property string pillText: !report ? "…"
        : !vpnUp ? "VPN off"
        : issues > 0 ? (issues + (issues === 1 ? " app" : " apps"))
        : "VPN"

    function refresh() {
        if (!proc.running)
            proc.running = true;
    }

    onInteractionActiveChanged: if (interactionActive) refresh()

    Process {
        id: proc
        command: ["python3", root.scriptPath]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    root.report = JSON.parse(text);
                } catch (e) {
                    console.warn("vpnRoutes: bad output:", e);
                }
            }
        }
    }

    Process {
        id: restartProc
        property string appName: ""
        stdout: StdioCollector {
            onStreamFinished: {
                let res = null;
                try {
                    res = JSON.parse(text);
                } catch (e) {
                    res = { ok: false, message: "Restart helper gave no answer" };
                }
                if (res.ok)
                    ToastService.showInfo(res.message);
                else
                    ToastService.showError("Couldn't restart " + restartProc.appName, res.message);
            }
        }
        onExited: {
            root.restartingKey = "";
            settleTimer.restart();
        }
    }

    // give a relaunched app a few seconds to open its connections before re-checking
    Timer {
        id: settleTimer
        interval: 5000
        onTriggered: root.refresh()
    }

    Timer {
        id: disarmTimer
        interval: 4000
        onTriggered: root.armedKey = ""
    }

    function restartClicked(a) {
        if (root.restartingKey !== "")
            return;
        if (root.armedKey !== a.key) {
            root.armedKey = a.key;
            disarmTimer.restart();
            return;
        }
        root.armedKey = "";
        disarmTimer.stop();
        root.restartingKey = a.key;
        restartProc.appName = a.name;
        restartProc.command = ["python3", root.scriptPath, "restart", a.key];
        restartProc.running = true;
    }

    Timer {
        interval: Math.max(3, root.refreshSec) * 1000
        repeat: true
        triggeredOnStart: true
        running: root.surfaceLive || root.interactionActive
        onTriggered: root.refresh()
    }

    function rowIcon(a) {
        if (a.status === "leak") return "gpp_bad";
        if (a.status === "restart") return "restart_alt";
        return a.expected === "vpn" ? "lock" : "public";
    }

    function rowColor(a) {
        if (a.status === "leak") return Theme.error;
        if (a.status === "restart") return Theme.warning;
        return a.expected === "vpn" ? Theme.primary : Theme.surfaceVariantText;
    }

    function rowDetail(a) {
        if (a.status === "restart")
            return "Excluded, but " + a.vpn + " conn. still via VPN — restart it";
        if (a.status === "leak")
            return "Should use VPN, " + a.direct + " conn. going direct!";
        if (a.expected === "vpn")
            return "Through VPN · " + a.vpn + " conn.";
        return (root.vpnUp ? "Excluded · " : "Direct · ") + a.direct + " conn.";
    }

    horizontalBarPill: Component {
        Row {
            spacing: Theme.spacingXS

            DIcon {
                name: root.pillIcon
                size: root.iconSize
                color: root.pillColor
                anchors.verticalCenter: parent.verticalCenter
            }

            StyledText {
                visible: root.showLabel
                text: root.pillText
                font.pixelSize: root.textSize
                color: root.issues > 0 && root.vpnUp ? root.pillColor : Theme.surfaceText
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    verticalBarPill: Component {
        DIcon {
            name: root.pillIcon
            size: root.iconSize
            color: root.pillColor
        }
    }

    popoutWidth: 400
    popoutHeight: 460

    popoutContent: Component {
        PopoutComponent {
            id: pop

            headerText: "VPN routing"
            detailsText: !root.report ? "Checking…"
                : !root.vpnUp ? "VPN disconnected — all traffic goes direct"
                : (root.report.vpn.name || "Connected") + " · split tunnelling: "
                  + (root.report.split.enabled ? root.report.split.mode : "off")
            showCloseButton: true

            Item {
                width: parent.width
                implicitHeight: root.popoutHeight - pop.headerHeight - pop.detailsHeight - Theme.spacingXL

                Flickable {
                    id: flick
                    anchors.fill: parent
                    anchors.bottomMargin: footer.height + Theme.spacingS
                    contentHeight: list.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds

                    Column {
                        id: list
                        width: flick.width
                        spacing: Theme.spacingXS

                        StyledText {
                            visible: (root.report?.apps?.length ?? 0) === 0
                            width: parent.width
                            text: "No apps with active internet connections right now."
                            color: Theme.surfaceVariantText
                            font.pixelSize: Theme.fontSizeSmall
                            wrapMode: Text.WordWrap
                        }

                        Repeater {
                            model: root.report?.apps ?? []

                            delegate: StyledRect {
                                required property var modelData
                                width: list.width
                                height: 52
                                radius: Theme.cornerRadius
                                color: modelData.status === "ok" ? Theme.cardSurface : Theme.chipSurface
                                border.width: modelData.status === "ok" ? 0 : 1
                                border.color: root.rowColor(modelData)

                                DIcon {
                                    id: ic
                                    name: root.rowIcon(modelData)
                                    size: Theme.iconSize
                                    color: root.rowColor(modelData)
                                    anchors.left: parent.left
                                    anchors.leftMargin: Theme.spacingM
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Column {
                                    anchors.left: ic.right
                                    anchors.leftMargin: Theme.spacingM
                                    anchors.right: restartBtn.visible ? restartBtn.left : badge.left
                                    anchors.rightMargin: Theme.spacingS
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: 2

                                    StyledText {
                                        width: parent.width
                                        text: modelData.name
                                        font.pixelSize: Theme.fontSizeMedium
                                        font.weight: Font.Medium
                                        color: Theme.surfaceText
                                        elide: Text.ElideRight
                                    }

                                    StyledText {
                                        width: parent.width
                                        text: root.rowDetail(modelData)
                                        font.pixelSize: Theme.fontSizeSmall
                                        color: modelData.status === "ok" ? Theme.surfaceVariantText : root.rowColor(modelData)
                                        elide: Text.ElideRight
                                    }
                                }

                                StyledRect {
                                    id: restartBtn
                                    readonly property bool armed: root.armedKey === modelData.key
                                    readonly property bool busy: root.restartingKey === modelData.key
                                    visible: modelData.status !== "ok" || root.restartAll || busy
                                    anchors.right: badge.left
                                    anchors.rightMargin: Theme.spacingS
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: restartBtnRow.implicitWidth + Theme.spacingS * 2
                                    height: 28
                                    radius: Theme.cornerRadius
                                    opacity: root.restartingKey !== "" && !busy ? 0.4 : 1
                                    color: armed ? root.rowColor(modelData)
                                         : restartMouse.containsMouse ? Theme.chipSurface : Theme.cardSurface
                                    border.width: 1
                                    border.color: armed ? "transparent" : Theme.surfaceTextAlpha

                                    Row {
                                        id: restartBtnRow
                                        anchors.centerIn: parent
                                        spacing: Theme.spacingXS

                                        DIcon {
                                            name: restartBtn.busy ? "hourglass_top" : "restart_alt"
                                            size: Theme.iconSize - 6
                                            color: restartBtn.armed ? Theme.surface : Theme.surfaceText
                                            anchors.verticalCenter: parent.verticalCenter
                                        }

                                        StyledText {
                                            visible: restartBtn.armed || restartBtn.busy
                                            text: restartBtn.busy ? "Restarting…" : "Sure?"
                                            font.pixelSize: Theme.fontSizeSmall
                                            font.weight: Font.Medium
                                            color: restartBtn.armed ? Theme.surface : Theme.surfaceText
                                            anchors.verticalCenter: parent.verticalCenter
                                        }
                                    }

                                    MouseArea {
                                        id: restartMouse
                                        anchors.fill: parent
                                        hoverEnabled: true
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: root.restartClicked(modelData)
                                    }
                                }

                                StyledText {
                                    id: badge
                                    anchors.right: parent.right
                                    anchors.rightMargin: Theme.spacingM
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: modelData.vpn > 0 && modelData.direct > 0 ? "MIXED"
                                        : modelData.vpn > 0 ? "VPN" : "DIRECT"
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.weight: Font.Bold
                                    color: modelData.vpn > 0 ? Theme.primary : Theme.surfaceVariantText
                                }
                            }
                        }
                    }
                }

                Row {
                    id: footer
                    anchors.bottom: parent.bottom
                    anchors.left: parent.left
                    anchors.right: parent.right
                    spacing: Theme.spacingS

                    StyledText {
                        width: parent.width - refreshBtn.width - Theme.spacingS
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Only apps with live internet connections are listed."
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.surfaceVariantText
                        elide: Text.ElideRight
                    }

                    StyledRect {
                        id: refreshBtn
                        width: refreshRow.implicitWidth + Theme.spacingM * 2
                        height: 30
                        radius: Theme.cornerRadius
                        color: refreshMouse.containsMouse ? Theme.chipSurface : Theme.cardSurface

                        Row {
                            id: refreshRow
                            anchors.centerIn: parent
                            spacing: Theme.spacingXS

                            DIcon {
                                name: "refresh"
                                size: Theme.iconSize - 4
                                color: Theme.primary
                                anchors.verticalCenter: parent.verticalCenter
                            }

                            StyledText {
                                text: proc.running ? "Checking…" : "Refresh"
                                font.pixelSize: Theme.fontSizeSmall
                                color: Theme.surfaceText
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }

                        MouseArea {
                            id: refreshMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.refresh()
                        }
                    }
                }
            }
        }
    }
}
