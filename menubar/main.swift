// Menu bar view of macblock. Reads the daemon's world-readable files;
// every change goes through the macblock command with an admin prompt.
import AppKit

let home = "/usr/local/macblock"

func read(_ path: String) -> Data? { FileManager.default.contents(atPath: home + "/" + path) }

func json(_ path: String) -> Any? {
    read(path).flatMap { try? JSONSerialization.jsonObject(with: $0) }
}

final class Menu: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

    func applicationDidFinishLaunching(_ note: Notification) {
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        refresh()
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in self.refresh() }
    }

    var enabled: Bool { FileManager.default.fileExists(atPath: home + "/enabled") }

    var pausedUntil: Date? {
        guard let data = read("pause_until"), let text = String(data: data, encoding: .utf8),
              let when = Double(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              when > Date().timeIntervalSince1970 else { return nil }
        return Date(timeIntervalSince1970: when)
    }

    var blocked: Int { (json("data/stats.json") as? [String: Any])?["blocked"] as? Int ?? 0 }

    func refresh() {
        item.button?.title = !enabled ? "⛔︎ off" : pausedUntil != nil ? "⏸ paused" : "🛡 \(blocked)"
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        menu.removeAllItems()
        func add(_ title: String, _ action: Selector?, _ value: String? = nil, to target: NSMenu? = nil) {
            let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
            entry.target = self
            entry.representedObject = value
            (target ?? menu).addItem(entry)
        }
        add("Blocked: \(blocked)", nil)
        menu.addItem(.separator())
        if enabled {
            if let until = pausedUntil {
                let time = DateFormatter.localizedString(from: until, dateStyle: .none, timeStyle: .short)
                add("Resume (paused until \(time))", #selector(run(_:)), "resume")
            } else {
                add("Pause for 10 minutes", #selector(run(_:)), "pause 10")
            }
        }
        add(enabled ? "Turn off" : "Turn on", #selector(run(_:)), "dns toggle")

        let recent = NSMenu()
        let rows = (json("data/recent.json") as? [[Any]]) ?? []
        for row in rows.reversed().prefix(20) {
            guard row.count > 1, let name = row[1] as? String else { continue }
            add("Allow \(name)", #selector(allow(_:)), name, to: recent)
        }
        let parent = NSMenuItem(title: "Recently blocked", action: nil, keyEquivalent: "")
        parent.submenu = recent
        menu.addItem(parent)
        menu.addItem(.separator())
        add("Quit menu", #selector(quit))
    }

    // Names come from the network, so anything but hostname characters is refused
    // before it gets near a root shell.
    @objc func allow(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String, !name.hasPrefix("-"),
              name.range(of: "^[a-z0-9._-]+$", options: .regularExpression) != nil else { return }
        admin("allow " + name)
    }

    @objc func run(_ sender: NSMenuItem) {
        if let command = sender.representedObject as? String { admin(command) }
    }

    func admin(_ command: String) {
        let source = "do shell script \"/usr/local/bin/macblock \(command) 2>&1\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        if let error = error, error[NSAppleScript.errorNumber] as? Int != -128 {
            let alert = NSAlert()
            alert.messageText = "macblock"
            alert.informativeText = error[NSAppleScript.errorMessage] as? String ?? "command failed"
            alert.runModal()
        }
        refresh()
    }

    @objc func quit() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = Menu()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
