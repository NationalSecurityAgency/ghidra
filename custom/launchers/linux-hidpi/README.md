# Ghidra Linux HiDPI Launcher

A Linux `.desktop` launcher setup for starting Ghidra with Java UI-scaling and font-antialiasing options, so the Ghidra CodeBrowser is easier to read on high-DPI Linux displays.

This was developed while running Ghidra on a Lenovo ThinkPad X13s ARM64 Linux setup, but the launcher template can be adapted for other Linux machines.

## Why this exists

Ghidra is a Java/Swing application. On some Linux desktop environments, especially high-DPI displays, the interface can render too small for comfortable reverse-engineering work.

This launcher fixes that by passing Java display options to the JVM at startup.

This does not modify Ghidra source code. It only changes how Ghidra is launched.

## What it changes

The launcher starts Ghidra with these Java options:

| Option | Purpose |
|---|---|
| `-Dsun.java2d.uiScale=2.5` | Scales the Java/Swing interface. |
| `-Dswing.aatext=true` | Enables antialiased text rendering. |
| `-Dawt.useSystemAAFontSettings=on` | Uses system font-smoothing settings. |

## Files

| File | Purpose |
|---|---|
| `ghidra-dev.desktop` | My local launcher for a Ghidra development build. |
| `Ghidra.desktop` | My local launcher for an installed ARM64 Ghidra build. |
| `ghidra-hidpi-template.desktop` | Portable launcher template for other users. |

## Install on your own Linux system

### 0. Get the launcher template

Either clone the repo and switch to this folder:

```bash
git clone https://github.com/WinnCore/ghidra.git
cd ghidra
git checkout hidpi-launcher-arm64
cd custom/launchers/linux-hidpi
```

Or download just the template file directly, without cloning the whole repo:

```bash
curl -O https://raw.githubusercontent.com/WinnCore/ghidra/hidpi-launcher-arm64/custom/launchers/linux-hidpi/ghidra-hidpi-template.desktop
```

### 1. Find your Ghidra install

Find the `ghidraRun` file:

```bash
find ~ /opt -name ghidraRun 2>/dev/null
```

Common examples:

```text
/opt/ghidra-11.4.1/ghidraRun
~/Downloads/ghidra_11.x_PUBLIC/ghidraRun
~/ghidra/ghidraRun
```

Also find the icon:

```bash
find ~ /opt -path "*support/ghidra.png" 2>/dev/null
```

### 2. Copy the launcher template

From this folder:

```bash
cp ghidra-hidpi-template.desktop ~/.local/share/applications/ghidra-hidpi.desktop
```

### 3. Edit the copied launcher

```bash
nano ~/.local/share/applications/ghidra-hidpi.desktop
```

Change these two lines:

```text
Exec=env _JAVA_OPTIONS="-Dsun.java2d.uiScale=2.5 -Dswing.aatext=true -Dawt.useSystemAAFontSettings=on" "/CHANGE/ME/path/to/ghidraRun"
Icon=/CHANGE/ME/path/to/support/ghidra.png
```

Example:

```text
Exec=env _JAVA_OPTIONS="-Dsun.java2d.uiScale=2.5 -Dswing.aatext=true -Dawt.useSystemAAFontSettings=on" "/opt/ghidra-11.4.1/ghidraRun"
Icon=/opt/ghidra-11.4.1/support/ghidra.png
```

### 4. Refresh the application menu

```bash
update-desktop-database ~/.local/share/applications/ 2>/dev/null || true
```

If it does not appear, log out and log back in.

Then launch:

```text
Ghidra HiDPI
```

from the app menu.

## Tuning the scale

The value `2.5` may not be right for every display.

| Display                        | Suggested value |
| ------------------------------ | --------------- |
| 1080p laptop                   | `1.25` or `1.5` |
| 2K laptop display              | `2.0`           |
| ThinkPad X13s built-in display | `2.5`           |
| 4K monitor                     | `2.5` or `3.0`  |

Edit this part:

```text
-Dsun.java2d.uiScale=2.5
```

Then relaunch Ghidra.

## Visual analysis workflow

Readable UI matters because reverse engineering is visually dense. Ghidra projects can contain many functions, generated names, labels, strings, cross-references, and blocks of assembly.

A simple visual workflow helps:

* Rename functions based on evidence.
* Use strings and cross-references to locate important behavior.
* Leave compiler/runtime helper functions alone unless they matter.
* Mark reviewed functions so they are not repeatedly reanalyzed.
* Use color-coding to separate known, unknown, suspicious, and important code.

Example color system:

| Color  | Meaning                                   |
| ------ | ----------------------------------------- |
| Green  | reviewed or understood                    |
| Yellow | needs investigation                       |
| Red    | important or suspicious behavior          |
| Blue   | main program flow                         |
| Purple | encoding, crypto, or transformation logic |

The point is not decoration. The point is reducing mental load while analyzing code.

## Troubleshooting

### Launcher does not appear

```bash
update-desktop-database ~/.local/share/applications/ 2>/dev/null || true
```

Then log out and log back in.

### Ghidra does not start

Check the path:

```bash
ls -l /path/to/ghidraRun
```

Make sure it is executable:

```bash
chmod +x /path/to/ghidraRun
```

### Scale is too large or too small

Edit:

```text
-Dsun.java2d.uiScale=2.5
```

Try `1.5`, `2.0`, `2.5`, or `3.0`.

### Fonts still look rough

Check GNOME font antialiasing:

```bash
gsettings get org.gnome.desktop.interface font-antialiasing
```

Check fontconfig:

```bash
fc-match
```

### Decompiler text is still too small

Some Ghidra views have their own font settings. Open Ghidra tool options and increase the font size for Listing or Decompiler views if needed.

## Developed on

* Lenovo ThinkPad X13s Gen 1
* ARM64 / AArch64 Linux
* GNOME desktop environment
* Ghidra 11.x and local Ghidra development build

## Notes

This is a launcher/configuration usability shim, not a Ghidra plugin or extension.

It belongs under:

```text
custom/launchers/
```

not:

```text
Ghidra/Extensions/
```
