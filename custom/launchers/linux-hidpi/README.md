# Ghidra Linux HiDPI Launcher

A Linux `.desktop` launcher setup for starting Ghidra with Java UI-scaling and font-antialiasing options, so the CodeBrowser is easier to read on high-DPI Linux displays.

## Why this exists

Ghidra is a Java/Swing application. On some HiDPI Linux setups, the default interface can render too small for comfortable reverse-engineering work. Swing applications may also ignore parts of the desktop font-smoothing configuration, which can make text look rough even when normal GTK applications look fine.

This launcher fixes that without modifying Ghidra source code. It passes Java `-D` properties to the JVM at startup.

This setup was originally put together on a Lenovo ThinkPad X13s ARM64 Linux system, where Ghidra usability needed a few manual adjustments.

## What this changes

This does not modify Ghidra source code.

It starts Ghidra with:

| Java option | Effect |
|---|---|
| `-Dsun.java2d.uiScale=2.5` | Scales the Swing UI. Adjust this value for your display. |
| `-Dswing.aatext=true` | Enables antialiased text rendering in Swing components. |
| `-Dawt.useSystemAAFontSettings=on` | Tells AWT/Swing to use system font-smoothing settings. |

## Files

- `ghidra-dev.desktop`  
  Local development launcher for a Ghidra dev build.

- `Ghidra.desktop`  
  Local launcher for an installed ARM64 Ghidra build.

- `ghidra-hidpi-template.desktop`  
  Portable `.desktop` launcher template. Edit the `Exec=` and `Icon=` paths before using it.

## Install on your own system

### 1. Find your Ghidra install path

Your Ghidra folder should contain a file named `ghidraRun`.

Example locations:

```bash
/opt/ghidra-11.4.1/ghidraRun
~/ghidra/ghidraRun
~/Downloads/ghidra_11.x_PUBLIC/ghidraRun
```

Search for it with:

```bash
find ~ /opt -name ghidraRun 2>/dev/null
```

### 2. Copy the launcher template

From this folder:

```bash
cp ghidra-hidpi-template.desktop ~/.local/share/applications/ghidra-hidpi.desktop
```

### 3. Edit the launcher

Open it:

```bash
nano ~/.local/share/applications/ghidra-hidpi.desktop
```

Change these lines:

```text
Exec=env _JAVA_OPTIONS="-Dsun.java2d.uiScale=2.5 -Dswing.aatext=true -Dawt.useSystemAAFontSettings=on" "/CHANGE/ME/path/to/ghidraRun"
Icon=/CHANGE/ME/path/to/support/ghidra.png
```

Example:

```text
Exec=env _JAVA_OPTIONS="-Dsun.java2d.uiScale=2.5 -Dswing.aatext=true -Dawt.useSystemAAFontSettings=on" "/opt/ghidra-11.4.1/ghidraRun"
Icon=/opt/ghidra-11.4.1/support/ghidra.png
```

### 4. Refresh desktop entries

```bash
update-desktop-database ~/.local/share/applications/ 2>/dev/null || true
```

If the launcher does not appear right away, log out and log back in.

## Tuning the scale factor

| Display type | Suggested value |
|---|---|
| 1080p laptop screen | `1.25` or `1.5` |
| 2K / HiDPI laptop display | `2.0` |
| ThinkPad X13s built-in display | `2.5` |
| 4K external monitor | `2.5` or `3.0` |

To change it, edit:

```text
-Dsun.java2d.uiScale=2.5
```

Then relaunch Ghidra.

## Visual analysis workflow

Readable UI matters because reverse engineering is visually dense. A Ghidra project can contain hundreds of functions, generated names, strings, labels, cross-references, and blocks of assembly.

Color-coding and renaming help turn a binary from a wall of assembly into a map.

A simple workflow:

- Rename functions based on evidence, not guesses.
- Use strings and cross-references to locate important behavior.
- Leave runtime/compiler helper functions alone unless they matter.
- Mark reviewed functions so you do not waste time rereading them.
- Mark suspicious or important logic for later review.

Example color system:

| Color | Meaning |
|---|---|
| Green | reviewed or understood |
| Yellow | needs investigation |
| Red | important or suspicious behavior |
| Blue | main program flow |
| Purple | encoding, crypto, or transformation logic |

The point is not decoration. The point is reducing mental load while analyzing code.

## Troubleshooting

### Launcher does not appear

```bash
update-desktop-database ~/.local/share/applications/ 2>/dev/null || true
```

Then log out and log back in.

### Ghidra does not start

Check that the `Exec=` path points to the real `ghidraRun` file:

```bash
ls -l /path/to/ghidraRun
```

Make sure it is executable:

```bash
chmod +x /path/to/ghidraRun
```

### UI scale is too large or too small

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

Check whether fontconfig is returning a normal font:

```bash
fc-match
```

### Decompiler text is still too small

Some Ghidra tool windows have their own font settings. Check Ghidra's tool options and increase the font size for Listing or Decompiler views if needed.

## Tested / developed on

- Lenovo ThinkPad X13s Gen 1
- ARM64 / AArch64 Linux
- Ghidra 11.x and local Ghidra dev build
- GNOME desktop environment

## Notes

This is a usability shim, not a Ghidra extension or plugin. It belongs under `custom/launchers/` rather than `Ghidra/Extensions/`.
