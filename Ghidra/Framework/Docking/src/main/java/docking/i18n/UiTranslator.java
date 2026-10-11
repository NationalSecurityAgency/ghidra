/* ###
 * IP: HexToCode_License
 *
 * HexToCode
 * Copyright (c) 2026 Shmuel Sinay <g47ben@gmail.com>. All rights reserved.
 *
 * Licensed under the HexToCode Restricted License; see the LICENSE file at the
 * root of this distribution. You may not use, copy, modify or distribute this
 * file except as that license allows.
 */
package docking.i18n;

import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.JTextComponent;
import javax.swing.border.TitledBorder;
import javax.swing.table.TableCellRenderer;
import javax.swing.tree.TreeCellRenderer;

import docking.widgets.label.GLabel;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Translates the visible text of the user interface (menus, buttons, labels, tabs, titles,
 * borders and tooltips) at runtime, using a dictionary of exact English phrases.
 * <p>
 * Ghidra builds its UI from hard-coded English strings, so rather than changing every call site,
 * this class listens for components as they are added to the screen and replaces their text
 * with the translated phrase, when one exists. Text with no translation is left unchanged.
 * <p>
 * The language is selected with the {@code ghidra.ui.language} system property (default
 * {@code he}); use {@code en} to disable translation. Dictionaries are UTF-8 resources named
 * {@code /i18n/<language>.txt} holding one {@code English<TAB>Translation} pair per line.
 * Additional dictionaries may be supplied on the classpath as {@code /i18n/<language>-*.txt}
 * listed in {@code /i18n/<language>.extra}. A phrase may contain one placeholder: {@code {0}}
 * (translated as well) or {@code {name}} (kept as-is), for example
 * {@code Close '{name}'<TAB>סגור את '{name}'}.
 */
public class UiTranslator {

	public static final String LANGUAGE_PROPERTY = "ghidra.ui.language";
	private static final String DEFAULT_LANGUAGE = "he";

	private static final String HOOKED_KEY = "docking.i18n.hooked";

	// Trailing decorations that are stripped before looking a phrase up and then re-applied
	private static final Pattern DECORATED =
		Pattern.compile("^(\\s*)(.*?)(\\s*(?:\\.\\.\\.|:|\\s-|\\s\\.\\.\\.)?\\s*)$", Pattern.DOTALL);

	// "Copy (Ctrl+C)", "Delete Selected Symbols (Delete)": a key binding appended to a tooltip
	private static final Pattern KEY_BINDING_SUFFIX = Pattern.compile(
		"^(.+?)(\\s+\\((?:(?:Ctrl|Alt|Shift|Meta|Cmd|Command|Option)\\+[^)]*|F\\d{1,2}|Delete|" +
			"Del|Enter|Escape|Insert|Home|End|Space|Tab|[A-Z0-9])\\))$");

	private static volatile Map<String, String> dictionary = Map.of();
	private static volatile List<PatternEntry> patterns = List.of();

	/**
	 * A dictionary entry with a placeholder: {@code {0}} is translated recursively (e.g.
	 * "Display {0}"), {@code {name}} is kept as-is (e.g. a program name in "Close '{name}'").
	 */
	private record PatternEntry(Pattern pattern, String template, boolean translateArg) {}
	private static volatile boolean installed;
	private static volatile boolean rightToLeft;

	// The product name shown instead of "Ghidra" (the application.name property), or null
	private static volatile String brand;
	private static final Pattern GHIDRA_WORD = Pattern.compile("\\bGhidra\\b");
	private static final Set<Window> HOOKED_WINDOWS =
		Collections.newSetFromMap(new WeakHashMap<>());
	private static final ThreadLocal<Boolean> UPDATING = ThreadLocal.withInitial(() -> false);

	private static final PropertyChangeListener TEXT_LISTENER = e -> {
		if (UPDATING.get()) {
			return;
		}
		Object source = e.getSource();
		if (source instanceof Component c) {
			translateComponent(c);
		}
	};

	private UiTranslator() {
		// utility class
	}

	/**
	 * Loads the dictionary for the configured language and starts translating every window.
	 * Safe to call more than once.
	 */
	public static synchronized void install() {
		if (installed) {
			return;
		}
		String language = getLanguage();
		if (!language.isEmpty() && !language.equals("en")) {
			dictionary = loadDictionary(language);
		}
		brand = findBrand();
		if (dictionary.isEmpty() && brand == null) {
			return;
		}
		installed = true;
		rightToLeft = !dictionary.isEmpty() &&
			!ComponentOrientation.getOrientation(Locale.forLanguageTag(language)).isLeftToRight();

		Toolkit.getDefaultToolkit()
				.addAWTEventListener(UiTranslator::eventDispatched,
					AWTEvent.CONTAINER_EVENT_MASK | AWTEvent.WINDOW_EVENT_MASK);

		SwingUtilities.invokeLater(() -> {
			for (Window w : Window.getWindows()) {
				translateTree(w);
			}
		});
	}

	private static String findBrand() {
		try {
			String name = Application.isInitialized() ? Application.getName() : null;
			return name == null || name.isBlank() || name.equals("Ghidra") ? null : name;
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * @return the configured UI language code (for example {@code he} or {@code en})
	 */
	public static String getLanguage() {
		return System.getProperty(LANGUAGE_PROPERTY, DEFAULT_LANGUAGE).strip().toLowerCase();
	}

	/**
	 * @return true if translation is active
	 */
	public static boolean isActive() {
		return installed;
	}

	/**
	 * Returns the translation of the given UI text, or the text itself if there is none.
	 * Leading/trailing whitespace and a trailing "...", ":" or " -" are preserved.
	 * @param text the English text
	 * @return the translated text
	 */
	public static String translate(String text) {
		String result = doTranslate(text);
		String name = brand;
		if (name != null && result != null && result.contains("Ghidra")) {
			// the product is shown under its own name; "GhidraScript" etc. are left alone
			result = GHIDRA_WORD.matcher(result).replaceAll(name);
		}
		return result;
	}

	private static String doTranslate(String text) {
		Map<String, String> dict = dictionary;
		if (text == null || text.isEmpty() || dict.isEmpty()) {
			return text;
		}
		String direct = dict.get(text);
		if (direct != null) {
			return direct;
		}
		if (text.startsWith("<html>") || text.startsWith("<HTML>")) {
			return text;
		}

		Matcher m = DECORATED.matcher(text);
		if (m.matches()) {
			String core = m.group(2);
			String found = lookupCore(dict, core);
			if (found != null) {
				return m.group(1) + found + m.group(3);
			}
			// "Label: value" - translate just the label part
			int colon = core.indexOf(": ");
			if (colon > 0) {
				String label = dict.get(core.substring(0, colon));
				if (label != null) {
					return m.group(1) + label + core.substring(colon) + m.group(3);
				}
			}
		}

		// "Copy (Ctrl+C)": translate the text, keep the key binding
		Matcher key = KEY_BINDING_SUFFIX.matcher(text);
		if (key.matches()) {
			String head = translate(key.group(1));
			if (!head.equals(key.group(1))) {
				return head + key.group(2);
			}
		}

		// "Memory Map [CodeBrowser: /prog]" and "Functions - 2 items": translate the leading
		// window or component name, keep the rest
		for (String separator : new String[] { " [", " - " }) {
			int i = text.indexOf(separator);
			if (i > 0) {
				String head = text.substring(0, i);
				String translated = translate(head);
				if (!translated.equals(head)) {
					return translated + text.substring(i);
				}
			}
		}
		return text;
	}

	private static String lookupCore(Map<String, String> dict, String core) {
		String found = dict.get(core);
		if (found == null) {
			// Many menu items differ only in letter case ("Zoom In" / "Zoom in")
			found = dict.get(core.toLowerCase(Locale.ROOT));
		}
		if (found == null) {
			for (PatternEntry entry : patterns) {
				Matcher m = entry.pattern().matcher(core);
				if (m.matches()) {
					String arg = m.group(1);
					String value = entry.translateArg() ? translate(arg) : arg;
					return entry.template().replace(entry.translateArg() ? "{0}" : "{name}", value);
				}
			}
		}
		return found;
	}

	private static Map<String, String> loadDictionary(String language) {
		Map<String, String> map = new HashMap<>();
		List<PatternEntry> patternList = new ArrayList<>();
		readResource("/i18n/" + language + ".txt", map);
		String extras = readResourceText("/i18n/" + language + ".extra");
		if (extras != null) {
			for (String line : extras.split("\\R")) {
				if (!line.isBlank()) {
					readResource("/i18n/" + line.strip(), map);
				}
			}
		}
		for (Iterator<Map.Entry<String, String>> it = map.entrySet().iterator(); it.hasNext();) {
			Map.Entry<String, String> e = it.next();
			String key = e.getKey();
			boolean translateArg = key.contains("{0}");
			if (translateArg || key.contains("{name}")) {
				it.remove();
				patternList.add(new PatternEntry(Pattern.compile(toRegex(key)), e.getValue(),
					translateArg));
			}
		}
		// most specific (longest) patterns first
		patternList.sort(Comparator.comparingInt(
			(PatternEntry p) -> p.pattern().pattern().length()).reversed());
		patterns = List.copyOf(patternList);
		return Collections.unmodifiableMap(map);
	}

	private static String toRegex(String key) {
		String placeholder = key.contains("{0}") ? "{0}" : "{name}";
		int i = key.indexOf(placeholder);
		return Pattern.quote(key.substring(0, i)) + "(.+?)" +
			Pattern.quote(key.substring(i + placeholder.length()));
	}

	private static void readResource(String path, Map<String, String> map) {
		String text = readResourceText(path);
		if (text == null) {
			return;
		}
		for (String line : text.split("\\R")) {
			// a comment is a '#' line without a tab ("# Refs<TAB>..." is a real phrase)
			if (line.isEmpty() || line.startsWith("#") && line.indexOf('\t') < 0) {
				continue;
			}
			int tab = line.indexOf('\t');
			if (tab <= 0 || tab == line.length() - 1) {
				continue;
			}
			String key = line.substring(0, tab);
			String value = line.substring(tab + 1).strip();
			map.put(key, value);
			if (!key.contains("{")) {
				map.putIfAbsent(key.toLowerCase(Locale.ROOT), value);
			}
		}
	}

	private static String readResourceText(String path) {
		try (InputStream is = UiTranslator.class.getResourceAsStream(path)) {
			if (is == null) {
				return null;
			}
			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			Msg.error(UiTranslator.class, "Unable to read UI dictionary " + path, e);
			return null;
		}
	}

	private static void eventDispatched(AWTEvent event) {
		if (event instanceof ContainerEvent ce && ce.getID() == ContainerEvent.COMPONENT_ADDED) {
			translateTree(ce.getChild());
		}
		else if (event instanceof WindowEvent we && we.getID() == WindowEvent.WINDOW_OPENED) {
			translateTree(we.getWindow());
		}
	}

	private static void translateTree(Component c) {
		if (c == null || isDataRenderer(c)) {
			return;
		}
		translateComponent(c);
		if (c instanceof JMenu menu) {
			// menu items live in the popup, which is not a child of the menu until shown
			translateTree(menu.getPopupMenu());
		}
		if (c instanceof Container container) {
			for (Component child : container.getComponents()) {
				translateTree(child);
			}
		}
	}

	/**
	 * Cell renderers display program data (symbol names, types, values...), which must never be
	 * translated: a function named "Delete" has to stay "Delete".
	 */
	private static boolean isDataRenderer(Component c) {
		return c instanceof TableCellRenderer || c instanceof ListCellRenderer ||
			c instanceof TreeCellRenderer || c instanceof CellRendererPane ||
			c.getParent() instanceof CellRendererPane || c instanceof JTextComponent;
	}

	private static void translateComponent(Component c) {
		if (isDataRenderer(c)) {
			return;
		}
		UPDATING.set(true);
		try {
			doTranslateComponent(c);
		}
		catch (RuntimeException e) {
			// never let translation break the UI
			Msg.debug(UiTranslator.class, "Unable to translate " + c.getClass().getName(), e);
		}
		finally {
			UPDATING.set(false);
		}
	}

	private static void doTranslateComponent(Component c) {
		if (rightToLeft && (c instanceof JPopupMenu || c instanceof JMenuItem)) {
			// menus read naturally right-to-left; other layouts are left alone
			c.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
		}
		if (c instanceof AbstractButton b) {
			String text = b.getText();
			String t = translate(text);
			if (!Objects.equals(text, t)) {
				// code may rely on the action command, which defaults to the button text
				if (b.getModel().getActionCommand() == null) {
					b.setActionCommand(text);
				}
				b.setText(t);
			}
		}
		else if (c instanceof JLabel label && !(label instanceof GLabel)) {
			String text = label.getText();
			String t = translate(text);
			if (!Objects.equals(text, t)) {
				label.setText(t);
			}
		}
		else if (c instanceof JTabbedPane tabs) {
			for (int i = 0; i < tabs.getTabCount(); i++) {
				String text = tabs.getTitleAt(i);
				String t = translate(text);
				if (!Objects.equals(text, t)) {
					tabs.setTitleAt(i, t);
				}
			}
		}
		else if (c instanceof Frame f) {
			translateTitle(f.getTitle(), f::setTitle);
		}
		else if (c instanceof Dialog d) {
			translateTitle(d.getTitle(), d::setTitle);
		}

		if (c instanceof JComponent jc) {
			String tip = jc.getToolTipText();
			String t = translate(tip);
			if (!Objects.equals(tip, t)) {
				jc.setToolTipText(t);
			}
			Border border = jc.getBorder();
			if (border instanceof TitledBorder tb) {
				String title = tb.getTitle();
				String tt = translate(title);
				if (!Objects.equals(title, tt)) {
					tb.setTitle(tt);
				}
			}
		}

		hook(c);
	}

	private static void translateTitle(String title, java.util.function.Consumer<String> setter) {
		String t = translate(title);
		if (!Objects.equals(title, t)) {
			setter.accept(t);
		}
	}

	/** Re-translate when the component's text changes later (e.g. dynamic menu names). */
	private static void hook(Component c) {
		if (c instanceof Window w) {
			if (HOOKED_WINDOWS.add(w)) {
				w.addPropertyChangeListener("title", TEXT_LISTENER);
			}
			return;
		}
		if (!(c instanceof JComponent jc) || jc.getClientProperty(HOOKED_KEY) != null) {
			return;
		}
		jc.putClientProperty(HOOKED_KEY, Boolean.TRUE);
		jc.addPropertyChangeListener("text", TEXT_LISTENER);
		jc.addPropertyChangeListener(JComponent.TOOL_TIP_TEXT_KEY, TEXT_LISTENER);
		if (jc instanceof JTabbedPane tabs) {
			tabs.addChangeListener(e -> translateComponent(tabs));
		}
	}
}
