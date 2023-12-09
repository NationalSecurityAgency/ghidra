/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package generic.theme.laf;

import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.plaf.*;

import org.apache.commons.collections4.IteratorUtils;

import generic.theme.*;
import generic.util.action.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Manages installing and updating a {@link LookAndFeel}
 */
public abstract class LookAndFeelManager {

	private LafType laf;
	private Map<String, ComponentFontRegistry> fontRegistryMap = new HashMap<>();
	protected ApplicationThemeManager themeManager;
	protected Map<String, String> normalizedIdToLafIdMap;

	protected LookAndFeelManager(LafType laf, ApplicationThemeManager themeManager) {
		this.laf = laf;
		this.themeManager = themeManager;
	}

	/**
	 * Returns the {@link LafType} managed by this manager.
	 * @return the {@link LafType}
	 */
	public LafType getLookAndFeelType() {
		return laf;
	}

	/**
	 * Installs the {@link LookAndFeel}
	 * @throws ClassNotFoundException if the <code>LookAndFeel</code>
	 *           class could not be found
	 * @throws InstantiationException if a new instance of the class
	 *          couldn't be created
	 * @throws IllegalAccessException if the class or initializer isn't accessible
	 * @throws UnsupportedLookAndFeelException if
	 *          <code>lnf.isSupportedLookAndFeel()</code> is false
	 */
	public void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		doInstallLookAndFeel();
		processJavaDefaults();
		fixupLookAndFeelIssues();
		installCustomLookAndFeelActions();
		updateComponentUis();
	}

	/**
	 * Called when all colors, fonts, and icons may have changed
	 * @param javaDefaults the current set of java defaults so that those ids can be updated
	 * special as needed by the current {@link LookAndFeel}
	 */
	public void resetAll(GThemeValueMap javaDefaults) {
		themeManager.refreshGThemeValues();
		resetIcons(javaDefaults);
		resetFonts(javaDefaults);
		updateAllRegisteredComponentFonts();
		updateComponentUis();
	}

	protected void updateAllRegisteredComponentFonts() {
		for (ComponentFontRegistry register : fontRegistryMap.values()) {
			register.updateComponentFonts();
		}
	}

	private void resetFonts(GThemeValueMap javaDefaults) {
		List<FontValue> fonts = javaDefaults.getFonts();
		UIDefaults defaults = UIManager.getDefaults();
		for (FontValue fontValue : fonts) {
			String id = fontValue.getId();
			String lafId = normalizedIdToLafIdMap.get(id);
			if (lafId == null) {
				continue;
			}
			Font correctFont = Gui.getFont(id);
			Font storedFont = defaults.getFont(id);
			if (correctFont != null && !correctFont.equals(storedFont)) {
				defaults.put(lafId, toUiResource(correctFont));
			}
		}
	}

	private void resetIcons(GThemeValueMap javaDefaults) {
		List<IconValue> icons = javaDefaults.getIcons();
		UIDefaults defaults = UIManager.getDefaults();
		for (IconValue iconValue : icons) {
			String id = iconValue.getId();
			String lafId = normalizedIdToLafIdMap.get(id);
			Icon correctIcon = Gui.getIcon(id);
			Icon storedIcon = defaults.getIcon(id);
			if (correctIcon != null && !correctIcon.equals(storedIcon)) {
				defaults.put(lafId, correctIcon);
			}
		}
	}

	/**
	 * Called when one or more colors have changed.
	 */
	public void colorsChanged() {
		themeManager.refreshGThemeValues();
		repaintAll();
	}

	/**
	 * Called when one or more icons have changed.
	 * @param changedIconIds set of icon ids affected by this icon change
	 * @param newIcon the new icon to use for the given set of icon ids
	 */
	public void iconsChanged(Set<String> changedIconIds, Icon newIcon) {
		UIDefaults defaults = UIManager.getDefaults();
		if (!(newIcon instanceof UIResource)) {
			newIcon = new IconUIResource(newIcon);
		}
		for (String changedIconId : changedIconIds) {
			String lafIconId = normalizedIdToLafIdMap.get(changedIconId);
			defaults.put(lafIconId, newIcon);
		}

		if (!changedIconIds.isEmpty()) {
			updateComponentUis();
		}
		themeManager.refreshGThemeValues();
		repaintAll();
	}

	/**
	 * Called when one or more fonts have changed.
	 * <p>
	 * This will update the Java {@link UIManager} and trigger a reload of the UIs.
	 * 
	 * @param changedFontIds the set of Java Font ids that are affected by this change; these are
	 * the normalized ids
	 */
	public void fontsChanged(Set<String> changedFontIds) {
		UIDefaults defaults = UIManager.getDefaults();
		for (String changedFontId : changedFontIds) {
			// even though all these derive from the new font, they might be different
			// because of FontModifiers.
			Font font = Gui.getFont(changedFontId);
			String javaFontId = normalizedIdToLafIdMap.get(changedFontId);
			if (javaFontId != null) {
				// lafFontId is null for group ids
				defaults.put(javaFontId, new FontUIResource(font));
			}
		}

		if (!changedFontIds.isEmpty()) {
			updateComponentUis();
		}

		updateAllRegisteredComponentFonts();
		repaintAll();
	}

	protected void updateComponentUis() {
		for (Window window : Window.getWindows()) {
			SwingUtilities.updateComponentTreeUI(window);
		}
	}

	protected void repaintAll() {
		for (Window window : Window.getWindows()) {
			window.repaint();
		}
	}

	/**
	 * Binds the component to the font identified by the given font id. Whenever the font for
	 * the font id changes, the component will be updated with the new font.
	 * @param component the component to set/update the font
	 * @param fontId the id of the font to register with the given component
	 */
	public void registerFont(Component component, String fontId) {
		ComponentFontRegistry register =
			fontRegistryMap.computeIfAbsent(fontId, id -> new ComponentFontRegistry(id));

		register.addComponent(component);
	}

	private Font toUiResource(Font font) {
		if (!(font instanceof UIResource)) {
			return new FontUIResource(font);
		}
		return font;
	}

	/**
	 * Subclasses may override this method to install a specific look and feel.
	 *
	 * @throws ClassNotFoundException if the <code>LookAndFeel</code>
	 *           class could not be found
	 * @throws InstantiationException if a new instance of the class
	 *          couldn't be created
	 * @throws IllegalAccessException if the class or initializer isn't accessible
	 * @throws UnsupportedLookAndFeelException if
	 *          <code>lnf.isSupportedLookAndFeel()</code> is false
	 */
	protected void doInstallLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {
		String name = laf.getName();
		UIManager.setLookAndFeel(findLookAndFeelClassName(name));

	}

	/**
	 * Subclass may override this method to do specific LookAndFeel fixes.
	 * <p>
	 * This will get called after default values are loaded.  This means that any values installed
	 * by this method will overwrite any values registered by the theme.
	 * <p>
	 * Standard properties, such as strings and booleans, can be set inside of the theme
	 * properties files.  For more complicated UIManager properties, look and feel classes will
	 * need to override this method and install those directly.
	 * <p>
	 * Any property installed here will not fully be part of the theme system, but rather will be
	 * directly installed into the Java Look and Feel.  Thus, properties installed here will be
	 * hard-coded overrides for the system.  If we decided that a hard-coded value should be put
	 * into the theme system, then we will need to add support for that property type so that it
	 * can be used when loading the theme files.
	 */
	protected void fixupLookAndFeelIssues() {
		installGlobalFontSizeOverride();
	}

	/**
	 * Extracts java default colors, fonts, and icons and stores them in the
	 * {@link ThemeManager} and updates the {@link UIDefaults} by installing GColors for all
	 * color values and installing any overridden fonts or icons.
	 */
	protected void processJavaDefaults() {
		UIDefaults defaults = UIManager.getDefaults();
		UiDefaultsMapper uiDefaultsMapper = createUiDefaultsMapper(defaults);
		GThemeValueMap javaDefaults = uiDefaultsMapper.getNormalizedJavaDefaults();
		themeManager.setJavaDefaults(javaDefaults);
		uiDefaultsMapper.installValuesIntoUIDefaults(themeManager.getCurrentValues());
		normalizedIdToLafIdMap = uiDefaultsMapper.getNormalizedIdToLafIdMap();
	}

	protected abstract UiDefaultsMapper createUiDefaultsMapper(UIDefaults defaults);

	protected String findLookAndFeelClassName(String lookAndFeelName) {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			String className = info.getClassName();
			if (lookAndFeelName.equals(className) || lookAndFeelName.equals(info.getName())) {
				return className;
			}
		}

		Msg.debug(this, "Unable to find requested Look and Feel: " + lookAndFeelName);
		return UIManager.getSystemLookAndFeelClassName();
	}

	protected boolean isSupported(String lookAndFeelName) {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			if (lookAndFeelName.equals(info.getName())) {
				return true;
			}
		}
		return false;
	}

	protected void setKeyBinding(String existingKsText, String newKsText,
			String[] prefixValues) {

		KeyStroke existingKs = KeyStroke.getKeyStroke(existingKsText);
		KeyStroke newKs = KeyStroke.getKeyStroke(newKsText);
		UIDefaults uiDefaults = UIManager.getDefaults();
		for (String properyPrefix : prefixValues) {
			Object object = uiDefaults.get(properyPrefix + ".focusInputMap");
			InputMap inputMap = (InputMap) object;
			Object action = inputMap.get(existingKs);
			inputMap.put(newKs, action);
		}
	}

	private void installGlobalFontSizeOverride() {

		// only set a global size if the property is set
		Integer overrideFontInteger = SystemUtilities.getFontSizeOverrideValue();
		if (overrideFontInteger == null) {
			return;
		}

		setGlobalFontSizeOverride(overrideFontInteger);
	}

	private void installCustomLookAndFeelActions() {
		// these prefixes are for text components
		String[] UIPrefixValues =
			{ "TextField", "FormattedTextField", "TextArea", "TextPane", "EditorPane" };

		DeleteToStartOfWordAction deleteToStartOfWordAction = new DeleteToStartOfWordAction();
		registerAction(deleteToStartOfWordAction, DeleteToStartOfWordAction.KEY_STROKE,
			UIPrefixValues);

		DeleteToEndOfWordAction deleteToEndOfWordAction = new DeleteToEndOfWordAction();
		registerAction(deleteToEndOfWordAction, DeleteToEndOfWordAction.KEY_STROKE, UIPrefixValues);

		BeginningOfLineAction beginningOfLineAction = new BeginningOfLineAction();
		registerAction(beginningOfLineAction, BeginningOfLineAction.KEY_STROKE, UIPrefixValues);

		EndOfLineAction endOfLineAction = new EndOfLineAction();
		registerAction(endOfLineAction, EndOfLineAction.KEY_STROKE, UIPrefixValues);

		SelectBeginningOfLineAction selectBeginningOfLineAction = new SelectBeginningOfLineAction();
		registerAction(selectBeginningOfLineAction, SelectBeginningOfLineAction.KEY_STROKE,
			UIPrefixValues);

		SelectEndOfLineAction selectEndOfLineAction = new SelectEndOfLineAction();
		registerAction(selectEndOfLineAction, SelectEndOfLineAction.KEY_STROKE, UIPrefixValues);
	}

	/** Allows you to globally set the font size (don't use this method!) */
	private void setGlobalFontSizeOverride(int fontSize) {
		UIDefaults defaults = UIManager.getDefaults();

		Set<Entry<Object, Object>> set = defaults.entrySet();
		Iterator<Entry<Object, Object>> iterator = set.iterator();
		while (iterator.hasNext()) {
			Entry<Object, Object> entry = iterator.next();
			Object key = entry.getKey();

			if (key.toString().toLowerCase().indexOf("font") != -1) {
				Font currentFont = defaults.getFont(key);
				if (currentFont != null) {
					Font newFont = currentFont.deriveFont((float) fontSize);
					UIManager.put(key, newFont);
				}
			}
		}
	}

	private void registerAction(Action action, KeyStroke keyStroke, String[] prefixValues) {
		for (String properyPrefix : prefixValues) {
			UIDefaults defaults = UIManager.getDefaults();
			Object object = defaults.get(properyPrefix + ".focusInputMap");
			InputMap inputMap = (InputMap) object;
			inputMap.put(keyStroke, action);
		}
	}

	/**
	 * Searches the given UIDefaults for ids whose value matches the given class
	 * @param defaults the UIDefaults to search
	 * @param clazz the value class to look for (i.e., Color, Font, or Icon)
	 * @return the list of ids whose value is of the given class type.
	 */
	public static List<String> getLookAndFeelIdsForType(UIDefaults defaults, Class<?> clazz) {
		List<String> colorKeys = new ArrayList<>();
		List<Object> keyList = IteratorUtils.toList(defaults.keys().asIterator());
		for (Object key : keyList) {
			if (key instanceof String) {
				Object value = defaults.get(key);
				if (clazz.isInstance(value)) {
					colorKeys.add((String) key);
				}
			}
		}
		return colorKeys;
	}

}
