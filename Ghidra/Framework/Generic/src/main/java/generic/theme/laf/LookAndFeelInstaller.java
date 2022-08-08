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

import java.awt.Color;
import java.awt.Font;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.UIManager.LookAndFeelInfo;

import org.apache.commons.collections4.IteratorUtils;

import generic.theme.*;
import generic.util.action.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Installs a specific {@link LookAndFeel} into the {@link UIManager}. The idea is that there
 * is a specific installer for each supported {@link LookAndFeel} to handle unique needs for
 * that LookAndFeel. Subclasses can also override {@link #fixupLookAndFeelIssues()} to make
 * UI tweaks to specific LookAndFeels.
 */
public class LookAndFeelInstaller {

	private LafType lookAndFeel;

	public LookAndFeelInstaller(LafType lookAndFeel) {
		this.lookAndFeel = lookAndFeel;
	}

	/**
	 * Installs the {@link LookAndFeel} associated with this installer
	 * @throws ClassNotFoundException if the <code>LookAndFeel</code>
	 *           class could not be found
	 * @throws InstantiationException if a new instance of the class
	 *          couldn't be created
	 * @throws IllegalAccessException if the class or initializer isn't accessible
	 * @throws UnsupportedLookAndFeelException if
	 *          <code>lnf.isSupportedLookAndFeel()</code> is false
	 */
	public void install() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {
		cleanUiDefaults();
		installLookAndFeel();
		installJavaDefaults();
		fixupLookAndFeelIssues();
		installGlobalProperties();
	}

	/**
	 * Subclass provide this method to install the specific loo
	 * @throws ClassNotFoundException if the <code>LookAndFeel</code>
	 *           class could not be found
	 * @throws InstantiationException if a new instance of the class
	 *          couldn't be created
	 * @throws IllegalAccessException if the class or initializer isn't accessible
	 * @throws UnsupportedLookAndFeelException if
	 *          <code>lnf.isSupportedLookAndFeel()</code> is false
	 */
	protected void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {
		String name = lookAndFeel.getName();
		UIManager.setLookAndFeel(findLookAndFeelClassName(name));

	}

	/**
	 * Subclass can override this method to do specific LookAndFeel fix ups
	 */
	protected void fixupLookAndFeelIssues() {
		// no generic fix-ups at this time.
	}

	/**
	 * Installs Colors, Fonts, and Icons into the UIDefaults. Subclasses my override this if they need to install
	 * UI properties in a different way.
	 */
	protected void installJavaDefaults() {
		GThemeValueMap javaDefaults = extractJavaDefaults();
		Gui.setJavaDefaults(javaDefaults);
		installPropertiesBackIntoUiDefaults(javaDefaults);
	}

	private void installPropertiesBackIntoUiDefaults(GThemeValueMap javaDefaults) {
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			GColorUIResource gColor = Gui.getGColorUiResource(id);
			defaults.put(id, gColor);
		}
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			//Note: fonts don't support indirect values, so there is no GFont object
			Font font = Gui.getFont(id);
			defaults.put(id, font);
		}
//		for (IconValue iconValue : javaDefaults.getIcons()) {
//			String id = iconValue.getId();
//			GIconUIResource gIcon = Gui.getGIconUiResource(id);
//			defaults.put(id, gIcon);
//		}
	}

	protected GThemeValueMap extractJavaDefaults() {
		return extractJavaDefaults(UIManager.getDefaults());
	}

	protected static GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
		GThemeValueMap values = new GThemeValueMap();
		// for now, just doing color properties.
		List<String> ids = getLookAndFeelIdsForType(defaults, Color.class);
		for (String id : ids) {
			// only use standard java colors here to avoid weird issues (such as GColor not
			// resolving or ColorUIResource not being honored. Later we will go back
			// and fix up the java defaults to use standard java color indirection
			values.addColor(new ColorValue(id, getNormalizedColor(UIManager.getColor(id))));
		}
		ids = getLookAndFeelIdsForType(defaults, Font.class);
		for (String id : ids) {
			values.addFont(new FontValue(id, UIManager.getFont(id)));
		}
		ids = getLookAndFeelIdsForType(defaults, Icon.class);
		for (String id : ids) {
			Icon icon = UIManager.getIcon(id);
			values.addIcon(new IconValue(id, icon));
		}

		return values;
	}

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

	protected void setKeyBinding(String existingKsText, String newKsText, String[] prefixValues) {

		KeyStroke existingKs = KeyStroke.getKeyStroke(existingKsText);
		KeyStroke newKs = KeyStroke.getKeyStroke(newKsText);

		for (String properyPrefix : prefixValues) {

			UIDefaults defaults = UIManager.getDefaults();
			Object object = defaults.get(properyPrefix + ".focusInputMap");
			InputMap inputMap = (InputMap) object;
			Object action = inputMap.get(existingKs);
			inputMap.put(newKs, action);
		}
	}

	private void installGlobalLookAndFeelAttributes() {
		// Fix up the default fonts that Java 1.5.0 changed to Courier, which looked terrible.
		Font f = new Font("Monospaced", Font.PLAIN, 12);
		UIManager.put("PasswordField.font", f);
		UIManager.put("TextArea.font", f);

		// We like buttons that change on hover, so force that to happen (see Tracker SCR 3966)
		UIManager.put("Button.rollover", Boolean.TRUE);
		UIManager.put("ToolBar.isRollover", Boolean.TRUE);
	}

	private void installPopupMenuSettingsOverride() {
		// Java 1.6 UI consumes MousePressed event when dismissing popup menu
		// which prevents application components from getting this event.
		UIManager.put("PopupMenu.consumeEventOnClose", Boolean.FALSE);
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

	private void installGlobalProperties() {
		installGlobalLookAndFeelAttributes();
		installGlobalFontSizeOverride();
		installCustomLookAndFeelActions();
		installPopupMenuSettingsOverride();
	}

	private static Color getNormalizedColor(Color color) {
		if (color.getClass() == Color.class) {
			return color;
		}
		return new Color(color.getRGB(), true);
	}

	private void cleanUiDefaults() {
		GThemeValueMap javaDefaults = Gui.getJavaDefaults();
		if (javaDefaults == null) {
			return;
		}
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			defaults.put(id, null);
		}
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			defaults.put(id, null);
		}
		for (IconValue iconValue : javaDefaults.getIcons()) {
			String id = iconValue.getId();
			defaults.put(id, null);
		}
	}

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
