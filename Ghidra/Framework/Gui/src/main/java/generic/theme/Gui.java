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
package generic.theme;

import java.awt.*;

import javax.swing.Icon;
import javax.swing.LookAndFeel;

/**
 * Provides a static set of methods for globally managing application themes and their values.
 * <P>
 * The basic idea is that all the colors, fonts, and icons used in an application should be
 * accessed indirectly via an "id" string. Then the actual color, font, or icon can be changed
 * without changing the source code. The default mapping of the id strings to a value is defined
 * in {name}.theme.properties files which are dynamically discovered by searching the module's
 * data directory. Also, these files can optionally define a dark default value for an id which
 * would replace the standard default value in the event that the current theme specifies that it
 * is a dark theme. Themes are used to specify the application's {@link LookAndFeel}, whether or
 * not it is dark, and any customized values for colors, fonts, or icons. There are several
 * "built-in" themes, one for each supported {@link LookAndFeel}, but additional themes can
 * be defined and stored in the users application home directory as a {name}.theme file.
 *
 */
public class Gui {
	// Start with an StubThemeManager so that simple tests can operate without having
	// to initialize the theme system. Applications and integration tests will
	// called ThemeManager.initialize() which will replace this with a fully initialized version.
	private static ThemeManager themeManager = new StubThemeManager();

	private Gui() {
		// static utils class, can't construct
	}

	/**
	 * Returns the current {@link Font} associated with the given id. A default font will be
	 * returned if the font can't be resolved and an error message will be printed to the console.
	 * @param id the id for the desired font
	 * @return the current {@link Font} associated with the given id.
	 */
	public static Font getFont(String id) {
		return themeManager.getFont(id);
	}

	/**
	 * Returns the {@link Color} registered for the given id. Will output an error message if
	 * the id can't be resolved.
	 * @param id the id to get the direct color for
	 * @return the {@link Color} registered for the given id.
	 */
	public static Color getColor(String id) {
		return themeManager.getColor(id);
	}

	/**
	 * Adds a {@link ThemeListener} to be notified of theme changes.
	 * @param listener the listener to be notified
	 */
	public static void addThemeListener(ThemeListener listener) {
		themeManager.addThemeListener(listener);
	}

	/**
	 * Removes the given {@link ThemeListener} from the list of listeners to be notified of
	 * theme changes.
	 * @param listener the listener to be removed
	 */
	public static void removeThemeListener(ThemeListener listener) {
		themeManager.removeThemeListener(listener);
	}

	/**
	 * Returns the Icon registered for the given id. If no icon is registered for the id,
	 * the default icon will be returned and an error message will be dumped to the console
	 * @param id the id to get the registered icon for
	 * @return the actual icon registered for the given id
	 */
	public static Icon getIcon(String id) {
		return themeManager.getIcon(id);
	}

	/**
	 * Returns true if an color for the given Id has been defined
	 * @param id the id to check for an existing color.
	 * @return true if an color for the given Id has been defined
	 */
	public static boolean hasColor(String id) {
		return themeManager.hasColor(id);
	}

	/**
	 * Returns true if an font for the given Id has been defined
	 * @param id the id to check for an existing font.
	 * @return true if an font for the given Id has been defined
	 */
	public static boolean hasFont(String id) {
		return themeManager.hasFont(id);
	}

	/**
	 * Returns true if an icon for the given Id has been defined
	 * @param id the id to check for an existing icon.
	 * @return true if an icon for the given Id has been defined
	 */
	public static boolean hasIcon(String id) {
		return themeManager.hasIcon(id);
	}

	/**
	 * Returns a darker version of the given color or brighter if the current theme is dark.
	 * @param color the color to get a darker version of
	 * @return a darker version of the given color or brighter if the current theme is dark
	 */
	public static Color darker(Color color) {
		if (isDarkTheme()) {
			return color.brighter();
		}
		return color.darker();
	}

	/**
	 * Returns a brighter version of the given color or darker if the current theme is dark.
	 * @param color the color to get a brighter version of
	 * @return a brighter version of the given color or darker if the current theme is dark
	 */
	public static Color brighter(Color color) {
		if (isDarkTheme()) {
			return color.darker();
		}
		return color.brighter();
	}

	/**
	 * Binds the component to the font identified by the given font id. Whenever the font for
	 * the font id changes, the component will updated with the new font.
	 * @param component the component to set/update the font
	 * @param fontId the id of the font to register with the given component
	 */
	public static void registerFont(Component component, String fontId) {
		themeManager.registerFont(component, fontId);
	}

	/**
	 * Returns true if the active theme is using dark defaults
	 * @return true if the active theme is using dark defaults
	 */
	public static boolean isDarkTheme() {
		return themeManager.isDarkTheme();
	}

	/**
	 * Returns true if the given id is a system-defined id, such as those starting with
	 * {@code laf.color} or {@code system.color}.
	 *
	 * @param id the id
	 * @return true if the given id is a system-defined id
	 */
	public static boolean isSystemId(String id) {
		return id.startsWith("laf.") || id.startsWith("system.");
	}

	static void setThemeManager(ThemeManager manager) {
		themeManager = manager;
	}
}
