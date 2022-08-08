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

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.util.Objects;

import javax.swing.Icon;

/**
 * Class to store all the configurable appearance properties (Colors, Fonts, Icons, Look and Feel)
 * in an application.
 */
public class GTheme extends GThemeValueMap {
	public static String FILE_EXTENSION = ".theme";

	static final String THEME_NAME_KEY = "name";
	static final String THEME_LOOK_AND_FEEL_KEY = "lookAndFeel";
	static final String THEME_USE_DARK_DEFAULTS = "useDarkDefaults";

	private final String name;
	private final LafType lookAndFeel;
	private final boolean useDarkDefaults;

	public GTheme(String name) {
		this(name, LafType.SYSTEM, false);

	}

	/**
	 * Creates a new empty GTheme with the given name
	 * @param name the name for the new GTheme
	 * @param lookAndFeel the look and feel type used by this theme
	 * @param useDarkDefaults determines whether or  
	 */
	protected GTheme(String name, LafType lookAndFeel, boolean useDarkDefaults) {
		this.name = name;
		this.lookAndFeel = lookAndFeel;
		this.useDarkDefaults = useDarkDefaults;
	}

	/**
	 * Returns the name of this GTheme
	 * @return the name of this GTheme
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the name of the LookAndFeel associated with this GTheme
	 * @return the name of the LookAndFeel associated with this GTheme
	 */
	public LafType getLookAndFeelType() {
		return lookAndFeel;
	}

	/**
	 * Returns true if this theme should use dark defaults
	 * @return true if this theme should use dark defaults
	 */
	public boolean useDarkDefaults() {
		return useDarkDefaults;
	}

	/**
	 * Returns a String that can be used to find and restore this theme. 
	 * @return  a String that can be used to find and restore this theme.
	 */
	public String getThemeLocater() {
		return "Default";
	}

	/**
	 * Sets the Color for the given id
	 * @param id the id to associate with the given Color
	 * @param color the Color to associate with the given id
	 */
	public void setColor(String id, Color color) {
		addColor(new ColorValue(id, color));
	}

	/**
	 * Sets a referred Color for the given id
	 * @param id the id to associate with the refId
	 * @param refId the id of an indirect Color lookup for the given id.
	 */
	public void setColorRef(String id, String refId) {
		addColor(new ColorValue(id, refId));
	}

	/**
	 * Sets the Font for the given id
	 * @param id the id to associate with the given Font
	 * @param font the Font to associate with the given id
	 */
	public void setFont(String id, Font font) {
		addFont(new FontValue(id, font));
	}

	/**
	 * Sets a referred font for the given id
	 * @param id the id to associate with the given Font reference id
	 * @param refId the id of an indirect Font lookup for the given id.
	 */
	public void setFontRef(String id, String refId) {
		addFont(new FontValue(id, refId));
	}

	/**
	 * Sets the icon for the given id
	 * @param id the id to associate with the given IconPath
	 * @param icon the icon to assign to the given id
	 */
	public void setIcon(String id, Icon icon) {
		addIcon(new IconValue(id, icon));
	}

	/**
	 * Sets a referred icon id for the given id
	 * @param id the id to associate with the given Font
	 * @param refId the id of an indirect Icon lookup for the given id.
	 */
	public void setIconRef(String id, String refId) {
		addIcon(new IconValue(id, refId));
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GTheme other = (GTheme) obj;
		return Objects.equals(name, other.name) && Objects.equals(lookAndFeel, other.lookAndFeel);
	}

	public boolean hasSupportedLookAndFeel() {
		return lookAndFeel.isSupported();
	}

	public FileGTheme saveToFile(File file, boolean includeDefaults) throws IOException {
		FileGTheme fileTheme = new FileGTheme(file, name, lookAndFeel, useDarkDefaults);
		if (includeDefaults) {
			fileTheme.load(Gui.getDefaults());
		}
		fileTheme.load(this);
		fileTheme.save();
		return fileTheme;
	}

}
