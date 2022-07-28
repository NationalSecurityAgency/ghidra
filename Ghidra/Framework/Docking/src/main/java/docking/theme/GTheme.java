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
package docking.theme;

import java.awt.Color;
import java.awt.Font;
import java.io.*;
import java.util.*;

import ghidra.docking.util.LookAndFeelUtils;
import ghidra.util.WebColors;

/**
 * Class to store all the configurable appearance properties (Colors, Fonts, Icons, Look and Feel)
 * in an application.
 */
public class GTheme extends GThemeValueMap {
	static final String THEME_NAME_KEY = "name";
	static final String THEME_LOOK_AND_FEEL_KEY = "lookAndFeel";
	static final String THEME_IS_DARK_KEY = "dark";

	private final String name;
	private final String lookAndFeelName;
	private final boolean isDark;

	public GTheme(String name) {
		this(name, LookAndFeelUtils.SYSTEM, false);

	}

	/**
	 * Creates a new empty GTheme with the given name
	 * @param name the name for the new GTheme
	 * @param lookAndFeelName the look and feel used by this theme
	 * @param isDark true if this theme uses dark backgrounds instead of the standard
	 *  light backgrounds
	 */
	protected GTheme(String name, String lookAndFeelName, boolean isDark) {
		this.name = name;
		this.lookAndFeelName = lookAndFeelName;
		this.isDark = isDark;
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
	public String getLookAndFeelName() {
		return lookAndFeelName;
	}

	/**
	 * Returns true if this theme should use dark defaults
	 * @return true if this theme should use dark defaults
	 */
	public boolean isDark() {
		return isDark;
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
	 * @param iconPath the path of the icon to assign to the given id
	 */
	public void setIcon(String id, String iconPath) {
		addIconPath(new IconValue(id, null, iconPath));
	}

	/**
	 * Sets a referred icon id for the given id
	 * @param id the id to associate with the given Font
	 * @param refId the id of an indirect Icon lookup for the given id.
	 */
	public void setIconRef(String id, String refId) {
		addIconPath(new IconValue(id, refId, null));
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
		return Objects.equals(name, other.name) &&
			Objects.equals(lookAndFeelName, other.lookAndFeelName) &&
			Objects.equals(isDark, other.isDark);
	}

	/**
	 * Creates a new file based GTheme with the same values as this GTheme
	 * @param saveToFile file to associate and save this GTheme to
	 * @return the new theme
	 * @throws IOException if a general I/O exception occurs
	 */
	public GTheme saveToFile(File saveToFile) throws IOException {
		return doSaveToFile(saveToFile, this);
	}

	/**
	 * Creates a new file based GTheme with the same values as this GTheme and includes default
	 * values not modified by this theme.
	 * @param saveToFile file to associate and save this GTheme to
	 * @param defaults the collection of default values to include in the output file
	 * @return the new theme
	 * @throws IOException if a general I/O exception occurs
	 */
	public GTheme saveToFile(File saveToFile, GThemeValueMap defaults) throws IOException {
		GThemeValueMap combined = new GThemeValueMap();
		combined.load(defaults);
		combined.load(this);
		return doSaveToFile(saveToFile, combined);
	}

	private GTheme doSaveToFile(File saveToFile, GThemeValueMap values) throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(saveToFile))) {
			List<ColorValue> colors = values.getColors();
			Collections.sort(colors);

			List<FontValue> fonts = values.getFonts();
			Collections.sort(fonts);

			List<IconValue> icons = values.getIcons();
			Collections.sort(icons);

			writer.write(THEME_NAME_KEY + " = " + name);
			writer.newLine();

			writer.write(THEME_LOOK_AND_FEEL_KEY + " = " + lookAndFeelName);
			writer.newLine();

			if (isDark()) {
				writer.write(THEME_IS_DARK_KEY + " = true");
				writer.newLine();
			}

			for (ColorValue colorValue : colors) {
				String outputId = colorValue.toExternalId(colorValue.getId());
				writer.write(outputId + " = " + getValueOutput(colorValue));
				writer.newLine();
			}

			for (FontValue fontValue : fonts) {
				String outputId = fontValue.toExternalId(fontValue.getId());
				writer.write(outputId + " = " + getValueOutput(fontValue));
				writer.newLine();
			}

			for (IconValue iconValue : icons) {
				String outputId = iconValue.toExternalId(iconValue.getId());
				writer.write(outputId + " = " + getValueOutput(iconValue));
				writer.newLine();
			}

		}
		return new FileGTheme(saveToFile);
	}

	private String getValueOutput(IconValue iconValue) {
		if (iconValue.getReferenceId() != null) {
			return iconValue.toExternalId(iconValue.getReferenceId());
		}
		return iconValue.getRawValue();
	}

	private String getValueOutput(FontValue fontValue) {
		if (fontValue.getReferenceId() != null) {
			return fontValue.toExternalId(fontValue.getReferenceId());
		}
		Font font = fontValue.getRawValue();
		return String.format("%s-%s-%s", font.getName(), getStyleString(font), font.getSize());
	}

	private String getStyleString(Font font) {
		boolean bold = font.isBold();
		boolean italic = font.isItalic();
		if (bold && italic) {
			return "BOLDITALIC";
		}
		if (bold) {
			return "BOLD";
		}
		if (italic) {
			return "ITALIC";
		}
		return "PLAIN";
	}

	private String getValueOutput(ColorValue colorValue) {
		if (colorValue.getReferenceId() != null) {
			return colorValue.toExternalId(colorValue.getReferenceId());
		}
		Color color = colorValue.getRawValue();
		String outputString = WebColors.toString(color, false);
		String colorName = WebColors.toWebColorName(color);
		if (colorName != null) {
			outputString += " // " + colorName;
		}
		return outputString;
	}
}
