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
import java.io.*;
import java.util.Collections;
import java.util.List;

import javax.swing.Icon;

import ghidra.util.WebColors;
import resources.icons.UrlImageIcon;

public class FileGTheme extends GTheme {
	public static final String FILE_PREFIX = "File:";
	private final File file;

	public FileGTheme(File file) throws IOException {
		this(file, new ThemeReader(file));
	}

	public FileGTheme(File file, String name, LafType laf, boolean useDarkDefaults) {
		super(name, laf, useDarkDefaults);
		this.file = file;
	}

	FileGTheme(File file, ThemeReader reader) {
		super(reader.getThemeName(), reader.getLookAndFeelType(), false);
		this.file = file;
		reader.loadValues(this);
	}

	@Override
	public String getThemeLocater() {
		return FILE_PREFIX + file.getAbsolutePath();
	}

	public boolean canSave() {
		if (file.exists()) {
			return file.canWrite();
		}
		return file.getParentFile().canWrite();
	}

	public File getFile() {
		return file;
	}

	public void save() throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
			List<ColorValue> colors = getColors();
			Collections.sort(colors);

			List<FontValue> fonts = getFonts();
			Collections.sort(fonts);

			List<IconValue> icons = getIcons();
			Collections.sort(icons);

			writer.write(THEME_NAME_KEY + " = " + getName());
			writer.newLine();

			writer.write(THEME_LOOK_AND_FEEL_KEY + " = " + getLookAndFeelType().getName());
			writer.newLine();

			writer.write(THEME_USE_DARK_DEFAULTS + " = " + useDarkDefaults());
			writer.newLine();

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

	private String getValueOutput(IconValue iconValue) {
		if (iconValue.getReferenceId() != null) {
			return iconValue.toExternalId(iconValue.getReferenceId());
		}
		Icon icon = iconValue.getRawValue();
		return iconToString(icon);
	}

	public static String iconToString(Icon icon) {
		if (icon instanceof UrlImageIcon urlIcon) {
			return urlIcon.getOriginalPath();
		}
		return "<UNKNOWN>";
	}

	private String getValueOutput(FontValue fontValue) {
		if (fontValue.getReferenceId() != null) {
			return fontValue.toExternalId(fontValue.getReferenceId());
		}
		Font font = fontValue.getRawValue();
		return fontToString(font);
	}

	public static String fontToString(Font font) {
		return String.format("%s-%s-%s", font.getName(), getStyleString(font), font.getSize());
	}

	private static String getStyleString(Font font) {
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
}
