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

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Writes a theme to a file either as a single theme file or as a zip file that contains the theme
 * file and any external (from the file system, not the classpath) icons used by the theme.
 */
public class ThemeWriter {
	static final String THEME_NAME_KEY = "name";
	static final String THEME_LOOK_AND_FEEL_KEY = "lookAndFeel";
	static final String THEME_USE_DARK_DEFAULTS = "useDarkDefaults";
	protected GTheme theme;

	/**
	 * Constructor
	 * @param theme the theme to be written to a file
	 */
	public ThemeWriter(GTheme theme) {
		this.theme = theme;
	}

	/**
	 * Writes the theme to the given file with the option to output as a zip file.
	 * @param file the file to write to
	 * @param asZip if true, outputs in zip format
	 * @throws FileNotFoundException i
	 * @throws IOException if an I/O error occurs trying to write the file
	 */
	public void writeTheme(File file, boolean asZip) throws IOException {
		if (asZip) {
			writeThemeToZipFile(file);
		}
		else {
			writeThemeToFile(file);
		}
	}

	/**
	 * Writes the theme to the given file.
	 * @param file the file to write to
	 * @throws FileNotFoundException i
	 * @throws IOException if an I/O error occurs trying to write the file
	 */
	public void writeThemeToFile(File file) throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
			writeThemeValues(writer);
		}
	}

	/**
	 * Writes the theme to the given file in a zip format.
	 * @param file the file to write to
	 * @throws IOException if an I/O error occurs trying to write the file
	 */
	public void writeThemeToZipFile(File file) throws IOException {
		String dir = theme.getName() + ".theme/";
		try (FileOutputStream fos = new FileOutputStream(file)) {
			ZipOutputStream zos = new ZipOutputStream(fos);
			saveThemeFileToZip(dir, zos);
			Set<File> iconFiles = theme.getExternalIconFiles();
			for (File iconFile : iconFiles) {
				copyToZipFile(dir, iconFile, zos);
			}
			zos.finish();
		}
	}

	protected void writeThemeValues(BufferedWriter writer) throws IOException {
		List<ColorValue> colors = theme.getColors();
		Collections.sort(colors);

		List<FontValue> fonts = theme.getFonts();
		Collections.sort(fonts);

		List<IconValue> icons = theme.getIcons();
		Collections.sort(icons);

		writer.write(THEME_NAME_KEY + " = " + theme.getName());
		writer.newLine();

		writer.write(THEME_LOOK_AND_FEEL_KEY + " = " + theme.getLookAndFeelType().getName());
		writer.newLine();

		writer.write(THEME_USE_DARK_DEFAULTS + " = " + theme.useDarkDefaults());
		writer.newLine();

		for (ColorValue colorValue : colors) {
			writer.write(colorValue.getSerializationString());
			writer.newLine();
		}

		for (FontValue fontValue : fonts) {
			writer.write(fontValue.getSerializationString());
			writer.newLine();
		}

		for (IconValue iconValue : icons) {
			writer.write(iconValue.getSerializationString());
			writer.newLine();

		}
	}

	private void copyToZipFile(String dir, File iconFile, ZipOutputStream zos) throws IOException {
		ZipEntry entry = new ZipEntry(dir + "images/" + iconFile.getName());
		zos.putNextEntry(entry);
		Files.copy(iconFile.toPath(), zos);
	}

	private void saveThemeFileToZip(String dir, ZipOutputStream zos) throws IOException {
		ZipEntry entry = new ZipEntry(dir + theme.getName() + ".theme");
		zos.putNextEntry(entry);
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(zos));
		writeThemeValues(writer);
		writer.flush();
	}
}
