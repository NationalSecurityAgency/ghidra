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
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;

import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Reads Themes from a file or {@link Reader}
 */
class ThemeReader extends AbstractThemeReader {

	private File file;
	private GTheme theme;

	/**
	 * Constructor for reading a theme from a file.
	 * @param file the file to read as a theme
	 * @throws IOException if an I/O error occurs reading the theme file
	 */
	ThemeReader(File file) throws IOException {
		super(file.getAbsolutePath());
		this.file = file;
	}

	public GTheme readTheme() throws IOException {
		if (file.getName().endsWith(GTheme.FILE_EXTENSION)) {
			return readFileTheme();
		}
		if (file.getName().endsWith(GTheme.ZIP_FILE_EXTENSION)) {
			return readZipTheme();
		}

		throw new IOException("Imported File must end in either " + GTheme.FILE_EXTENSION + " or " +
			GTheme.ZIP_FILE_EXTENSION);
	}

	/**
	 * Assumes the file is a theme file and reads it.
	 */
	private GTheme readFileTheme() throws IOException {
		try (Reader reader = new FileReader(file)) {
			read(reader);
		}
		if (theme == null) {
			throw new IOException("Invalid Theme file: " + file);
		}
		return theme;
	}

	private GTheme readZipTheme() throws IOException {
		try (ZipFile zipFile = new ZipFile(file)) {
			Enumeration<? extends ZipEntry> entries = zipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				String name = entry.getName();
				try (InputStream is = zipFile.getInputStream(entry)) {
					if (name.endsWith(".theme")) {
						processThemeData(name, is);
					}
					else {
						processIconFile(name, is);
					}
				}
			}
		}
		return theme;
	}

	// for testing
	GTheme readTheme(Reader reader) throws IOException {
		read(reader);
		return theme;
	}

	@Override
	protected void processNoSection(Section section) throws IOException {
		String themeName = section.getValue(ThemeWriter.THEME_NAME_KEY);
		if (themeName == null) {
			throw new IOException("Missing theme name!");
		}
		String lookAndFeelName = section.getValue(ThemeWriter.THEME_LOOK_AND_FEEL_KEY);
		LafType lookAndFeel = LafType.fromName(lookAndFeelName);
		if (lookAndFeel == null) {
			throw new IOException(
				"Invalid or missing lookAndFeel name: \"" + lookAndFeelName + "\"");
		}
		boolean isDark = Boolean.valueOf(section.getValue(ThemeWriter.THEME_USE_DARK_DEFAULTS));

		theme = new GTheme(file, themeName, lookAndFeel, isDark);
		section.remove(ThemeWriter.THEME_NAME_KEY);
		section.remove(ThemeWriter.THEME_LOOK_AND_FEEL_KEY);
		section.remove(ThemeWriter.THEME_USE_DARK_DEFAULTS);
		processValues(theme, section);
	}

	@Override
	protected void processDefaultSection(Section section) throws IOException {
		error(section.getLineNumber(), "[Defaults] section not allowed in theme files!");
	}

	@Override
	protected void processDarkDefaultSection(Section section) throws IOException {
		error(section.getLineNumber(), "[Dark Defaults] section not allowed in theme files!");
	}

	@Override
	protected void processCustomSection(Section section) throws IOException {
		error(section.getLineNumber(),
			"Custom sections not allowed in theme files! " + section.getName());
	}

	private void processIconFile(String path, InputStream is) throws IOException {
		int indexOf = path.indexOf("images/");
		if (indexOf < 0) {
			Msg.error(this, "Unknown file: " + path);
		}
		String relativePath = path.substring(indexOf, path.length());
		File dir = Application.getUserSettingsDirectory();
		File iconFile = new File(dir, relativePath);
		FileUtils.copyInputStreamToFile(is, iconFile);
	}

	private void processThemeData(String name, InputStream is) throws IOException {
		InputStreamReader reader = new InputStreamReader(is);
		read(reader);
	}

}
