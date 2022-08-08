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
import java.util.*;

import javax.swing.Icon;
import javax.swing.plaf.FontUIResource;

import org.apache.commons.collections4.map.HashedMap;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import ghidra.util.WebColors;
import resources.ResourceManager;

public class ThemePropertyFileReader {

	private static final String NO_SECTION = "[No Section]";
	private static final String DEFAULTS = "[Defaults]";
	private static final String DARK_DEFAULTS = "[Dark Defaults]";

	private GThemeValueMap defaults = new GThemeValueMap();
	private GThemeValueMap darkDefaults = new GThemeValueMap();
	private Map<String, List<String>> aliasMap = new HashedMap<>();
	private List<String> errors = new ArrayList<>();
	private String filePath;

	public ThemePropertyFileReader(File file) throws IOException {
		filePath = file.getAbsolutePath();
		try (Reader reader = new FileReader(file)) {
			read(reader);
		}
	}

	public ThemePropertyFileReader(ResourceFile file) throws IOException {
		filePath = file.getAbsolutePath();
		try (Reader reader = new InputStreamReader(file.getInputStream())) {
			read(reader);
		}
	}

	protected ThemePropertyFileReader() {

	}

	ThemePropertyFileReader(String source, Reader reader) throws IOException {
		filePath = source;
		read(reader);
	}

	public GThemeValueMap getDefaultValues() {
		return defaults;
	}

	public GThemeValueMap getDarkDefaultValues() {
		return darkDefaults;
	}

	public Map<String, List<String>> getAliases() {
		return aliasMap;
	}

	public List<String> getErrors() {
		return errors;
	}

	protected void read(Reader reader) throws IOException {
		List<Section> sections = readSections(new LineNumberReader(reader));
		for (Section section : sections) {
			switch (section.getName()) {
				case NO_SECTION:
					processNoSection(section);
					break;
				case DEFAULTS:
					processValues(defaults, section);
					break;
				case DARK_DEFAULTS:
					processValues(darkDefaults, section);
					break;
				default:
					error(section.getLineNumber(),
						"Encounded unknown theme file section: " + section.getName());
			}
		}

	}

	protected void processNoSection(Section section) throws IOException {
		if (!section.isEmpty()) {
			error(0, "Theme properties file has values defined outside of a defined section");
		}

	}

	public void processValues(GThemeValueMap valueMap, Section section) {
		for (String key : section.getKeys()) {
			String value = section.getValue(key);
			int lineNumber = section.getLineNumber(key);
			if (ColorValue.isColorKey(key)) {
				valueMap.addColor(parseColorProperty(key, value, lineNumber));
			}
			else if (FontValue.isFontKey(key)) {
				valueMap.addFont(parseFontProperty(key, value, lineNumber));
			}
			else if (IconValue.isIconKey(key)) {
				if (!FileGTheme.JAVA_ICON.equals(value)) {
					valueMap.addIcon(parseIconProperty(key, value));
				}
			}
			else {
				error(lineNumber, "Can't process property: " + key + " = " + value);
			}
		}
	}

	private IconValue parseIconProperty(String key, String value) {
		if (IconValue.isIconKey(value)) {
			return new IconValue(key, value);
		}
		Icon icon = ResourceManager.loadImage(value);
		return new IconValue(key, icon);
	}

	private FontValue parseFontProperty(String key, String value, int lineNumber) {
		if (FontValue.isFontKey(value)) {
			return new FontValue(key, value);
		}
		Font font = Font.decode(value);
		if (font == null) {
			error(lineNumber, "Could not parse Color: " + value);
		}
		return font == null ? null : new FontValue(key, new FontUIResource(font));
	}

	private ColorValue parseColorProperty(String key, String value, int lineNumber) {
		if (ColorValue.isColorKey(value)) {
			return new ColorValue(key, value);
		}
		Color color = WebColors.getColor(value);
		if (color == null) {
			error(lineNumber, "Could not parse Color: " + value);
		}
		return color == null ? null : new ColorValue(key, color);
	}

	private List<Section> readSections(LineNumberReader reader) throws IOException {

		List<Section> sections = new ArrayList<>();
		Section currentSection = new Section(NO_SECTION, 0);
		sections.add(currentSection);

		String line;
		while ((line = reader.readLine()) != null) {
			line = removeComments(line);

			if (line.isBlank()) {
				continue;
			}

			if (isSectionHeader(line)) {
				currentSection = new Section(line, reader.getLineNumber());
				sections.add(currentSection);
			}
			else {
				currentSection.add(line, reader.getLineNumber());
			}
		}

		return sections;
	}

	private String removeComments(String line) {
		// remove any trailing comment on line
		int commentIndex = line.indexOf("//");
		if (commentIndex >= 0) {
			line = line.substring(0, commentIndex);
		}
		line = line.trim();

		// clear line if entire line is comment
		if (line.startsWith("#")) {
			return "";
		}
		return line;
	}

	private boolean isSectionHeader(String line) {
		return line.startsWith("[") && line.endsWith("]");
	}

	protected void error(int lineNumber, String message) {
		String msg =
			"Error parsing file \"" + filePath + "\" at line: " + lineNumber + ", " + message;
		errors.add(msg);
		Msg.out(msg);
	}

	protected class Section {

		private String name;
		Map<String, String> properties = new HashMap<>();
		Map<String, Integer> lineNumbers = new HashMap<>();
		private int startLineNumber;

		public Section(String sectionName, int lineNumber) {
			this.name = sectionName;
			this.startLineNumber = lineNumber;
		}

		public void remove(String key) {
			properties.remove(key);
		}

		public String getValue(String key) {
			return properties.get(key);
		}

		public Set<String> getKeys() {
			return properties.keySet();
		}

		public int getLineNumber(String key) {
			return lineNumbers.get(key);
		}

		public boolean isEmpty() {
			return properties.isEmpty();
		}

		public int getLineNumber() {
			return startLineNumber;
		}

		public String getName() {
			return name;
		}

		public void add(String line, int lineNumber) {
			int splitIndex = line.indexOf('=');
			if (splitIndex < 0) {
				error(lineNumber, "Missing required \"=\" for propery line: \"" + line + "\"");
				return;
			}
			String key = line.substring(0, splitIndex).trim();
			String value = line.substring(splitIndex + 1, line.length()).trim();
			if (key.isBlank()) {
				error(lineNumber, "Missing key for propery line: \"" + line + "\"");
				return;
			}
			if (key.isBlank()) {
				error(lineNumber, "Missing value for propery line: \"" + line + "\"");
				return;
			}
			properties.put(key, value);
			lineNumbers.put(key, lineNumber);

		}

	}

}
