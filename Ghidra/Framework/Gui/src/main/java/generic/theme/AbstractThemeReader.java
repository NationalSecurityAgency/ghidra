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
import java.text.ParseException;
import java.util.*;

import ghidra.util.Msg;

/**
 * Abstract base class for reading theme values either in sections (theme property files) or no
 * sections (theme files)
 */
public abstract class AbstractThemeReader {

	private static final String NO_SECTION = "No Section";
	private static final String DEFAULTS = "Defaults";
	private static final String DARK_DEFAULTS = "Dark Defaults";

	private List<String> errors = new ArrayList<>();
	protected String source;

	protected AbstractThemeReader(String source) {
		this.source = source;
	}

	/**
	 * Returns a list of errors found while parsing
	 * @return a list of errors found while parsing
	 */
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
					processDefaultSection(section);
					break;
				case DARK_DEFAULTS:
					processDarkDefaultSection(section);
					break;
				default:
					processCustomSection(section);
			}
		}

	}

	protected abstract void processNoSection(Section section) throws IOException;

	protected abstract void processDefaultSection(Section section) throws IOException;

	protected abstract void processDarkDefaultSection(Section section) throws IOException;

	protected abstract void processCustomSection(Section section) throws IOException;

	protected void processValues(GThemeValueMap valueMap, Section section) {
		for (String key : section.getKeys()) {
			String value = section.getValue(key);
			int lineNumber = section.getLineNumber(key);
			if (ColorValue.isColorKey(key)) {
				ColorValue colorValue = parseColorProperty(key, value, lineNumber);
				ColorValue oldValue = valueMap.addColor(colorValue);
				reportDuplicateKey(oldValue, lineNumber);
			}
			else if (FontValue.isFontKey(key)) {
				FontValue oldValue = valueMap.addFont(parseFontProperty(key, value, lineNumber));
				reportDuplicateKey(oldValue, lineNumber);
			}
			else if (IconValue.isIconKey(key)) {
				if (!GTheme.JAVA_ICON.equals(value)) {
					IconValue oldValue =
						valueMap.addIcon(parseIconProperty(key, value, lineNumber));
					reportDuplicateKey(oldValue, lineNumber);
				}
			}
			else {
				error(lineNumber, "Can't process property: " + key + " = " + value);
			}
		}
	}

	private void reportDuplicateKey(ThemeValue<?> oldValue, int lineNumber) {
		if (oldValue != null) {
			error(lineNumber, "Duplicate id found: \"" + oldValue.getId() + "\"");
		}
	}

	private IconValue parseIconProperty(String key, String value, int lineNumber) {
		try {
			IconValue parsedValue = IconValue.parse(key, value);
			if (parsedValue == null) {
				error(lineNumber, "Could not parse Icon value: " + value);
			}
			return parsedValue;
		}
		catch (ParseException e) {
			error(lineNumber,
				"Could not parse Icon value: \"" + value + "\" because: " + e.getMessage());
		}
		return null;
	}

	private FontValue parseFontProperty(String key, String value, int lineNumber) {
		try {
			FontValue parsedValue = FontValue.parse(key, value);
			if (parsedValue == null) {
				error(lineNumber, "Could not parse Font value: " + value);
			}
			return parsedValue;
		}
		catch (Exception e) {
			error(lineNumber, "Could not parse Font value: " + value + "because " + e.getMessage());
		}
		return null;
	}

	private ColorValue parseColorProperty(String key, String value, int lineNumber) {
		ColorValue parsedValue = ColorValue.parse(key, value);
		if (parsedValue == null) {
			error(lineNumber, "Could not parse Color value: " + value);
		}
		return parsedValue;
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
				String name = line.substring(1, line.length() - 1);
				currentSection = new Section(name, reader.getLineNumber());
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
		StringBuilder builder = new StringBuilder();
		builder.append("Error parsing theme file \"" + source + "\"");

		if (lineNumber >= 0) {
			builder.append(" at line: " + lineNumber);
		}
		builder.append(". ");
		builder.append(message);
		String msg = builder.toString();
		errors.add(msg);
		outputError(msg);
	}

	protected void outputError(String msg) {
		Msg.error(this, msg);
	}

	/**
	 * Represents all the value found in a section of the theme properties file. Sections are 
	 * defined by a line containing just "[section name]"
	 */
	protected class Section {

		private String name;
		private Map<String, String> properties = new HashMap<>();
		private Map<String, Integer> lineNumbers = new HashMap<>();
		private int startLineNumber;

		/**
		 * Constructor sectionName the section name
		 * @param sectionName the name of this section
		 * @param lineNumber the line number in the file where the section started
		 */
		public Section(String sectionName, int lineNumber) {
			this.name = sectionName;
			this.startLineNumber = lineNumber;
		}

		/**
		 * Removes the value with the given key
		 * @param key the key to remove
		 */
		public void remove(String key) {
			properties.remove(key);
		}

		/**
		 * Returns the value for the given key.
		 * @param key the key to get a value for
		 * @return the value for the given key
		 */
		public String getValue(String key) {
			return properties.get(key);
		}

		/**
		 * Returns a set of all keys in the section
		 * @return a set of all keys in the section
		 */
		public Set<String> getKeys() {
			return properties.keySet();
		}

		/**
		 * Returns the line number in the original file where the key was parsed
		 * @param key the key to get a line number for
		 * @return the line number in the original file where the key was parsed
		 */
		public int getLineNumber(String key) {
			return lineNumbers.get(key);
		}

		/**
		 * Returns true if the section is empty.
		 * @return true if the section is empty.
		 */
		public boolean isEmpty() {
			return properties.isEmpty();
		}

		/**
		 * Returns the line number in the file where this section began.
		 * @return the line number in the file where this section began.
		 */
		public int getLineNumber() {
			return startLineNumber;
		}

		/**
		 * Returns the name of this section
		 * @return the name of this section
		 */
		public String getName() {
			return name;
		}

		/**
		 * Adds a raw line from the file to this section. The line will be parsed into a a 
		 * key-value pair.
		 * @param line the line to be added/parsed
		 * @param lineNumber the line number in the file for this line
		 */
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
			if (value.isBlank()) {
				error(lineNumber, "Missing value for propery line: \"" + line + "\"");
				return;
			}
			if (properties.containsKey(key)) {
				error(lineNumber, "Duplicate key found in this file!: " + key + "\"");
				return;
			}
			properties.put(key, value);
			lineNumbers.put(key, lineNumber);

		}
	}
}
