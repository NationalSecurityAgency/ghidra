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
import java.util.HashMap;
import java.util.Map;

import generic.jar.ResourceFile;

/**
 * Reads the values for a single theme.properities file
 */
public class ThemePropertyFileReader extends AbstractThemeReader {

	private GThemeValueMap defaults = new GThemeValueMap();
	private GThemeValueMap darkDefaults = new GThemeValueMap();
	private Map<LafType, GThemeValueMap> customSectionsMap = new HashMap<>();
	private boolean defaultSectionProcessed;

	/**
	 * Constructor for when the the theme.properties file is a {@link ResourceFile}
	 * @param file the {@link ResourceFile} esourceFileto read
	 * @throws IOException if an I/O error occurs reading the file
	 */
	public ThemePropertyFileReader(ResourceFile file) throws IOException {
		super(file.getAbsolutePath());

		try (Reader reader = new InputStreamReader(file.getInputStream())) {
			read(reader);
		}
	}

	/**
	 * Constructor using a Reader (needed for reading from zip files).
	 * @param source the name or description of the Reader source
	 * @param reader the {@link Reader} to parse as theme data
	 * @throws IOException if an I/O error occurs while reading from the Reader
	 */
	protected ThemePropertyFileReader(String source, Reader reader) throws IOException {
		super(source);
		read(reader);
	}

	/**
	 * Returns the map of standard defaults values. 
	 * @return the map of standard defaults values.
	 */
	public GThemeValueMap getDefaultValues() {
		return defaults;
	}

	/**
	 * Returns the map of dark defaults values. 
	 * @return the map of dark defaults values.
	 */
	public GThemeValueMap getDarkDefaultValues() {
		return darkDefaults;
	}

	/**
	 * Returns a map of all the custom (look and feel specific) value maps
	 * @return a map of all the custom (look and feel specific) value maps
	 */
	public Map<LafType, GThemeValueMap> getLookAndFeelSections() {
		return customSectionsMap;
	}

	protected void processNoSection(Section section) throws IOException {
		if (!section.isEmpty()) {
			error(section.getLineNumber(),
				"Theme properties file has values defined outside of a defined section");
		}
	}

	@Override
	protected void processDefaultSection(Section section) throws IOException {
		defaultSectionProcessed = true;
		processValues(defaults, section);
	}

	@Override
	protected void processDarkDefaultSection(Section section) throws IOException {
		if (!defaultSectionProcessed) {
			error(section.getLineNumber(),
				"Defaults section must be defined before Dark Defaults section!");
			return;
		}
		processValues(darkDefaults, section);
		validate("Dark Defaults", darkDefaults);
	}

	@Override
	protected void processCustomSection(Section section) throws IOException {
		String name = section.getName();
		LafType lafType = LafType.fromName(name);
		if (lafType == null) {
			error(section.getLineNumber(), "Unknown Look and Feel section found: " + name);
			return;
		}
		if (!defaultSectionProcessed) {
			error(section.getLineNumber(),
				"Defaults section must be defined before " + name + " section!");
			return;
		}
		GThemeValueMap customValues = new GThemeValueMap();
		processValues(customValues, section);
		customSectionsMap.put(lafType, customValues);
		validate(name, customValues);
	}

	private void validate(String name, GThemeValueMap valuesMap) {
		for (String id : valuesMap.getColorIds()) {
			if (!defaults.containsColor(id)) {
				reportMissingDefaultsError("Color", name, id);
			}
		}
		for (String id : valuesMap.getFontIds()) {
			if (!defaults.containsFont(id)) {
				reportMissingDefaultsError("Font", name, id);
			}
		}
		for (String id : valuesMap.getIconIds()) {
			if (!defaults.containsIcon(id)) {
				reportMissingDefaultsError("Icon", name, id);
			}
		}
	}

	private void reportMissingDefaultsError(String type, String name, String id) {
		String message = type + " id found in \"" + name +
			"\" section, but not defined in \"Defaults\" section: " + id;
		error(-1, message);
	}

}
