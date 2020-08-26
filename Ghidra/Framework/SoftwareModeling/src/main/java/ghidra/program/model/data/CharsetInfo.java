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
package ghidra.program.model.data;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * Additional information about {@link Charset java.nio.charset.Charset's} that
 * Ghidra needs to be able to create Ghidra string datatype instances.
 * <p>
 * See charset_info.xml to specify a custom charset.
 */
public class CharsetInfo {

	private static final class Singleton {
		private static final CharsetInfo INSTANCE = new CharsetInfo();
	}

	/**
	 * Get the global singleton instance of this {@link CharsetInfo}.
	 *
	 * @return global singleton instance
	 */
	public static CharsetInfo getInstance() {
		return Singleton.INSTANCE;
	}

	//-----------------------------------------------------------------------------

	public static final String UTF8 = "UTF-8";
	public static final String UTF16 = "UTF-16";
	public static final String UTF32 = "UTF-32";
	public static final String USASCII = "US-ASCII";

	/**
	 * @param charsetName name of charset
	 * @return true if the supported multi-byte charset does not specify LE or
	 *         BE
	 */
	public static boolean isBOMCharset(String charsetName) {
		return UTF32.equals(charsetName) || UTF16.equals(charsetName);
	}

	//-----------------------------------------------------------------------------

	private Map<String, CharsetInfoRec> charsetInfoRecsByName = new HashMap<>();
	private List<String> charsetNamesList = new ArrayList<>();
	private String[] charsetNames;

	private CharsetInfo() {
		initialize(false);
	}

	private void initialize(boolean includeConfigFile) {
		registerStandardCharsets();
		if (includeConfigFile) {
			readConfigFile();
		}
		addJVMAvailableCharsets();
		this.charsetNames = charsetNamesList.toArray(new String[charsetNamesList.size()]);
	}

	/**
	 * Reinitialize registered Charsets and include user defined Charsets
	 * specified in charset_info.xml.
	 */
	public static void reinitializeWithUserDefinedCharsets() {
		getInstance().initialize(true);
	}

	/**
	 * Register minimal set of Java Charsets to facilitate most test without
	 * Application initialization overhead.
	 */
	private void registerStandardCharsets() {
		addCharset(USASCII, 1);
		addCharset(UTF8, 1);
		addCharset("ISO-8859-1", 1);
		addCharset(UTF16, 2);
		addCharset("UTF-16BE", 2);
		addCharset("UTF-16LE", 2);
		addCharset(UTF32, 4);
		addCharset("UTF-32BE", 4);
		addCharset("UTF-32LE", 4);
	}

	private void addCharset(String name, int charSize) {
		CharsetInfoRec rec = new CharsetInfoRec(name, charSize);
		charsetInfoRecsByName.put(name, rec);
		charsetNamesList.add(name);
	}

	/**
	 * Returns an array list of the currently configured charsets.
	 * 
	 * @return String[] of current configured charsets.
	 */
	public String[] getCharsetNames() {
		return charsetNames;
	}

	/**
	 * Returns the number of bytes that the specified charset needs to specify a
	 * character.
	 *
	 * @param charsetName charset name
	 * @return number of bytes in a character, ie. 1, 2, 4, etc, defaults to 1
	 *         if charset is unknown or not specified in config file.
	 */
	public int getCharsetCharSize(String charsetName) {
		CharsetInfoRec rec = charsetInfoRecsByName.get(charsetName);
		return (rec != null) ? rec.charSize : 1;
	}

	/**
	 * Returns list of {@link Charset}s that encode with the number of bytes specified.
	 * @param size the number of bytes for the {@link Charset} encoding.
	 * @return Charsets that encode one byte characters.
	 */
	public List<String> getCharsetNamesWithCharSize(int size) {
		List<String> names = new ArrayList<>();
		for (String name : charsetNames) {
			if (getCharsetCharSize(name) == size) {
				names.add(name);
			}
		}
		return names;
	}

	private void addJVMAvailableCharsets() {
		// Add charsets that can be discovered in the current JVM.
		for (String csName : Charset.availableCharsets().keySet()) {
			if (charsetInfoRecsByName.containsKey(csName)) {
				continue;
			}
			addCharset(csName, 1);
		}
	}

	@SuppressWarnings("unchecked")
	private void readConfigFile() {
		ResourceFile xmlFile = Application.findDataFileInAnyModule("charset_info.xml");
		try (InputStream xmlInputStream = xmlFile.getInputStream()) {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document doc = sax.build(xmlInputStream);
			Element root = doc.getRootElement();
			for (Element child : (List<Element>) root.getChildren("charset")) {
				try {
					String name = child.getAttributeValue("name");
					if (name == null || name.trim().isEmpty()) {
						throw new IOException("Bad charset definition in " + xmlFile);
					}
					if (!Charset.isSupported(name)) {
						Msg.warn(this,
							"Unsupported charset defined in " + xmlFile.getName() + ": " + name);
					}

					int charSize = XmlUtilities.parseBoundedIntAttr(child, "charSize", 1, 8);

					addCharset(name, charSize);
				}
				catch (NumberFormatException nfe) {
					throw new IOException("Invalid charset definition in " + xmlFile);
				}
			}
		}
		catch (JDOMException | IOException e) {
			Msg.showError(this, null, "Error reading charset data", e.getMessage(), e);
		}

	}

	private static class CharsetInfoRec {
		final String name;
		final int charSize;

		CharsetInfoRec(String name, int charSize) {
			this.name = name;
			this.charSize = charSize;
		}
	}

}
