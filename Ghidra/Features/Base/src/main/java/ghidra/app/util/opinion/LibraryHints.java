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
package ghidra.app.util.opinion;

import java.io.*;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * <code>LibraryHints</code> provides a means of specifying certain LIBRARY
 * EXPORT attributes which should be included when the associated .exports file
 * is created.
 */
class LibraryHints {

	private static final String HINTS_EXT = ".hints";

	private HashMap<String, List<Attribute>> nameAttributeMap =
		new HashMap<String, List<Attribute>>();
	private HashMap<Integer, List<Attribute>> ordinalAttributeMap =
		new HashMap<Integer, List<Attribute>>();

	private LibraryHints() {
	}

	private void add(int ordinal, Attribute attr) {
		List<Attribute> list = ordinalAttributeMap.get(ordinal);
		if (list == null) {
			list = new ArrayList<Attribute>();
			ordinalAttributeMap.put(ordinal, list);
		}
		list.add(attr);
	}

	private void add(String name, Attribute attr) {
		List<Attribute> list = nameAttributeMap.get(name);
		if (list == null) {
			list = new ArrayList<Attribute>();
			nameAttributeMap.put(name, list);
		}
		list.add(attr);
	}

	private void loadMap(List<Attribute> list, HashMap<String, Attribute> map) {
		if (list != null) {
			for (Attribute attr : list) {
				map.put(attr.getName(), attr);
			}
		}
	}

	private Attribute getAttribute(List<Attribute> list, String attrName) {
		if (list != null) {
			for (Attribute attr : list) {
				if (attrName.equals(attr.getName())) {
					return attr;
				}
			}
		}
		return null;
	}

	/**
	 * Get all attribute hints based on ordinal and/or label name. Use of the
	 * ordinal takes precedence for any given attribute hint.
	 * 
	 * @param ordinal
	 * @param name
	 * @return collection of attribute hints
	 */
	Collection<Attribute> getAttributeHints(int ordinal, String name) {
		HashMap<String, Attribute> map = new HashMap<String, Attribute>();
		loadMap(nameAttributeMap.get(name), map);
		loadMap(ordinalAttributeMap.get(ordinal), map);
		return map.values();
	}

	/**
	 * Get the named attribute hint based on either an ordinal or label name.
	 * Use of the ordinal takes precedence.
	 * 
	 * @param ordinal
	 * @param name
	 * @param attrName
	 * @return attribute hint or null
	 */
	Attribute getAttributeHint(int ordinal, String name, String attrName) {
		List<Attribute> list = ordinalAttributeMap.get(ordinal);
		if (list != null) {
			Attribute attr = getAttribute(list, attrName);
			if (attr != null) {
				return attr;
			}
		}
		list = nameAttributeMap.get(name);
		if (list != null) {
			Attribute attr = getAttribute(list, attrName);
			if (attr != null) {
				return attr;
			}
		}
		return null;
	}

	private static ResourceFile getHintsFile(String libraryName, int size) {
		String filename = libraryName.toUpperCase();
		return LibraryLookupTable.getExistingExtensionedFile(filename, HINTS_EXT, size);
	}

	static LibraryHints getLibraryHints(String libraryName, int size) {
		LibraryHints hints = new LibraryHints();
		ResourceFile file = getHintsFile(libraryName, size);
		if (file != null && file.isFile()) {
			hints.readLibraryHints(file);
		}
		return hints;
	}

	private void readLibraryHints(ResourceFile hintsFile) {

		InputStream is = null;
		try {
			is = new BufferedInputStream(hintsFile.getInputStream());
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document document = sax.build(is);
			Element root = document.getRootElement();

			if (!"LIBRARY_HINTS".equals(root.getName())) {
				throw new SAXNotRecognizedException("Expected LIBRARY_HINTS document");
			}

			Iterator<?> iter = root.getChildren().iterator();
			while (iter.hasNext()) {
				Element element = (Element) iter.next();
				if ("HINT".equals(element.getName())) {
					parseHint(element);
				}
				else {
					throw new SAXNotRecognizedException("Unexpected element: " + element.getName());
				}
			}
		}
		catch (Exception e) {
			Msg.error(this, "Error occurred while parsing hints file: " + hintsFile, e);
		}
		finally {
			if (is != null) {
				try {
					is.close();
				}
				catch (IOException e1) {
				}
			}
		}
	}

	private void parseHint(Element element) throws SAXException {
		String attrName = element.getAttributeValue("ATTR");
		String value = element.getAttributeValue("VALUE");
		if (attrName == null) {
			throw new SAXException("HINT element requires both ATTR and VALUE attributes");
		}
		String ordStr = element.getAttributeValue("ORDINAL");
		if (ordStr != null) {
			try {
				add(Integer.parseInt(ordStr), new Attribute(attrName, value));
			}
			catch (NumberFormatException e) {
				throw new SAXException("HINT element ORDINAL attribute must be an integer value");
			}
		}
		String name = element.getAttributeValue("NAME");
		if (name != null) {
			add(name, new Attribute(attrName, value));
		}
	}

}
