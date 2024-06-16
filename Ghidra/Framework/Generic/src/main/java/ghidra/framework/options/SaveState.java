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
package ghidra.framework.options;

import java.io.File;
import java.io.IOException;

import org.jdom.Element;

/**
 * Class for saving name/value pairs as XML or Json.  Classes that want to be
 * able to save their state can do so using the SaveState object.
 * The idea is that each state variable in the class
 * is first saved into a SaveState object via a String key.  Then the SaveState
 * object is written out as XML or Json.  When the save state object is
 * restored, the SaveState object is constructed with an XML Element or JsonObject
 * that contains all of the name/value pairs. Since the "get" methods require
 * a default value, the object that is recovering its state variables
 * will be successfully initialized even if
 * the given key,value pair is not found in the SaveState object.
 * <p> <i>Note: Names for options are assumed to be unique. When a putXXX()
 * method is called, if a value already exists for a name, it will
 * be overwritten.</i>
 * <P>
 * The SaveState supports the following types:
 * <pre>
 *      java primitives
 *      arrays of java primitives
 *      String
 *      Color
 *      Font
 *      KeyStroke
 *      File
 *      Date
 *      Enum
 *      SaveState (values can be nested SaveStates)
 *  </pre>
 */

public class SaveState extends XmlProperties {
	private static final String SAVE_STATE = "SAVE_STATE";

	/**
	 * Creates a new SaveState object with a non-default name.  The name serves no real purpose
	 * other than as a hint as to what the SaveState represents
	 * 
	 * @param name of the state
	 */
	public SaveState(String name) {
		super(name);
	}

	/**
	 * Default Constructor for SaveState; uses "SAVE_STATE" as the
	 * name of the state.
	 * @see java.lang.Object#Object()
	 */
	public SaveState() {
		this(SAVE_STATE);
	}

	/**
	 * Construct a SaveState from a file containing XML from a previously saved SaveState.
	 * @param file the file containing the XML to read.
	 * @throws IOException if the file can't be read or is not formatted properly for a SaveState
	 */
	public SaveState(File file) throws IOException {
		super(file);
	}

	public SaveState(Element element) {
		super(element);
	}

	/**
	 * Write the saveState to a file as XML
	 * @param file the file to write to.
	 * @throws IOException if the file could not be written
	 */
	public void saveToFile(File file) throws IOException {
		saveToXmlFile(file);
	}

	/**
	 * Associates a sub SaveState value with the given name.
	 * @param name The name in the name,value pair.
	 * @param value The value in the name,value pair.
	 */
	public void putSaveState(String name, SaveState value) {
		map.put(name, value);
	}

	/**
	 * Returns the sub SaveState associated with the
	 * given name.
	 * @param name The name associated with the desired Element.
	 * @return The SaveState object associated with the
	 * given name.
	 */
	public SaveState getSaveState(String name) {
		return getAsType(name, null, SaveState.class);
	}

	protected void processElement(Element element) {
		String tag = element.getName();

		if (tag.equals("SAVE_STATE")) {
			Element child = (Element) element.getChildren().get(0);
			if (child != null) {
				String name = element.getAttributeValue(NAME);
				map.put(name, new SaveState(child));
				return;
			}
		}
		super.processElement(element);
	}

	@Override
	protected Element createElement(String key, Object value) {
		if (value instanceof SaveState saveState) {
			Element savedElement = saveState.saveToXml();
			Element element = new Element("SAVE_STATE");
			element.setAttribute(NAME, key);
			element.setAttribute(TYPE, "SaveState");
			element.addContent(savedElement);
			return element;
		}
		return super.createElement(key, value);
	}
}
