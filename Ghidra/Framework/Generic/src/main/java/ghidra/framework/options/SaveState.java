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
import java.util.List;

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

	private static final String XML_TYPE = "SaveState";
	static final String SAVE_STATE_TAG_NAME = "SAVE_STATE";
	static final String DEFAULT_NAME = "UNNAMED";

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
	 * Default Constructor for SaveState; uses {@value #DEFAULT_NAME} as the name of the state.
	 * @see java.lang.Object#Object()
	 */
	public SaveState() {
		this(SAVE_STATE_TAG_NAME);
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

	@SuppressWarnings("unchecked")
	@Override
	protected void processElement(Element element) {
		String tag = element.getName();
		if (!tag.equals(SAVE_STATE_TAG_NAME)) {
			super.processElement(element);
			return;
		}

		if (isOldStyleSaveState(element)) {
			restoreSaveStateWithoutKeyAttribute(element);
			return;
		}

		/*
		 	We are restoring a child SaveState from xml.
		 	
		 	When using a SaveState inside of a SaveState, we produce xml that looks like this: 
		 	
		    <SAVE_STATE>
				<SAVE_STATE KEY="Property Key" NAME="Client Name" TYPE="SaveState">
				    <STATE NAME="a" TYPE="int" VALUE="5" />
				</SAVE_STATE>
			</SAVE_STATE>
		 */

		String key = element.getAttributeValue(ATTRIBUTE_KEY);
		String name = element.getAttributeValue(ATTRIBUTE_NAME);
		SaveState saveState = createSaveState(name);

		List<Element> children = element.getChildren();
		for (Element e : children) {
			saveState.processElement(e);
		}

		map.put(key, saveState);
	}

	@SuppressWarnings("unchecked")
	private void restoreSaveStateWithoutKeyAttribute(Element element) {

		String key = element.getAttributeValue(ATTRIBUTE_NAME);
		SaveState saveState = createSaveState(null);
		List<Element> children = element.getChildren();
		if (children.isEmpty()) {
			map.put(key, saveState);
			return;
		}

		Element child = (Element) element.getChildren().get(0);
		if (child == null) {
			return; //  not sure if this can happen
		}

		/*
			Old style tag, with one level of extra nesting
			
			<SAVE_STATE NAME="Bar" TYPE="SaveState">
			    <SAVE_STATE>   <-- This is an intermediate 'child' tag
			        <STATE NAME="DATED_OPTION" TYPE="int" VALUE="3" />
			    </SAVE_STATE>
			</SAVE_STATE>
			
			and another old style:
			
			<SAVE_STATE NAME="Bar" TYPE="SaveState">  (this has no intermediate 'child' tag)
			    <STATE NAME="DATED_OPTION" TYPE="int" VALUE="3" />
			</SAVE_STATE>		
		*/

		String childTag = child.getName();
		if (!childTag.equals(STATE)) {
			// this is the case where we have an intermediate node; we want that child's children
			children = child.getChildren();
		}

		for (Element e : children) {
			saveState.processElement(e);
		}

		map.put(key, saveState);
	}

	private boolean isOldStyleSaveState(Element element) {
		/*
		 	Older style save states looked like this:
		 	
		 		<SAVE_STATE NAME="Foo" TYPE="SaveState">
		 	
		 	where there is no 'KEY' attribute.  The new style looks like this (note that the value
		 	of 'KEY' used to be the value stored in 'NAME'):
		 	
		 		<SAVE_STATE KEY="Foo" NAME="Client Name" TYPE="SaveState">
		 */
		return element.getAttribute(ATTRIBUTE_KEY) == null;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected Element createElement(String key, Object value) {
		if (!(value instanceof SaveState saveState)) {
			return super.createElement(key, value);
		}

		/*
		 	We are saving a child SaveState to xml.
		 	
		 	When using a SaveState inside of a SaveState, we produce xml that looks like this: 
		 	
		    <SAVE_STATE>
				<SAVE_STATE KEY="Property Key" NAME="Client Name" TYPE="SaveState">
				    <STATE NAME="a" TYPE="int" VALUE="5" />
				</SAVE_STATE>
			</SAVE_STATE>
		 */

		Element savedElement = saveState.saveToXml();
		Element element = new Element(SAVE_STATE_TAG_NAME);

		String name = saveState.getName();
		if (SAVE_STATE_TAG_NAME.equals(name)) {
			name = DEFAULT_NAME;
		}

		element.setAttribute(ATTRIBUTE_NAME, name);
		element.setAttribute(ATTRIBUTE_KEY, key);
		element.setAttribute(ATTRIBUTE_TYPE, XML_TYPE);

		// do not write an extra <SAVE_STATE> intermediate node
		List<Element> children = savedElement.getChildren();
		for (Element e : children) {
			Element newElement = (Element) e.clone();
			element.addContent(newElement);
		}

		return element;
	}

	// allows subclasses to override how sub-save states are created
	protected SaveState createSaveState(String name) {
		if (name == null) {
			// null implies an old style xml where a name was not specified
			return new SaveState();
		}
		return new SaveState(name);
	}
}
