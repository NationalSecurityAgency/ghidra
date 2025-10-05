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

import java.util.*;
import java.util.Map.Entry;

import org.jdom.Attribute;
import org.jdom.Element;

/**
 * A version of {@link SaveState} that allows clients to add attributes to properties in this save
 * state.  The following code shows how to use this class:
 * <pre>
 * AttributedSaveState ss = new AttributedSaveState();
 * ss.putBoolean("Happy", true);
 * 
 * Map<String, String> attrs = Map.of("MyAttribute", "AttributeValue");
 * ss.addAttrbibutes("Happy", attrs);
 * </pre>
 * 
 * <p>In this example, the property "Happy" will be given the attribute "MyAttribute" with the value
 * of "AttributeValue".  This is useful for clients that wish to add attributes to individual 
 * properties, such as a date for tracking usage.
 * 
 * <p><u>Usage Note:</u> The given attributes are only supported when writing and reading xml. Json
 * is not supported.
 */
public class AttributedSaveState extends SaveState {

	private Map<String, Map<String, String>> propertyAttributes;

	public AttributedSaveState() {
		super();
	}

	public AttributedSaveState(String name) {
		super(name);
	}

	public AttributedSaveState(Element root) {
		super(root);
	}

	/**
	 * Adds the given map of attribute name/value pairs to this save state.
	 * @param propertyName the property name within this save state that will be attributed
	 * @param attributes the attributes
	 */
	public void addAttributes(String propertyName, Map<String, String> attributes) {
		getPropertyAttributes().put(propertyName, attributes);
	}

	/**
	 * Removes all attributes associated with the given property name.
	 * @param propertyName the property name within this save state that has the given attributes
	 */
	public void removeAttributes(String propertyName) {
		getPropertyAttributes().remove(propertyName);
	}

	/**
	 * Gets the attributes currently associated with the given property name
	 * @param propertyName the property name for which to get attributes
	 * @return the attributes or null
	 */
	public Map<String, String> getAttributes(String propertyName) {
		return getPropertyAttributes().get(propertyName);
	}

	private Map<String, Map<String, String>> getPropertyAttributes() {
		if (propertyAttributes == null) {
			propertyAttributes = new HashMap<>();
		}
		return propertyAttributes;
	}

	@Override
	protected SaveState createSaveState() {
		return new AttributedSaveState();
	}

	@Override
	protected void initializeElement(Element e) {

		String name = e.getAttributeValue(NAME);
		if (name == null) {
			return; // sub-element; properties not supported
		}

		// 
		// Overridden to add our attributes to the newly created element, used to create xml
		// 
		Map<String, String> attrs = getPropertyAttributes().get(name);
		if (attrs != null) {
			Set<Entry<String, String>> entries = attrs.entrySet();
			for (Entry<String, String> entry : entries) {
				String key = entry.getKey();
				String value = entry.getValue();
				e.setAttribute(key, value);
			}
		}
	}

	@Override
	protected void processElement(Element element) {
		super.processElement(element);

		String name = element.getAttributeValue(NAME);
		if (name == null) {
			return; // sub-element; properties not supported
		}

		//
		// Overridden to extract non-standard attributes from the given element.  The element was 
		// created after restoring from xml.   We extract the attributes that we added above in
		// initializeElement().
		// 
		Map<String, String> newAttrs = new HashMap<>();

		@SuppressWarnings("unchecked")
		List<Attribute> attrs = element.getAttributes();
		for (Attribute attr : attrs) {

			String attrName = attr.getName();
			String attrValue = switch (attrName) {
				// ignore standard attributes, as they are managed by the parent class
				case NAME, TYPE, VALUE -> null;
				default -> attr.getValue();
			};

			if (attrValue != null) {
				newAttrs.put(attrName, attrValue);
			}
		}

		if (!newAttrs.isEmpty()) {
			getPropertyAttributes().put(name, newAttrs);
		}
	}
}
