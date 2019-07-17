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
package ghidra.app.merge.propertylist;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;

/**
 * Container for conflicts on a property name.
 * 
 * 
 */
class ConflictInfo {

	private String listName;
	private String propertyName;
	private String displayedPropertyName;
	private String groupName;
	private OptionType myType;
	private OptionType latestType;
	private OptionType origType;
	private Object myValue;
	private Object latestValue;
	private Object origValue;
	private String myTypeString;
	private String latestTypeString;
	private String origTypeString;

	/**
	 * Constructor
	 * @param listName list name
	 * @param propertyName name of property in the list
	 * @param latestType property type in LATEST version
	 * @param myType property type in MY version
	 * @param origType property type in ORIGINAL version
	 * @param latestValue property's value in LATEST version
	 * @param myValue property's value in MY version
	 * @param origValue property's value in ORIGINAL version
	 */
	ConflictInfo(String listName, String propertyName, OptionType latestType, OptionType myType,
			OptionType origType, Object latestValue, Object myValue, Object origValue) {
		this.listName = listName;
		this.propertyName = propertyName;

		int pos = propertyName.lastIndexOf(Options.DELIMITER);
		if (pos > 0) {
			groupName = listName + " " + propertyName.substring(0, pos);
			displayedPropertyName = propertyName.substring(pos + 1);
		}
		else {
			groupName = listName;
			displayedPropertyName = propertyName;
		}
		this.myType = myType;
		this.latestType = latestType;
		this.origType = origType;
		this.myValue = myValue;
		this.latestValue = latestValue;
		this.origValue = origValue;

		myTypeString = getTypeString(myType);
		latestTypeString = getTypeString(latestType);
		origTypeString = getTypeString(origType);
	}

	boolean isTypeMatch() {
		return myType == latestType;
	}

	String getListName() {
		return listName;
	}

	String getPropertyName() {
		return propertyName;
	}

	String getDisplayedPropertyName() {
		return displayedPropertyName;
	}

	String getGroupName() {
		return groupName;
	}

	String getLatestTypeString() {
		return latestTypeString;
	}

	String getMyTypeString() {
		return myTypeString;
	}

	String getOrigTypeString() {
		return origTypeString;
	}

	Object getLatestValue() {
		return latestValue;
	}

	Object getMyValue() {
		return myValue;
	}

	Object getOrigValue() {
		return origValue;
	}

	OptionType getLatestType() {
		return latestType;
	}

	OptionType getMyType() {
		return myType;
	}

	OptionType getOrigType() {
		return origType;
	}

	private String getTypeString(OptionType type) {
		switch (type) {
			case BOOLEAN_TYPE:
				return "boolean";
			case DOUBLE_TYPE:
				return "double";
			case INT_TYPE:
				return "integer";
			case LONG_TYPE:
				return "long";
			case STRING_TYPE:
				return "string";
			case DATE_TYPE:
				return "date";
			case NO_TYPE:
			default:
				return "unknown";
		}
	}
}
