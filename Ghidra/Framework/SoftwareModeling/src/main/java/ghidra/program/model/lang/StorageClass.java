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
package ghidra.program.model.lang;

import ghidra.xml.XmlParseException;

/**
 * Data-type class for the purpose of assigning storage
 */
public enum StorageClass {
	GENERAL(0, "general"),		// General purpose
	FLOAT(1, "float"),			// Floating-point data-types
	PTR(2, "ptr"),				// Pointer data-types
	HIDDENRET(3, "hiddenret"),	// Class for hidden return values
	VECTOR(4, "vector"),		// Vector data-types
	CLASS1(100, "class1"),		// Architecture specific class 1
	CLASS2(101, "class2"),		// Architecture specific class 2
	CLASS3(102, "class3"),		// Architecture specific class 3
	CLASS4(103, "class4");		// Architecture specific class 4

	private int value;			// Value for comparing storage classes
	private String name;		// Name for marshaling

	private StorageClass(int val, String nm) {
		value = val;
		name = nm;
	}

	public int getValue() {
		return value;
	}

	@Override
	public String toString() {
		return name;
	}

	public static StorageClass getClass(String val) throws XmlParseException {
		switch (val) {
			case "general":
				return GENERAL;
			case "float":
				return FLOAT;
			case "ptr":
				return PTR;
			case "hiddenret":
				return HIDDENRET;
			case "vector":
				return VECTOR;
			case "class1":
				return CLASS1;
			case "class2":
				return CLASS2;
			case "class3":
				return CLASS3;
			case "class4":
				return CLASS4;
			default:
				break;
		}
		throw new XmlParseException("Unknown type class: " + val);
	}
}
