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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes;

/**
 *
 */
public class ClassFieldAttributes {

	private static final Map<ClassFieldAttributes, ClassFieldAttributes> map = new HashMap<>();

	// These initializations use the map above, so it must be initialized first
	public static final ClassFieldAttributes UNKNOWN = get(Access.UNKNOWN, Property.UNKNOWN);
	public static final ClassFieldAttributes BLANK = get(Access.BLANK, Property.BLANK);

	private final Access access;
	private final Property property;

	public static ClassFieldAttributes get(Access access, Property property) {
		ClassFieldAttributes key = new ClassFieldAttributes(access, property);
		ClassFieldAttributes cfa = map.putIfAbsent(key, key);
		return (cfa != null) ? cfa : key;
	}

	static ClassFieldAttributes convert(ClassFieldMsAttributes msAtts, Access defaultAccess) {
		Access myAccess = switch (msAtts.getAccess()) {
			case PUBLIC -> Access.PUBLIC;
			case PROTECTED -> Access.PROTECTED;
			case PRIVATE -> Access.PRIVATE;
			case BLANK -> defaultAccess;
			default -> Access.UNKNOWN;
		};
		Property myProperty = switch (msAtts.getProperty()) {
			case VIRTUAL -> Property.VIRTUAL;
			case STATIC -> Property.STATIC;
			case FRIEND -> Property.FRIEND;
			case BLANK -> Property.BLANK;
			default -> Property.UNKNOWN;
		};
		return get(myAccess, myProperty);
	}

	private ClassFieldAttributes(Access access, Property property) {
		this.access = access;
		this.property = property;
	}

	Access getAccess() {
		return access;
	}

	Property getProperty() {
		return property;
	}

	void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		if (access.getValue() > Access.BLANK.getValue()) {
			myBuilder.append(access);
			myBuilder.append(' ');
		}
		if (property.getValue() > Property.BLANK.getValue()) {
			myBuilder.append(property);
			myBuilder.append(' ');
		}
		builder.append(myBuilder);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		emit(builder);
		return builder.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(access, property);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ClassFieldAttributes other = (ClassFieldAttributes) obj;
		return access == other.access && property == other.property;
	}

	//----------------------------------------------------------------------------------------------
	// TODO: Consider expanding these beyond C++.
	//  See https://en.wikipedia.org/wiki/Access_modifiers
	//  These could then be:
//	UNKNOWN("UNKNOWN_ACCESS ", -1),
//	OPEN("open", 0),
//	PUBLIC("internal", 1),
//	INTERNAL("internal", 2),
//	PACKAGE("package", 3),
//	PROTECTED("protected", 4),
//	PROTECTED_INTERNAL("protected internal", 5),
//	PRIVATE_PROTECTED("private protected", 6),
//	FILE("file", 7),
//	FILE_PRIVATE("fileprivate", 8),
//	PRIVATE("private", 9);
	static enum Access {
		UNKNOWN("UNKNOWN_ACCESS", -1),
		BLANK("", 0), // eliminated 20230524... using defaultAccess on some methods. Could renumber
		PUBLIC("public", 1),
		PROTECTED("protected", 2),
		PRIVATE("private", 3);

		private static final Map<Integer, Access> BY_VALUE = new HashMap<>();
		static {
			for (Access val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}
		private final String label;
		private final int value;

		public String getString() {
			return label;
		}

		@Override
		public String toString() {
			return label;
		}

		public int getValue() {
			return value;
		}

		public static Access fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private Access(String label, int value) {
			this.label = label;
			this.value = value;
		}

		/**
		 * Merge two Access values, leaning toward more restrictive. UNKNOWN is only returned
		 *  if both are UNKNOWN.
		 * @param other value to merge
		 * @return the merged value
		 */
		public Access mergeRestrictive(Access other) {
			// No need to test for UNKNOWN as its value is on the permissive end.
			if (this.value > other.value) {
				return this;
			}
			return other;
		}

		/**
		 * Merge two Access values, leaning toward more permissive. UNKNOWN is only returned
		 *  if both are UNKNOWN.
		 * @param other value to merge
		 * @return the merged value
		 */
		public Access mergePermissive(Access other) {
			if (this.value < other.value) {
				// Only need special test for UNKNOWN here, as its value is on the permissive end.
				if (this == UNKNOWN) {
					return other;
				}
				return this;
			}
			return other;
		}
	}

	//----------------------------------------------------------------------------------------------
	static enum Property {
		UNKNOWN("INVALID_PROPERTY", -1),
		BLANK("", 0), // means non-virtual, non-static, non-friend
		VIRTUAL("virtual", 1),
		STATIC("static", 2),
		FRIEND("friend", 3);
		// Also consider <intro>, <pure>, <intro,pure>.  See MSFT.

		private static final Map<Integer, Property> BY_VALUE = new HashMap<>();
		static {
			for (Property val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}
		private final String label;
		private final int value;

		public String getString() {
			return label;
		}

		@Override
		public String toString() {
			return label;
		}

		public int getValue() {
			return value;
		}

		public static Property fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private Property(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}
}
