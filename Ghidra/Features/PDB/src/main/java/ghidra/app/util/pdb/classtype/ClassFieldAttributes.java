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
package ghidra.app.util.pdb.classtype;

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

	public synchronized static ClassFieldAttributes get(Access access, Property property) {
		ClassFieldAttributes key = new ClassFieldAttributes(access, property);
		ClassFieldAttributes cfa = map.putIfAbsent(key, key);
		return (cfa != null) ? cfa : key;
	}

	public static ClassFieldAttributes convert(ClassFieldMsAttributes msAtts,
			Access defaultAccess) {
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

	public Access getAccess() {
		return access;
	}

	public Property getProperty() {
		return property;
	}

	public void emit(StringBuilder builder) {
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

}
