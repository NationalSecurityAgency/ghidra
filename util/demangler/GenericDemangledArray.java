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
package util.demangler;

import java.util.regex.Matcher;

public class GenericDemangledArray extends GenericDemangledDataType {

	private String dataType;

	public GenericDemangledArray(String name) {
		super(name);
		setArray();
	}

	public void setDataType(String dataType) {
		this.dataType = dataType;
	}

	public String getDataType() {
		return dataType;
	}

	@Override
	public void copyInto(GenericDemangledVariable destination) {
		super.copyInto(destination);

		if (dataType != null) {
			GenericDemangledDataType dt = new GenericDemangledDataType(dataType);
			destination.setDatatype(dt);
		}
	}

	/**
	 * Note: this code is a modified form of what was in the parent class, specifically to 
	 * handle arrays.  Also, feel free to jigger this around, as long as the tests pass, we are
	 * probably OK.  There is probably a lot of code in this method that is not needed.
	 */
	@Override
	public String toSignature() {
		StringBuffer buffer = new StringBuffer();

		if (isUnion) {
			buffer.append(UNION).append(SPACE);
		}
		if (isStruct) {
			buffer.append(STRUCT).append(SPACE);
		}
		if (isEnum) {
			buffer.append(ENUM).append(SPACE);
		}
		if (isClass) {
			buffer.append(CLASS).append(SPACE);
		}
		if (isComplex) {
			buffer.append(COMPLEX).append(SPACE);
		}
		if (isVolatile) {
			buffer.append(VOLATILE).append(SPACE);
		}
		if (isSigned) {
			buffer.append(SIGNED).append(SPACE);
		}
		if (isUnsigned) {
			buffer.append(UNSIGNED).append(SPACE);
		}

		String space = "";
		if (dataType != null) {
			buffer.append(space).append(dataType);
			space = String.valueOf(SPACE);
		}

		if (isConst()) {
			buffer.append(space).append(CONST);
			space = String.valueOf(SPACE);
		}

		if (getNamespace() != null) {
			buffer.append(getNamespace().toNamespace());
		}

		if (getName() != null) {
			buffer.append(getName());
			space = String.valueOf(SPACE);
		}

		if (getTemplate() != null) {
			buffer.append(getTemplate().toTemplate());
			space = String.valueOf(SPACE);
		}

		if (isUnaligned) {
			buffer.append(space).append(UNALIGNED);
			space = String.valueOf(SPACE);
		}

		if (isFar) {
			buffer.append(space).append(FAR);
			space = String.valueOf(SPACE);
		}

		if (isRestrict) {
			buffer.append(space).append(RESTRICT);
			space = String.valueOf(SPACE);
		}

		handlePointer(buffer, space);

		if (isReference) {

			// ugly, but MS does this
			boolean hasPointers = pointerLevels >= 1;
			if (isConst() && hasPointers) {
				buffer.append(space).append(CONST);
				space = String.valueOf(SPACE);
			}

			buffer.append(space).append(REF_NOTATION);
			space = String.valueOf(SPACE);
		}

		handleTrailingPointer(buffer, space);

		if (isArray) {
			Matcher matcher = ARRAY_SUBSCRIPT_PATTERN.matcher(getName());
			if (!matcher.find()) {
				// only put subscript on if the name doesn't have it
				buffer.append(ARR_NOTATION);
			}
		}
		return buffer.toString();
	}

	private void handlePointer(StringBuffer buffer, String space) {
		String myName = getName();
		if (myName.contains("*")) {
			return; // don't add pointer notation if it is already in the name
		}

		boolean hasPointers = pointerLevels >= 1;
		if (hasPointers) {
			buffer.append(space + PTR_NOTATION);
			space = String.valueOf(SPACE);
		}
	}

	private void handleTrailingPointer(StringBuffer buffer, String space) {
// not sure if we need this here		
//		String myName = getName();
//		if (myName.contains("*")) {
//			return; // don't add pointer notation if it is already in the name
//		}

		if (isPointer64) {
			buffer.append(space).append(PTR64);
			space = String.valueOf(SPACE);
		}

		for (int i = 1; i < pointerLevels; i++) {

			// ugly, but MS does this			
			if (isConst()) {
				buffer.append(space).append(CONST);
				space = String.valueOf(SPACE);
			}

			buffer.append(space).append(PTR_NOTATION);
			space = String.valueOf(SPACE);

			// ugly, but MS does this
			if (isPointer64) {
				buffer.append(space).append(PTR64);
				space = String.valueOf(SPACE);
			}
		}
	}
}
