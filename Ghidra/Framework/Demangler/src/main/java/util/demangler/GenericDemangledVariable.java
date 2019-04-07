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

/**
 * An interface to represent a demangled global variable.
 */
public class GenericDemangledVariable extends GenericDemangledObject {
	private GenericDemangledDataType datatype;

	public GenericDemangledVariable(String name) {
		this.name = name;
	}

	public void setDatatype(GenericDemangledDataType datatype) {
		this.datatype = datatype;
	}

	/**
	 * Returns the data type of this variable.
	 * @return the data type of this variable
	 */
	public GenericDemangledDataType getDataType() {
		return datatype;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();

		buffer.append(visibility == null || "global".equals(visibility) ? EMPTY_STRING
				: visibility + SPACE);

		if (isStatic()) {
			buffer.append("static ");
		}

		String spacer = EMPTY_STRING;
		if (isUnsigned) {
			buffer.append("unsigned");
			spacer = SPACE;
		}

		if (isStruct) {
			buffer.append("struct");
			spacer = SPACE;
		}

		if (specialPrefix != null) {
			buffer.append(specialPrefix);
			spacer = SPACE;
		}

		boolean hasName = (name != null) && !name.isEmpty();
		if (!(datatype instanceof GenericDemangledFunctionPointer)) {

			if (datatype != null) {
				buffer.append(spacer);
				buffer.append(datatype.toSignature());
				spacer = SPACE;
			}
		}

		// e.g., 'const' - this appears after the data type in MS land
		if (storageClass != null) {
			buffer.append(spacer).append(storageClass);
			spacer = SPACE;
		}

		if (namespace != null) {

			buffer.append(spacer);
			spacer = EMPTY_STRING;

			buffer.append(namespace.toNamespace());

			if (!hasName) {
				int end = buffer.length();
				buffer.delete(end - 2, end); // strip off the last namespace characters
			}
		}

		if (hasName) {
			buffer.append(spacer);
			spacer = EMPTY_STRING;
			buffer.append(name);
		}

		buffer.append(specialMidfix == null ? EMPTY_STRING : specialMidfix + SPACE);
		buffer.append(specialSuffix == null ? EMPTY_STRING : SPACE + specialSuffix);

		if (datatype instanceof GenericDemangledFunctionPointer) {
			GenericDemangledFunctionPointer funcPtr = (GenericDemangledFunctionPointer) datatype;
			return funcPtr.toSignature(buffer.toString());
		}

		if (isConst()) {
			buffer.append(" const");
		}

		return buffer.toString().trim();
	}
}
