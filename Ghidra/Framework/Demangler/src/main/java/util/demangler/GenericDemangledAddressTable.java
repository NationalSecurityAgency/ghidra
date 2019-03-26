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

public class GenericDemangledAddressTable extends GenericDemangledObject {

	private int length;

	public GenericDemangledAddressTable(String name, int length) {
		this.name = name;
		this.length = length;
	}

	/**
	 * Returns the length of the address table.
	 * -1 indicates the length is unknown.
	 * @return the length of the address table
	 */
	public int getLength() {
		return length;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();

		if (specialPrefix != null) {
			buffer.append(specialPrefix);
			buffer.append(' ');
		}

		if (namespace != null) {
			String namespaceStr = namespace.toSignature();
			buffer.append(namespaceStr);
			if (!namespaceStr.endsWith(NAMESPACE_SEPARATOR)) {
				buffer.append(NAMESPACE_SEPARATOR);
			}
		}

		buffer.append(name);

		return buffer.toString();
	}
}
