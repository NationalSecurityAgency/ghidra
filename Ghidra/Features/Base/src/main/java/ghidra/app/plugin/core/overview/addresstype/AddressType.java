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
package ghidra.app.plugin.core.overview.addresstype;

/**
 * An enum for the different types that are represented by unique colors by the
 * {@link AddressTypeOverviewColorService}
 */
public enum AddressType {
	FUNCTION("Function"),
	UNINITIALIZED("Uninitialized"),
	EXTERNAL_REF("External Reference"),
	INSTRUCTION("Instruction"),
	DATA("Data"),
	UNDEFINED("Undefined");

	private String description;

	AddressType(String description) {
		this.description = description;
	}

	/**
	 * Returns a description of this enum value.
	 * @return a description of this enum value.
	 */
	public String getDescription() {
		return description;
	}

}
