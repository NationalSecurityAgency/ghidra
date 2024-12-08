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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;

/**
 * Abstract base for information about type methods and interface methods
 */
public abstract class MethodInfo {
	final Address address;

	public MethodInfo(Address address) {
		this.address = address;
	}

	/**
	 * Entry point of the method
	 * 
	 * @return {@link Address}
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Function signature of the method.
	 * 
	 * @return {@link FunctionDefinition}
	 * @throws IOException if error reading method information
	 */
	abstract public FunctionDefinition getSignature() throws IOException;
}
