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
package ghidra.program.database.function;

import ghidra.program.database.symbol.OverlappingNamespaceException;
import ghidra.program.model.address.Address;

public class OverlappingFunctionException extends Exception {

	public OverlappingFunctionException(Address entryPoint, OverlappingNamespaceException e) {
		super("Unable to create function at " + entryPoint + " due to overlap with range [" +
			e.getStart() + "," + e.getEnd() + "]");
	}
	
	public OverlappingFunctionException(Address entryPoint) {
		super("Unable to create function at " + entryPoint + " due to overlap with another namespace");
	}

	public OverlappingFunctionException(String msg) {
		super(msg);
	}

}
