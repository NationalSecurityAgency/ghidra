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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The <CODE>FunctionThunkFieldLocation</CODE> class provides specific information
 * about the Function Thunk field within a program location.
 */
public class FunctionThunkFieldLocation extends FunctionSignatureFieldLocation {

	/**
	 * Construct a new FunctionThunkFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param charOffset the position within the function thunk string for this location.
	 * @param signature the function signature string at this location.
	 */
	public FunctionThunkFieldLocation(Program program, Address locationAddr, Address functionAddr,
			int charOffset, String signature) {

		super(program, locationAddr, functionAddr, charOffset, signature);
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionThunkFieldLocation() {
	}

}
