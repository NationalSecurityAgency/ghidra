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
 * The <CODE>XRefHeaderFieldLocation</CODE> class contains specific location information
 * within the XREF field header that precedes the XREF field locations.
 */
public class XRefHeaderFieldLocation extends XRefFieldLocation {

	public XRefHeaderFieldLocation(Program program, Address addr, int[] componentPath,
			int charOffset) {
		super(program, addr, componentPath, null, 0, charOffset);
	}

	/**
	 * Should only be used for XML restoring.
	 */
	public XRefHeaderFieldLocation() {
		super();
	}

}
