/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util;

import ghidra.program.model.address.*;

public class XmlProgramUtilities {
	/**
	 * Creates a string representation of the specifed address.
	 * @param addr the address to convert to a string
	 * @return the string representation of the address
	 */
	public static String toString(Address addr) {
	    AddressSpace space = addr.getAddressSpace();
	    if (space instanceof OverlayAddressSpace) {
	        OverlayAddressSpace oSpace = (OverlayAddressSpace)space;
	        return oSpace.toString()+oSpace.getOverlayedSpace().toString()+addr.toString(false);
	    }
	    return addr.toString();
	}
	/**
	 * Parses the address string.
	 * @param factory the address factory
	 * @param addrString the address string to parse
	 * @return the parsed address, or null
	 */
	public static Address parseAddress(AddressFactory factory, String addrString) {
	    if (addrString == null) {
	        return null;
	    }
        Address addr = factory.getAddress(addrString);
        if (addr == null) {
            int index = addrString.indexOf("::");
            if (index > 0) {
                addr = factory.getAddress(addrString.substring(index+2));
            }
        }
        return addr;
	}
}
