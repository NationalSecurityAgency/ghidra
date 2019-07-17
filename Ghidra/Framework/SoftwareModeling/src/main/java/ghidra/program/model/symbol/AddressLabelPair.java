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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;

import java.io.Serializable;

/**
 * Container for holding an address and label.
 */
public final class AddressLabelPair implements Serializable {
	private Address addr;
	private String label;

	/**
	 * Creates a new <CODE>AddressLabelPair</CODE>.
	 * @param addr the address 
	 * @param label the label
	 */
    public AddressLabelPair(Address addr, String label) {
		this.addr = addr;
		this.label = label;
    }

	/**
	 * Returns the address.
	 */
    public Address getAddress() {
		return addr;
    }

	/**
	 * Returns the label.
	 */
    public String getLabel() {
		return label;
    }


	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @Override
    public boolean equals(Object obj) {
        if(obj == null) {
            return false;
        }
        if(!(obj instanceof AddressLabelPair)) {
            return false;
        }
        
        AddressLabelPair objPair = (AddressLabelPair) obj;

        // must have both labels being non-null
        return SystemUtilities.isEqual( objPair.label, this.label ) && 
        	objPair.addr.equals(this.addr);
    }

}
