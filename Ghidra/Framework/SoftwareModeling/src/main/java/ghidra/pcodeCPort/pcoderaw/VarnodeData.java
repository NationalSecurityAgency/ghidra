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
package ghidra.pcodeCPort.pcoderaw;

import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.address.AddressUtils;
import ghidra.pcodeCPort.space.AddrSpace;

public class VarnodeData {
	//  string name;			// This field will be depracated when sleigh comes on line
	public AddrSpace space;

	public long offset;

	public int size;

	public VarnodeData() {
	}

	public VarnodeData(AddrSpace base, long off, int size) {
		space = base;
		offset = off;
		this.size = size;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != VarnodeData.class) {
			return false;
		}
		VarnodeData other = (VarnodeData) obj;
		return space == other.space && offset == other.offset && size == other.size;
	}

	@Override
	public int hashCode() {
		return space.hashCode() + (int) offset + size;
	}

	public int compareTo(VarnodeData other) {
		int result = space.compareTo(other.space);
		if (result != 0) {
			return result;
		}
		result = AddressUtils.unsignedCompare(offset, other.offset);
		if (result != 0) {
			return result;
		}
		return other.size - size;// BIG sizes come first
	}

	public Address getAddress() {
//	    if ( space == null ) {
//	        return new Address( AddrSpace.MIN_SPACE, 0 );
//	    }
		return new Address(this.space, this.offset);
	}
}
