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
package ghidra.program.util;
import ghidra.program.model.address.Address;

/**
 *  Specifies a selection that consists of components inside a structure.
 */
public class InteriorSelection {
	
	private ProgramLocation from;
	private ProgramLocation to;
	private Address start;
	private Address end;

	/**
	 * Construct a new interior selection.
	 * @param from start location
	 * @param to end location
	 * @param start start address
	 * @param end end address
	 */
    public InteriorSelection(ProgramLocation from, ProgramLocation to, Address start, Address end) {
		this.from = from;
		this.to = to;
		this.start = start;
		this.end = end;
    }
    /**
     * Get the start location.
     * @return ProgramLocation
     */
	public ProgramLocation getFrom() {
		return from;
	}
	/**
	 * Get the end location.
	 * @return ProgramLocation
	 */
	public ProgramLocation getTo() {
		return to;
	}
	/**
	 * Get the start address of this selection.
	 * @return Address
	 */
	public Address getStartAddress() {
		return start;
	}
	/**
	 * Get the end address of this selection.
	 * @return Address
	 */
	public Address getEndAddress() {
		return end;
	}
	/**
	 * Get the number of bytes contained in the selection.
	 * @return int
	 */
	public int getByteLength() {
		long diff = end.subtract(start);
		return (int) (diff+1);
	}

	/**
	 * 
	 * @see java.lang.Object#equals(Object)
	 */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
	    InteriorSelection is = (InteriorSelection)obj;

		return from.equals(is.from) && to.equals(is.to);
    }

	/* (non Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return "From = " + from.getAddress() + ", To = " + to.getAddress();
	}

}
