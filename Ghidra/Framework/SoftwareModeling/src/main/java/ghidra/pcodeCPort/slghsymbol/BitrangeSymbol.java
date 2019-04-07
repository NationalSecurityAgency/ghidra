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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.sleigh.grammar.Location;

// A smaller bitrange within a varnode
public class BitrangeSymbol extends SleighSymbol {

	VarnodeSymbol varsym; // Varnode containing the bitrange
	int bitoffset; // least significant bit of range
	int numbits; // number of bits in the range

	public BitrangeSymbol(Location location) {
	    super(location);
	} // For use with restoreXml

	public BitrangeSymbol( Location location, String nm, VarnodeSymbol sym, int bitoff, int num ) {
		super( location, nm );
		varsym = sym;
		bitoffset = bitoff;
		numbits = num;
	}

	public VarnodeSymbol getParentSymbol() {
		return varsym;
	}

	public int getBitOffset() {
		return bitoffset;
	}

	public int numBits() {
		return numbits;
	}

	@Override
    public symbol_type getType() {
		return symbol_type.bitrange_symbol;
	}

}
