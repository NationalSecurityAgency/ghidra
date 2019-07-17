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
package ghidra.pcodeCPort.address;

import ghidra.pcodeCPort.pcoderaw.*;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.translate.*;
import ghidra.pcodeCPort.utils.*;

import java.io.PrintStream;

import org.jdom.Element;




//For specifying a storage space. Could be RAM, ROM, cpu register, data
//segment, coprocessor, stack, nvram, etc. 
//Note: cpui_mach_addr represents an offset ONLY, not an offset and length
//cpui_mach_addr is expected to print itself and read itself. It can take
//a size as a "suggestion" for how it should print itself

//All addresses are absolute and there are are no registers in CPUI. However,
//all addresses are prefixed with an "immutable" pointer, which can
//specify a separate RAM space, a register space, an i/o space etc. Thus
//a translation from a real machine language will typically simulate registers
//by placing them in their own space, separate from RAM. Indirection
//(i.e. pointers) must be simulated through the LOAD and STORE ops.
public class Address implements Comparable<Address>{
	public enum mach_extreme {
		m_minimal, m_maximal
	}

	private AddrSpace base; // Pointer to our address space

	private long offset; // Offset (in bytes)

	//	 Default invalid address
	public Address() {
		base = AddrSpace.MIN_SPACE;
	}

	public Address( AddrSpace id, long off ) {
		base = id;
		offset = off;		
	}

	public Address( Address addr ) {
		base = addr.base;
		offset = addr.offset;
	}

	//		  private int get_offset_size(const char *ptr);
	public boolean isInvalid() {
		return (base == AddrSpace.MIN_SPACE || base == AddrSpace.MAX_SPACE);
	}

	void setOffset( long o ) {
		offset = o;
	}

	public int getAddrSize() {
		return base.getAddrSize();
	}

	public boolean isBigEndian() {
		return base.isBigEndian();
	}

	void printOffset( PrintStream s ) {
		base.printOffset( s, offset );
	}

	public int printRaw( PrintStream s ) {
		return base.printRaw( s, offset );
	}
	
	// Convert address to most basic physical address
	// This routine is only present for backward compatibility
	// with SLED
	public void toPhysical() {
	    AddrSpace phys = base.getContain();
	    if ((phys != null)&&(base.getType()==spacetype.IPTR_SPACEBASE)) {
	        base = phys;
	    }
	}
	
	@Override
    public String toString() {
		return base.getName() + ":0x" + base.toString(offset);
	}
	public String toString(boolean showAddressSpace) {
		if (showAddressSpace) {
			return base.getName() + ":0x" + base.toString(offset);
		}
		return "0x" + base.toString(offset);
	}
	public int read( String s ) {
		MutableInt size = new MutableInt( 0 );
		offset = base.read( s, size );
		return size.get();
	}

	public AddrSpace getSpace() {
		return base;
	}

	public long getOffset() {
		return offset;
	}

	public char getShortcut() {
		return base.getShortCut();
	}

	@Override
	public boolean equals( Object obj ) {
		if (!(obj instanceof Address)) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		Address other = (Address) obj;
		return base == other.base && offset == other.offset;
	}

	public int compareTo( Address other ) {
		int result = base.compareTo( other.base );
		if (result != 0) {
			return result;
		}
		return AddressUtils.unsignedCompare( offset, other.offset );
	}

	public Address add( long off ) {
		return new Address( base, (offset + off) & base.getMask() );
	}

	public Address subtract( long off ) {
		return sub( off );
	}
	
	public Address sub( long off ) {
		return new Address( base, (offset - off) & base.getMask() );
	}

	public boolean isConstant() {
		return (base.getType() == spacetype.IPTR_CONSTANT);
	}

	public void saveXml( PrintStream s ) {
		s.append( "<addr" );
		if (base != null) {
			base.saveXmlAttributes( s, offset );
		}
		s.append( "/>" );
	}

	public void saveXml( PrintStream s, int size ) {
		s.append( "<addr" );
		if (base != null) {
			base.saveXmlAttributes( s, offset, size );
		}
		s.append( "/>" );
	}

	public static AddrSpace getSpaceFromConst( Address addr ) {
		return (AddrSpace) AddrSpaceToIdSymmetryMap.getSpace( addr.offset );
	}

	// Define pseudo-locations that have specific
	public Address( mach_extreme ex ) {
		// properties under comparion
		if (ex == mach_extreme.m_minimal) {
			base = AddrSpace.MIN_SPACE;
			offset = 0;
		} else {
			base = AddrSpace.MAX_SPACE;
			offset = -1;
		}
	}

	// Return true if (op2,sz2) is endian aligned and contained
	// in (this,sz)
	public boolean endianContain( int sz, Address op2, int sz2 ) {
		if (base != op2.base) {
			return false;
		}
		if (op2.offset < offset) {
			return false;
		}
		if (base.isBigEndian()) {
			long off1 = offset + (sz - 1);
			long off2 = op2.offset + (sz2 - 1);
			return (off1 == off2);
		}
		if (op2.offset != offset) {
			return false; // Not little endian aligned
		}
		if (sz2 > sz) {
			return false; // Not fully contained
		}
		return true;
	}

	public int overlap( int skip, Address op, int size ) {// Where does this+skip fall in op to op+size

		if (base != op.base) {
			return -1; // Must be in same address space to overlap
		}
		if (base.getType() == spacetype.IPTR_CONSTANT) {
			return -1; // Must not be constants
		}

		long dist = offset + skip - op.offset;
		dist &= base.getMask();

		if (dist >= size)
			return -1; // but must fall before op+size
		return (int) dist;
	}

	public static VarnodeData restoreXml( Element el, Translate trans ) {
		VarnodeData var = new VarnodeData();

		var.restoreXml( el, trans );
		return var;
		}

}
