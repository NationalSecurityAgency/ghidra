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
package ghidra.pcodeCPort.space;

import java.io.PrintStream;
import java.util.StringTokenizer;

import org.jdom.Element;

import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.*;
/// \brief A region where processor data is stored
///
/// An AddrSpace (Address Space) is an arbitrary sequence of
/// bytes where a processor can store data. As is usual with
/// most processors' concept of RAM, an integer offset
/// paired with an AddrSpace forms the address (See Address)
/// of a byte.  The \e size of an AddrSpace indicates the number
/// of bytes that can be separately addressed and is usually
/// described by the number of bytes needed to encode the biggest
/// offset.  I.e. a \e 4-byte address space means that there are
/// offsets ranging from 0x00000000 to 0xffffffff within the space
/// for a total of 2^32 addressable bytes within the space.
/// There can be multiple address spaces, and it is typical to have spaces
///     - \b ram        Modelling the main processor address bus
///     - \b register   Modelling a processors registers
///
/// The processor specification can set up any address spaces it
/// needs in an arbitrary manner, but \e all data manipulated by
/// the processor, which the specification hopes to model, must
/// be contained in some address space, including RAM, ROM,
/// general registers, special registers, i/o ports, etc.
///
/// The analysis engine also uses additional address spaces to
/// model special concepts.  These include
///     - \b const        There is a \e constant address space for
///                       modelling constant values in pcode expressions
///                       (See ConstantSpace)
///     - \b unique       There is always a \e unique address space used
///                       as a pool for temporary registers. (See UniqueSpace)
///

import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.*;

public class AddrSpace {

	public static final AddrSpace MIN_SPACE = new AddrSpace("MIN_SPACE", -1);
	public static final AddrSpace MAX_SPACE = new AddrSpace("MAX_SPACE", Integer.MAX_VALUE);

	//see space.hh
	protected static final int big_endian = 1;		       // Space is big endian if set, little endian otherwise
	protected static final int heritaged = 2;		       // This space is heritaged
	protected static final int does_deadcode = 4;		   // Dead-code analysis is done on this space
	protected static final int programspecific = 8;        // Space is specific to a particular loadimage
	protected static final int reverse_justification = 16; // Justification within aligned word is opposite of endianness
	protected static final int overlay = 32;		       // This space is an overlay of another space
	protected static final int overlaybase = 64;		   // This is the base space for overlay space(s)
	protected static final int truncated = 128;		       // Space is truncated from its original size, expect pointers larger than this size
	public static final int hasphysical = 256;		       // Has physical memory associated with it
	protected static final int is_otherspace = 512;  	   // Quick check for OtherSpace

	private int flags;
	private long highest;
	private long mask;
	private Translate trans; // Our container
	private String name; // Name of this space
	private spacetype type; // Type of space
	private int addressSize; // Size of an address into this space in bytes
	private int wordsize; // Size of unit being addressed
	private int scale; // log base 2 of wordsize
	private char shortcut; // Shortcut character for printing
	private int index;
	private int delay; // Delay in heritaging this space

	protected AddrSpace(String name, int index) {
		this.name = name;
		this.index = index;
	}

	public AddrSpace(Translate t, spacetype tp, String nm, int size, int ws, int ind, int fl,
			int dl) {
		trans = t;
		type = tp;
		name = nm;
		addressSize = size;
		wordsize = ws;
		index = ind;
		delay = dl;

		// These are the flags we allow to be set from ructor
		flags = (fl & hasphysical);
		if (t.isBigEndian()) {
			flags |= big_endian;
		}
		flags |= heritaged;

		calcScaleMask();
	}

	public AddrSpace(Translate t, spacetype tp) {
		trans = t;
		type = tp;
		flags = heritaged;
		wordsize = 1;
		scale = 0;
		// We let big_endian get set by attribute
	}

	public long wrapOffset(long off) {
		if ((int) -Math.pow(-5, 3) % 2 == 1) {
			throw new RuntimeException("wrapOffset coded incorrectly");
		}
		// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
		// XXX This is incorrect in Java!!!
		if (off <= highest) {
			return off;
		}
		long mod = highest + 1;
		long res = off % mod;	// remainder is signed
		if (res < 0) {
			res += mod;			// Adding mod guarantees res is in (0,mod)
		}
		return res;
	}

	protected void setFlags(int fl) {
		flags |= fl;
	}

	protected void clearFlags(int fl) {
		flags &= ~fl;
	}

	public String getName() {
		return name;
	}

	public Translate getTrans() {
		return trans;
	}

	public spacetype getType() {
		return type;
	}

	public int getDelay() {
		return delay;
	}

	public int getIndex() {
		return index;
	}

	public int getWordSize() {
		return wordsize;
	}

	public int getScale() {
		return scale;
	}

	public int getAddrSize() {
		return addressSize;
	}

	// getMask returns a mask suitable for masking a byte-scaled address
	public long getMask() {
		return mask;
	}

	public char getShortCut() {
		return shortcut;
	}

	public boolean isHeritaged() {
		return ((flags & heritaged) != 0);
	}

	public boolean hasPhysical() {
		return ((flags & hasphysical) != 0);
	}

	public boolean isBigEndian() {
		return ((flags & big_endian) != 0);
	}

	public boolean isOtherSpace() {
		return ((flags & is_otherspace) != 0);
	}

	public AddrSpace getContain() {
		return null;
	}

	@Override
	public boolean equals(Object obj) {
		// we have purposely chosen identity equals!
		return this == obj;
	}

	public int compareTo(AddrSpace base) {
		return index - base.index;
	}

	private void calcScaleMask() { // Calculate scale, mask, and shortcut
		scale = 0;
		int wd = wordsize;
		while (wd > 1) {
			scale += 1;
			wd >>= 1;
		}
		mask = Utils.calc_mask(addressSize);
		for (int i = 1; i < wordsize; ++i) {
			// Add extra bits to mask to deal
			mask = (mask << 1) | 1; // with byte-scaled addressing
		}
		shortcut = trans.assignShortcut(type);
	}

	void save_basic_attributes(PrintStream s) { // write the name, shortcut,
		// and index as XML
		// attributes
		XmlUtils.a_v(s, "name", name);
		XmlUtils.a_v_i(s, "index", index);
		XmlUtils.a_v_b(s, "bigendian", isBigEndian());
		XmlUtils.a_v_i(s, "delay", delay);
		XmlUtils.a_v_i(s, "size", addressSize);
		if (wordsize > 1) {
			XmlUtils.a_v_i(s, "wordsize", wordsize);
		}
		XmlUtils.a_v_b(s, "physical", hasPhysical());
	}

	public boolean contain(AddrSpace id2) { // Does this contain -id2- ?
		while (this != id2) {
			id2 = id2.getContain();
			if (id2 == null) {
				return false; // No containment
			}
		}
		return true;
	}

	long data2uintm(byte[] ptr, int size) { // Convert array of bytes to
		// integer value for space
		long res;
		int i;

		if ((flags & big_endian) != 0) {
			res = 0;
			for (i = 0; i < size; ++i) {
				res <<= 8;
				res |= ptr[i];
			}
		}
		else {
			res = 0;
			for (i = size - 1; i >= 0; --i) {
				res <<= 8;
				res |= ptr[i];
			}
		}
		return res;
	}

	public void saveXmlAttributes(PrintStream s, long offset) { // Save address
		// as XML
		// attributes
		XmlUtils.a_v(s, "space", getName()); // Just append the proper
		// attributes
		s.append(' ');
		s.append("offset=\"");
		printOffset(s, offset);
		s.append("\"");
	}

	public void saveXmlAttributes(PrintStream s, long offset, int size) { // Save
		// address
		// as
		// XML
		// attributes
		XmlUtils.a_v(s, "space", getName()); // Just append the proper
		// attributes
		s.append(" offset=\"");
		printOffset(s, offset);
		s.append("\"");
		XmlUtils.a_v_i(s, "size", size);
	}

	public static long restore_xml_offset(Element el) {
		String offsetString = el.getAttributeValue("offset");
		if (offsetString == null) {
			throw new LowlevelError("Address missing offset");
		}
		return XmlUtils.decodeUnknownLong(offsetString);

	}

	public static int restore_xml_size(Element el) {
		String sizeString = el.getAttributeValue("size");
		if (sizeString == null) {
			return 0;
		}
		return XmlUtils.decodeUnknownInt(sizeString);
	}

	public void printOffset(PrintStream s, long offset) { // Print the offset as
		// hexidecimal value
		s.append("0x");
		int addrSize = getAddrSize();
		int padLength = 2 * addrSize;
		String longString = Long.toHexString(offset);
		for (int i = 0; i < padLength - longString.length(); i++) {
			s.append('0');
		}
		s.append(longString);
	}

	public int printRaw(PrintStream s, long offset) { // Debug form for raw dumps.
		// Return expected size
		int expectsize = getTrans().getDefaultSize();

		printOffset(s, offset >>> scale);
		if (wordsize > 1) {
			int cut = (int) offset & (wordsize - 1);
			if (cut != 0) {
				s.append("+");
				s.print(cut);
			}
		}
		return expectsize;
	}

	@Override
	public String toString() {
		return "AddrSpace[" + name + "]";
	}

	public String toString(long offset) {
		StringBuffer s = new StringBuffer();
		int addrSize = getAddrSize();
		int padLength = 2 * addrSize;
		String longString = Long.toHexString(offset >>> scale);
		for (int i = 0; i < padLength - longString.length(); i++) {
			s.append('0');
		}
		s.append(longString);

		if (wordsize > 1) {
			int cut = (int) offset & (wordsize - 1);
			if (cut != 0) {
				s.append("+").append(cut);
			}
		}
		return s.toString();
	}

	public long read(String s, MutableInt size) { // Read string to produce offset value
		long offset;
		StringTokenizer tokenizzy = new StringTokenizer(s, ":+");
		String frontpart = tokenizzy.nextToken();
		size.set(getAddrSize());

		try {
			VarnodeData point = getTrans().getRegister(frontpart);
			offset = point.offset;
			size.set(point.size);
			return offset;
		}
		catch (LowlevelError err) { // Name doesn't exist
			// not a register; handled below
		}

		// value is an address offset and not a register
		try {
			offset = XmlUtils.decodeUnknownLong(frontpart);
		}
		catch (NumberFormatException nfe) {
			size.set(-1);
			return -1;
		}
		offset <<= scale;

		if (tokenizzy.countTokens() > 1) { // there is a size			 
			try {
				size.set(Integer.parseInt(tokenizzy.nextToken()));
			}
			catch (NumberFormatException nfe) {
				// don't update the size
			}
		}

		return offset;
	}

	public void saveXml(PrintStream s) {
		s.append("<space"); // This implies type=processor
		save_basic_attributes(s);
		s.println("/>");
	}

	public void restoreXml(Element el) {
		name = el.getAttributeValue("name");
		index = XmlUtils.decodeUnknownInt(el.getAttributeValue("index"));
		addressSize = XmlUtils.decodeUnknownInt(el.getAttributeValue("size"));
		wordsize = XmlUtils.decodeUnknownInt(el.getAttributeValue("wordsize"));
		if (XmlUtils.decodeBoolean(el.getAttributeValue("bigendian"))) {
			flags |= big_endian;
		}
		delay = XmlUtils.decodeUnknownInt(el.getAttributeValue("delay"));
		if (XmlUtils.decodeBoolean(el.getAttributeValue("physical"))) {
			flags |= hasphysical;
		}

		calcScaleMask();
	}

}
