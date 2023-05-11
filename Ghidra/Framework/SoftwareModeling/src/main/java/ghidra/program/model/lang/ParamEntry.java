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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.VarnodeData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class ParamEntry {
	private static final int FORCE_LEFT_JUSTIFY = 1;	// Big endian values are left justified within their slot
	private static final int REVERSE_STACK = 2;			// slots from stack section are allocated in reverse order
	private static final int SMALLSIZE_ZEXT = 4;		// Assume values that are below max size are zero extended
	private static final int SMALLSIZE_SEXT = 8;		// Assume values that are below max size are sign extended
	private static final int IS_BIG_ENDIAN = 16; // Interpret values in this container as big endian
	private static final int SMALLSIZE_INTTYPE = 32;	// Assume values that are below max size are extended based on integer type
	private static final int SMALLSIZE_FLOAT = 64;		// Assume values smaller than max -size- are floating-point extended to full size
	//private static final int EXTRACHECK_HIGH = 128;
	//private static final int EXTRACHECK_LOW = 256;
	private static final int IS_GROUPED = 512;			// The entry is grouped with other entries
	private static final int OVERLAPPING = 0x100;		// This overlaps an earlier entry

	public static final int TYPE_UNKNOWN = 8;			// Default type restriction
	public static final int TYPE_PTR = 2;				// pointer types
	public static final int TYPE_FLOAT = 3;				// floating point types

	private int flags;
	private int type;				// Restriction on DataType this entry must match
	private int[] groupSet;			// Group(s) this entry belongs to
	private AddressSpace spaceid;	// Space of this range
	private long addressbase;		// Start of the range
	private int size;				// size of the range
	private int minsize;			// minimum allowable match
	private int alignment;			// how much alignment,  0=use only once
	private int numslots;			// (Maximum) number of slots that can store separate parameters
	private Varnode[] joinrec;

	public ParamEntry(int grp) {	// For use with restoreXml
		groupSet = new int[1];
		groupSet[0] = grp;
	}

	public int getGroup() {
		return groupSet[0];
	}

	public int[] getAllGroups() {
		return groupSet;
	}

	public int getSize() {
		return size;
	}

	public int getMinSize() {
		return minsize;
	}

	public int getAlign() {
		return alignment;
	}

	public long getAddressBase() {
		return addressbase;
	}

	public int getType() {
		return type;
	}

	public boolean isExclusion() {
		return (alignment == 0);
	}

	public boolean isReverseStack() {
		return ((flags & REVERSE_STACK) != 0);
	}

	public boolean isGrouped() {
		return ((flags & IS_GROUPED) != 0);
	}

	public boolean isOverlap() {
		return ((flags & OVERLAPPING) != 0);
	}

	public boolean isBigEndian() {
		return ((flags & IS_BIG_ENDIAN) != 0);
	}

	public boolean isFloatExtended() {
		return ((flags & SMALLSIZE_FLOAT) != 0);
	}

	private boolean isLeftJustified() {
		return (((flags & IS_BIG_ENDIAN) == 0) || ((flags & FORCE_LEFT_JUSTIFY) != 0));
	}

	public AddressSpace getSpace() {
		return spaceid;
	}

	/**
	 * Collect pieces from the join list, in endian order, until the given size is covered.
	 * The last piece is trimmed to match the size exactly.  If the size is too big to be
	 * covered by this ParamEntry, null is returned.
	 * @param sz is the given size
	 * @return the collected array of Varnodes or null
	 */
	public Varnode[] getJoinPieces(int sz) {
		int num = 0;
		int first, replace;
		Varnode vn = null;
		Varnode[] res;
		if (isBigEndian()) {
			first = 0;
			while (sz > 0) {
				if (num >= joinrec.length) {
					return null;
				}
				vn = joinrec[num];
				if (vn.getSize() > sz) {
					num += 1;
					break;
				}
				sz -= vn.getSize();
				num += 1;
			}
			replace = num - 1;
		}
		else {
			while (sz > 0) {
				if (num >= joinrec.length) {
					return null;
				}
				vn = joinrec[joinrec.length - 1 - num];
				if (vn.getSize() > sz) {
					num += 1;
					break;
				}
				sz -= vn.getSize();
				num += 1;
			}
			first = joinrec.length - num;
			replace = first;
		}
		if (sz == 0 && num == joinrec.length) {
			return joinrec;
		}
		res = new Varnode[num];
		for (int i = 0; i < num; ++i) {
			res[i] = joinrec[first + i];
		}
		if (sz > 0) {
			res[replace] = new Varnode(vn.getAddress(), sz);
		}

		return res;
	}

	/**
	 * Is this ParamEntry, as a memory range, contained by the given memory range.
	 * @param addr is the starting address of the given memory range
	 * @param sz is the number of bytes in the given memory range
	 * @return true if this is contained
	 */
	public boolean containedBy(Address addr, int sz) {
		if (spaceid != addr.getAddressSpace()) {
			return false;
		}
		if (Long.compareUnsigned(addressbase, addr.getOffset()) < 0) {
			return false;
		}
		long rangeEnd = addr.getOffset() + sz - 1;
		long thisEnd = addressbase + size - 1;
		return (Long.compareUnsigned(thisEnd, rangeEnd) <= 0);
	}

	/**
	 * Does this ParamEntry intersect the given range in some way
	 * @param addr is the starting address of the given range
	 * @param sz is the number of bytes in the given range
	 * @return true if there is an intersection
	 */
	public boolean intersects(Address addr, int sz) {
		long rangeend;
		if (joinrec != null) {
			rangeend = addr.getOffset() + sz - 1;
			for (Varnode vn : joinrec) {
				if (addr.getAddressSpace().getSpaceID() != vn.getSpace()) {
					continue;
				}
				long vnend = vn.getOffset() + vn.getSize() - 1;
				if (Long.compareUnsigned(addr.getOffset(), vn.getOffset()) < 0 &&
					Long.compareUnsigned(rangeend, vnend) < 0) {
					continue;
				}
				if (Long.compareUnsigned(addr.getOffset(), vn.getOffset()) > 0 &&
					Long.compareUnsigned(rangeend, vnend) > 0) {
					continue;
				}
				return true;
			}
		}
		if (spaceid.getSpaceID() != addr.getAddressSpace().getSpaceID()) {
			return false;
		}
		rangeend = addr.getOffset() + sz - 1;
		long thisend = addressbase + size - 1;
		if (Long.compareUnsigned(addr.getOffset(), addressbase) < 0 &&
			Long.compareUnsigned(rangeend, thisend) < 0) {
			return false;
		}
		if (Long.compareUnsigned(addr.getOffset(), addressbase) > 0 &&
			Long.compareUnsigned(rangeend, thisend) > 0) {
			return false;
		}
		return true;
	}

	public int justifiedContain(Address addr, int sz) {
		if (joinrec != null) {
			int res = 0;
			for (int i = joinrec.length - 1; i >= 0; --i) {	// Move from least significant to most
				Varnode vdata = joinrec[i];
				int cur = justifiedContainAddress(vdata.getAddress().getAddressSpace(),
					vdata.getOffset(), vdata.getSize(), addr.getAddressSpace(), addr.getOffset(),
					sz, false, ((flags & IS_BIG_ENDIAN) != 0));
				if (cur < 0) {
					res += vdata.getSize();			// We skipped this many less significant bytes
				}
				else {
					return res + cur;
				}
			}
			return -1;		// Not contained at all
		}
		if (alignment == 0) {		// Ordinary endian containment
			return justifiedContainAddress(spaceid, addressbase, size, addr.getAddressSpace(),
				addr.getOffset(), sz, ((flags & FORCE_LEFT_JUSTIFY) != 0),
				((flags & IS_BIG_ENDIAN) != 0));
		}
		if (spaceid != addr.getAddressSpace()) {
			return -1;
		}
		long startaddr = addr.getOffset();
		if (Long.compareUnsigned(startaddr, addressbase) < 0) {
			return -1;
		}
		long endaddr = startaddr + sz - 1;
		if (Long.compareUnsigned(endaddr, startaddr) < 0) {
			return -1;		// Don't allow wrap around
		}
		if (Long.compareUnsigned(addressbase + size - 1, endaddr) < 0) {
			return -1;
		}
		startaddr -= addressbase;
		endaddr -= addressbase;
		if (!isLeftJustified()) {		// For right justified (big endian), endaddr must be aligned
			int res = (int) ((endaddr + 1) % alignment);
			if (res == 0) {
				return 0;
			}
			return (alignment - res);
		}
		return (int) (startaddr % alignment);
	}

	/**
	 * Does this ParamEntry contain another entry (as a subpiece)
	 * @param otherEntry is the other entry
	 * @return true if this contains the other entry
	 */
	public boolean contains(ParamEntry otherEntry) {
		if (otherEntry.joinrec != null) {
			return false;	// Assume a join entry cannot be contained
		}
		if (joinrec == null) {
			Address addr = spaceid.getAddress(addressbase);
			return otherEntry.containedBy(addr, size);
		}
		for (Varnode vn : joinrec) {
			if (otherEntry.containedBy(vn.getAddress(), vn.getSize())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Assuming the address is contained in this entry and we -skip- to a certain byte
	 * return the slot associated with that byte
	 * @param addr  is the address to check (which MUST be contained)
	 * @param skip  is the number of bytes to skip
	 * @return the slot index
	 */
	public int getSlot(Address addr, int skip) {
		int res = groupSet[0];
		if (alignment != 0) {
			long diff = addr.getOffset() + skip - addressbase;
			int baseslot = (int) diff / alignment;
			if (isReverseStack()) {
				res += (numslots - 1) - baseslot;
			}
			else {
				res += baseslot;
			}
		}
		else if (skip != 0) {
			res = groupSet[groupSet.length - 1];
		}
		return res;
	}

	/**
	 * Return the storage address assigned when allocating something of size -sz- assuming -slotnum- slots
	 * have already been assigned.  Set res.space to null if the -sz- is too small or if
	 * there are not enough slots left
	 * @param slotnum	number of slots already assigned
	 * @param sz        number of bytes to being assigned
	 * @param res       the final storage address
	 * @return          slotnum plus the number of slots used
	 */
	public int getAddrBySlot(int slotnum, int sz, VarnodeData res) {
		res.space = null;		// Start with an invalid result
		int spaceused;
		if (sz < minsize) {
			return slotnum;
		}
		if (alignment == 0) {		// If not an aligned entry (allowing multiple slots)
			if (slotnum != 0) {
				return slotnum;	// Can only allocate slot 0
			}
			if (sz > size) {
				return slotnum;		// Check on maximum size
			}
			res.space = spaceid;
			res.offset = addressbase;			// Get base address of the slot
			spaceused = size;
			if ((flags & SMALLSIZE_FLOAT) != 0) {
				return slotnum;
			}
		}
		else {
			int slotsused = sz / alignment;	// How many slots does a -sz- byte object need
			if ((sz % alignment) != 0) {
				slotsused += 1;
			}
			if (slotnum + slotsused > numslots) {
				return slotnum;
			}
			spaceused = slotsused * alignment;
			int index;
			if (isReverseStack()) {
				index = numslots;
				index -= slotnum;
				index -= slotsused;
			}
			else {
				index = slotnum;
			}
			res.space = spaceid;
			res.offset = addressbase + index * alignment;
			slotnum += slotsused;		// Inform caller of number of slots used
		}
		if (!isLeftJustified()) {
			res.offset += (spaceused - sz);
		}
		return slotnum;
	}

	/**
	 * Find the ParamEntry in the list whose storage matches the given Varnode
	 * @param curList is the list of ParamEntry
	 * @param varnode is the given Varnode
	 * @return the matching entry or null
	 */
	private static ParamEntry findEntryByStorage(List<ParamEntry> curList, Varnode varnode) {
		ListIterator<ParamEntry> iter = curList.listIterator(curList.size());
		while (iter.hasPrevious()) {
			ParamEntry entry = iter.previous();
			if (entry.spaceid.getSpaceID() == varnode.getSpace() &&
				entry.addressbase == varnode.getOffset() && entry.size == varnode.getSize()) {
				return entry;
			}
		}
		return null;
	}

	/**
	 * Adjust the group and groupsize based on the ParamEntrys being overlapped
	 * @param curList is the current list of ParamEntry
	 * @throws XmlParseException if no overlap is found
	 */
	private void resolveJoin(List<ParamEntry> curList) throws XmlParseException {
		if (joinrec == null) {
			return;
		}
		ArrayList<Integer> newGroupSet = new ArrayList<>();
		for (Varnode piece : joinrec) {
			ParamEntry entry = findEntryByStorage(curList, piece);
			if (entry != null) {
				for (int group : entry.groupSet) {
					newGroupSet.add(group);
				}
			}
		}
		if (newGroupSet.isEmpty()) {
			throw new XmlParseException("<pentry> join must overlap at least one previous entry");
		}
		newGroupSet.sort(null);
		groupSet = new int[newGroupSet.size()];
		for (int i = 0; i < groupSet.length; ++i) {
			groupSet[i] = newGroupSet.get(i);
		}
		flags |= OVERLAPPING;
	}

	/**
	 * Search for overlap with any previous ParamEntry.  Reassign group and groupsize to
	 * reflect this overlap.
	 * @param curList is the list of previous ParamEntry
	 * @throws XmlParseException if overlaps do not take the correct form
	 */
	private void resolveOverlap(List<ParamEntry> curList) throws XmlParseException {
		if (joinrec != null) {
			return;
		}
		ArrayList<Integer> newGroupSet = new ArrayList<>();
		Address addr = spaceid.getAddress(addressbase);
		for (ParamEntry entry : curList) {
			if (entry == this) {
				continue;
			}
			if (!entry.intersects(addr, size)) {
				continue;
			}
			if (contains(entry)) {
				if (entry.isOverlap()) {
					continue;		// Don't count resources (already counted overlapped pentry)
				}
				for (int group : entry.groupSet) {
					newGroupSet.add(group);
				}
			}
			else {
				throw new XmlParseException("Illegal overlap of <pentry> in compiler spec");
			}
		}
		if (newGroupSet.isEmpty()) {
			return;				// No overlaps
		}
		newGroupSet.sort(null);
		groupSet = new int[newGroupSet.size()];
		for (int i = 0; i < groupSet.length; ++i) {
			groupSet[i] = newGroupSet.get(i);
		}
		flags |= OVERLAPPING;
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_PENTRY);
		encoder.writeSignedInteger(ATTRIB_MINSIZE, minsize);
		encoder.writeSignedInteger(ATTRIB_MAXSIZE, size);
		if (alignment != 0) {
			encoder.writeSignedInteger(ATTRIB_ALIGN, alignment);
		}
		if (type == TYPE_FLOAT || type == TYPE_PTR) {
			String tok = (type == TYPE_FLOAT) ? "float" : "ptr";
			encoder.writeString(ATTRIB_METATYPE, tok);
		}
		String extString = null;
		if ((flags & SMALLSIZE_SEXT) != 0) {
			extString = "sign";
		}
		else if ((flags & SMALLSIZE_ZEXT) != 0) {
			extString = "zero";
		}
		else if ((flags & SMALLSIZE_INTTYPE) != 0) {
			extString = "inttype";
		}
		else if ((flags & SMALLSIZE_FLOAT) != 0) {
			extString = "float";
		}
		if (extString != null) {
			encoder.writeString(ATTRIB_EXTENSION, extString);
		}
		AddressXML addressSize;
		if (joinrec == null) {
			// Treat as unsized address with no size
			addressSize = new AddressXML(spaceid, addressbase, 0);
		}
		else {
			addressSize = new AddressXML(spaceid, addressbase, size, joinrec);
		}
		addressSize.encode(encoder);
		encoder.closeElement(ELEM_PENTRY);
	}

	public void restoreXml(XmlPullParser parser, CompilerSpec cspec, List<ParamEntry> curList,
			boolean grouped) throws XmlParseException {
		flags = 0;
		type = TYPE_UNKNOWN;
		size = minsize = -1;		// Must be filled in
		alignment = 0;				// default
		numslots = 1;

		XmlElement el = parser.start("pentry");
		Iterator<Entry<String, String>> iter = el.getAttributes().entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> entry = iter.next();
			String name = entry.getKey();
			if (name.equals("minsize")) {
				minsize = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("size")) {	// old style
				alignment = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("align")) {
				alignment = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("maxsize")) {
				size = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("metatype")) {		// Not implemented at the moment
				String meta = entry.getValue();
				// TODO:  Currently only supporting "float", "ptr", and "unknown" metatypes
				if ((meta != null)) {
					if (meta.equals("float")) {
						type = TYPE_FLOAT;
					}
					else if (meta.equals("ptr")) {
						type = TYPE_PTR;
					}
				}
			}
			else if (name.equals("extension")) {
				flags &= ~(SMALLSIZE_ZEXT | SMALLSIZE_SEXT | SMALLSIZE_INTTYPE | SMALLSIZE_FLOAT);
				String value = entry.getValue();
				if (value.equals("sign")) {
					flags |= SMALLSIZE_SEXT;
				}
				else if (value.equals("zero")) {
					flags |= SMALLSIZE_ZEXT;
				}
				else if (value.equals("inttype")) {
					flags |= SMALLSIZE_INTTYPE;
				}
				else if (value.equals("float")) {
					flags |= SMALLSIZE_FLOAT;
				}
				else if (!value.equals("none")) {
					throw new XmlParseException("Bad extension attribute: " + value);
				}
			}
			else {
				throw new XmlParseException("Unknown paramentry attribute: " + name);
			}
		}
		if (minsize < 1 || size < minsize) {
			throw new XmlParseException(
				"paramentry size not specified properly: minsize=" + minsize + " maxsize=" + size);
		}
		if (alignment == size) {
			alignment = 0;
		}

		XmlElement subel = parser.start();
		AddressXML addressSized = AddressXML.restoreXml(subel, cspec);
		parser.end(subel);
		if (addressSized.getSize() != 0 && size > addressSized.getSize()) {
			throw new XmlParseException("<pentry> maxsize is bigger than memory range");
		}
		addressSized.getFirstAddress();		// Fail fast. Throws AddressOutOfBounds exception if offset is invalid
		spaceid = addressSized.getAddressSpace();
		addressbase = addressSized.getOffset();
		joinrec = addressSized.getJoinRecord();

		boolean isbigendian = cspec.getLanguage().isBigEndian();
		if (isbigendian) {
			flags |= IS_BIG_ENDIAN;
		}
		if (alignment != 0) {
//			if ((addressbase % alignment) != 0)
//				throw new XmlParseException("Stack <pentry> address must match alignment");
			numslots = size / alignment;
		}
		if (spaceid.isStackSpace() && (!cspec.isStackRightJustified()) && isbigendian) {
			flags |= FORCE_LEFT_JUSTIFY;
		}
		if (!cspec.stackGrowsNegative()) {
			flags |= REVERSE_STACK;
			if (alignment != 0) {
				if ((size % alignment) != 0) {
					throw new XmlParseException(
						"For positive stack growth, <pentry> size must match alignment");
				}
			}
		}
		if (grouped) {
			flags |= IS_GROUPED;
		}
		resolveJoin(curList);
		resolveOverlap(curList);
		parser.end(el);
	}

	/**
	 * Determine if this ParamEntry is equivalent to another instance
	 * @param obj is the other instance
	 * @return true if they are equivalent
	 */
	public boolean isEquivalent(ParamEntry obj) {
		if (!spaceid.equals(obj.spaceid) || addressbase != obj.addressbase) {
			return false;
		}
		if (size != obj.size || minsize != obj.minsize || alignment != obj.alignment) {
			return false;
		}
		if (type != obj.type || flags != obj.flags) {
			return false;
		}
		if (numslots != obj.numslots) {
			return false;
		}
		if (groupSet.length != obj.groupSet.length) {
			return false;
		}
		for (int i = 0; i < groupSet.length; ++i) {
			if (groupSet[i] != obj.groupSet[i]) {
				return false;
			}
		}
		if (!SystemUtilities.isArrayEqual(joinrec, obj.joinrec)) {
			return false;
		}
		return true;
	}

	/**
	 * Return -1 if (op2,sz2) is not properly contained in (op1,sz1)
	 * If it is contained, return the endian aware offset of (op2,sz2)
	 * I.e. if the least significant byte of the op2 range falls on the least significant
	 * byte of the op1 range, return 0.  If it intersects the second least significant, return 1, etc.
	 * @param spc1  the first address space
	 * @param offset1 the first offset
	 * @param sz1   size of first space
	 * @param spc2  the second address space
	 * @param offset2 is the second offset
	 * @param sz2   size of second space
	 * @param forceleft  is true if containment is forced to be on the left even for big endian
	 * @param isBigEndian true if big endian
	 * @return the endian aware offset or -1
	 */
	public static int justifiedContainAddress(AddressSpace spc1, long offset1, int sz1,
			AddressSpace spc2, long offset2, int sz2, boolean forceleft, boolean isBigEndian) {
		if (spc1 != spc2) {
			return -1;
		}
		if (Long.compareUnsigned(offset2, offset1) < 0) {
			return -1;
		}
		long off1 = offset1 + (sz1 - 1);
		long off2 = offset2 + (sz2 - 1);
		if (Long.compareUnsigned(off1, off2) < 0) {
			return -1;
		}
		if (isBigEndian && (!forceleft)) {
			return (int) (off1 - off2);
		}
		return (int) (offset2 - offset1);
	}

	public static int getMetatype(DataType tp) {
		// TODO: A complete metatype implementation
		if (tp instanceof TypeDef) {
			tp = ((TypeDef) tp).getBaseDataType();
		}
		if (tp instanceof AbstractFloatDataType) {
			return TYPE_FLOAT;
		}
		if (tp instanceof Pointer) {
			return TYPE_PTR;
		}
		return TYPE_UNKNOWN;
	}

	/**
	 * ParamEntry within a group must be distinguishable by size or by type
	 * @param entry1 is the first being compared
	 * @param entry2 is the second being compared
	 * @throws XmlParseException if the pair is not distinguishable
	 */
	public static void orderWithinGroup(ParamEntry entry1, ParamEntry entry2)
			throws XmlParseException {
		if (entry2.minsize > entry1.size || entry1.minsize > entry2.size) {
			return;
		}
		if (entry1.type != entry2.type) {
			if (entry1.type == TYPE_UNKNOWN) {
				throw new XmlParseException(
					"<pentry> tags with a specific type must come before the general type");
			}
			return;
		}
		throw new XmlParseException(
			"<pentry> tags within a group must be distinguished by size or type");
	}
}
