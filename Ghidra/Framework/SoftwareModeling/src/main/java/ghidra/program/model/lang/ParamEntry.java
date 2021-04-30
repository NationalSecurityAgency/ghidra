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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.VarnodeData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.Varnode;
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

	public static final int TYPE_UNKNOWN = 8;			// Default type restriction
	public static final int TYPE_PTR = 2;				// pointer types
	public static final int TYPE_FLOAT = 3;				// floating point types
	
	private int flags;
	private int type;				// Restriction on DataType this entry must match
	private int group;				// Group of (mutually exclusive) entries that this entry belongs to
	private int groupsize;			// The number of consecutive groups taken by the entry
	private AddressSpace spaceid;	// Space of this range
	private long addressbase;		// Start of the range
	private int size;				// size of the range
	private int minsize;			// minimum allowable match
	private int alignment;			// how much alignment,  0=use only once
	private int numslots;			// (Maximum) number of slots that can store separate parameters
	private Varnode[] joinrec;
	
	public ParamEntry(int grp) {	// For use with restoreXml
		group = grp;
	}
	
	public int getGroup() {
		return group;
	}
	
	public int getGroupSize() {
		return groupsize;
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
		return (alignment==0);
	}

	public boolean isReverseStack() {
		return ((flags & REVERSE_STACK)!=0);
	}
	
	public boolean isBigEndian() {
		return ((flags & IS_BIG_ENDIAN)!=0);
	}

	public boolean isFloatExtended() {
		return ((flags & SMALLSIZE_FLOAT)!=0);
	}
	
	private boolean isLeftJustified() {
		return (((flags & IS_BIG_ENDIAN)==0) || ((flags & FORCE_LEFT_JUSTIFY)!=0));
	}
	
	public AddressSpace getSpace() {
		return spaceid;
	}
	
	public Varnode[] getJoinRecord() {
		return joinrec;
	}
	
	public boolean contains(ParamEntry op2) {
		if ((type != TYPE_UNKNOWN)&&(op2.type != type)) {
			return false;
		}
		if (spaceid != op2.spaceid) {
			return false;
		}
		if (unsignedCompare(op2.addressbase,addressbase)) {
			return false;
		}
		long op2end = op2.addressbase + op2.size -1;
		long end = addressbase+size-1;
		if (unsignedCompare(end,op2end)) {
			return false;
		}
		if (alignment != op2.alignment) {
			return false;
		} 
		return true;
	}
	
	public int justifiedContain(Address addr,int sz) {
		if (joinrec != null) {
			int res = 0;
			for(int i=joinrec.length-1;i>=0;--i) {	// Move from least significant to most
				Varnode vdata = joinrec[i];
				int cur = justifiedContainAddress(vdata.getAddress().getAddressSpace(),vdata.getOffset(),vdata.getSize(),
									addr.getAddressSpace(),addr.getOffset(),sz,false,((flags & IS_BIG_ENDIAN)!=0));
				if (cur<0) {
					res += vdata.getSize();			// We skipped this many less significant bytes
				}
				else {
					return res + cur;
				}
			}
			return -1;		// Not contained at all
		}
		if (alignment == 0) {		// Ordinary endian containment
			return justifiedContainAddress(spaceid,addressbase,size,
					                       addr.getAddressSpace(),addr.getOffset(),sz,
					                       ((flags & FORCE_LEFT_JUSTIFY)!=0),((flags & IS_BIG_ENDIAN)!=0));
		}
		if (spaceid != addr.getAddressSpace()) {
			return -1;
		}
		long startaddr = addr.getOffset();
		if (unsignedCompare(startaddr, addressbase)) {
			return -1;
		}
		long endaddr = startaddr + sz - 1;
		if (unsignedCompare(endaddr, startaddr)) {
			return -1;		// Don't allow wrap around
		}
		if (unsignedCompare(addressbase + size-1,endaddr)) {
			return -1;
		}
		startaddr -= addressbase;
		endaddr -= addressbase;
		if (!isLeftJustified()) {		// For right justified (big endian), endaddr must be aligned
			int res = (int)((endaddr+1) % alignment);
			if (res==0) {
				return 0;
			}
			return (alignment-res);
		}
		return (int) (startaddr % alignment);
	}
	
	/**
	 * Assuming the address is contained in this entry and we -skip- to a certain byte
	 * return the slot associated with that byte
	 * @param addr  is the address to check (which MUST be contained)
	 * @param skip  is the number of bytes to skip
	 * @return the slot index
	 */
	public int getSlot(Address addr,int skip) {
		int res = group;
		if (alignment != 0) {
			long diff = addr.getOffset() + skip - addressbase;
			int baseslot = (int)diff / alignment;
			if (isReverseStack()) {
				res += (numslots-1) - baseslot;
			}
			else {
				res += baseslot;
			}
		}
		else if (skip != 0) {
			res += (groupsize -1);
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
	public int getAddrBySlot(int slotnum,int sz,VarnodeData res) {
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
			if ((flags & SMALLSIZE_FLOAT)!=0) {
				return slotnum;
			}
		}
		else {
			int slotsused = sz / alignment;	// How many slots does a -sz- byte object need
			if ( (sz %alignment) != 0) {
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
	 * Create a join record from an XML tag. Pieces of the join are encoded as a sequence of tag attributes
	 * @param el
	 * @throws XmlParseException 
	 */
	private void readJoinXML(XmlElement el,CompilerSpec cspec) throws XmlParseException {
		ArrayList<Varnode> pieces = new ArrayList<Varnode>();
		int sizesum = 0;
		int pos = 0;
		for(;;) {
			String attrName = "piece" + Integer.toString(pos+1);
			String attrVal = el.getAttribute(attrName);
			if (attrVal == null) {
				break;
			}
			int offpos = attrVal.indexOf(':');
			Varnode newvn;
			if (offpos == -1) {
				Register register = cspec.getLanguage().getRegister(attrVal);
				if (register == null) {
					throw new XmlParseException("Unknown pentry register: " + attrVal);
				}
				newvn = new Varnode(register.getAddress(),register.getBitLength()/8);
			}
			else {
				int szpos = attrVal.indexOf(':', offpos+1);
				if (szpos == -1) {
					throw new XmlParseException("join address piece attribute is malformed");
				}
				String spcname = attrVal.substring(0, offpos);
				AddressSpace spc = cspec.getAddressSpace(spcname);
				long offset = SpecXmlUtils.decodeLong(attrVal.substring(offpos+1,szpos));
				long sz = SpecXmlUtils.decodeLong(attrVal.substring(szpos+1));
				newvn = new Varnode(spc.getAddress(offset),(int)sz);
			}
			pieces.add(newvn);
			sizesum += newvn.getSize();
			pos += 1;
		}
		addressbase = 0;		// This should be the offset assigned by the join space
		size = sizesum;
		joinrec = new Varnode[ pieces.size() ];
		pieces.toArray(joinrec);
	}

	private void readXMLAddress(XmlPullParser parser, CompilerSpec cspec, int size)
			throws XmlParseException {
		XmlElement subel = parser.start();
		if (subel.getName().equals("register")) {
			String regName = subel.getAttribute("name");
			if (regName == null) {
				throw new XmlParseException("Missing pentry register name");
			}
			Register register = cspec.getLanguage().getRegister(regName);
			if (register == null) {
				throw new XmlParseException("Unknown pentry register: " + regName);
			}
			int regSize = register.getMinimumByteSize();
			if (size > regSize) {
				throw new XmlParseException(
					"Invalid pentry size specified for " + regSize + "-byte register: " + regName);
			}
			spaceid = register.getAddressSpace();
			addressbase = register.getOffset();
		}
		else {
			spaceid = cspec.getAddressSpace(subel.getAttribute("space"));
			if (spaceid.getType() == AddressSpace.TYPE_JOIN) {
				readJoinXML(subel,cspec);
			}
			else {
				addressbase = SpecXmlUtils.decodeLong(subel.getAttribute("offset"));
			}
		}
		parser.end(subel);
		
	}
	
	public void restoreXml(XmlPullParser parser,CompilerSpec cspec,boolean normalstack) throws XmlParseException {
		flags = 0;
		type = TYPE_UNKNOWN;
		size = minsize = -1;		// Must be filled in
		alignment = 0;				// default
		numslots = 1;
		groupsize = 1;				// default
		
		XmlElement el = parser.start("pentry");
		Iterator<Entry<String, String>> iter = el.getAttributes().entrySet().iterator();
		while(iter.hasNext()) {
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
			else if (name.equals("group")) {
				group = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("groupsize")) {
				groupsize = SpecXmlUtils.decodeInt(entry.getValue());
			}
			else if (name.equals("extension")) {
				flags &= ~(SMALLSIZE_ZEXT | SMALLSIZE_SEXT | SMALLSIZE_INTTYPE);
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
					throw new XmlParseException("Bad extension attribute: "+value);
				}
			}
			else {
				throw new XmlParseException("Unknown paramentry attribute: "+name);
			}
		}
		if (minsize < 1 || size < minsize) {
			throw new XmlParseException(
				"paramentry size not specified properly: minsize=" + minsize + " maxsize=" + size);
		}
		if (alignment == size) {
			alignment = 0;
		}
		
		readXMLAddress(parser, cspec, size);
		
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
		if (!normalstack) {
			flags |= REVERSE_STACK;
			if (alignment != 0) {
				if ((size % alignment) != 0) {
					throw new XmlParseException("For positive stack growth, <pentry> size must match alignment");
				}
			}
		}
		// resolveJoin
		parser.end(el);
	}
	
	/**
	 * Unsigned less-than operation
	 * @param a
	 * @param b
	 * @return   return true is a is less than b, where a and b are interpreted as unsigned integers
	 */
	public static boolean unsignedCompare(long a,long b) {
		return (a+0x8000000000000000L < b + 0x8000000000000000L);
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
	 * @param sz2   size of second space
	 * @param forceleft  is true if containment is forced to be on the left even for big endian
	 * @param isBigEndian true if big endian
	 * @return the endian aware offset or -1
	 */
	public static int justifiedContainAddress(AddressSpace spc1,long offset1,int sz1,AddressSpace spc2,long offset2,int sz2,boolean forceleft,boolean isBigEndian) {
		if (spc1 != spc2) {
			return -1;
		}
		if (unsignedCompare(offset2,offset1)) {
			return -1;
		}
		long off1 = offset1 + (sz1 - 1);
		long off2 = offset2 + (sz2 - 1);
		if (unsignedCompare(off1,off2)) {
			return -1;
		}
		if (isBigEndian && (!forceleft)) {
			return (int)(off1 - off2);
		}
		return (int)(offset2 - offset1);
	}
	
	public static int getMetatype(DataType tp) {
		// TODO: A complete metatype implementation
		if (tp instanceof TypeDef) {
			tp = ((TypeDef)tp).getBaseDataType();
		}
		if (tp instanceof AbstractFloatDataType) {
			return TYPE_FLOAT;
		}
		if (tp instanceof Pointer) {
			return TYPE_PTR;
		}
		return TYPE_UNKNOWN;
	}
}
