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
package ghidra.program.model.pcode;

import ghidra.program.model.address.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

/**
 * 
 *
 * Basically a unique address for a PcodeOp
 * It is unique, maintains original assembly instruction address, and is comparable
 * within a basic block
 */
public class SequenceNumber implements Comparable<SequenceNumber> {
	private Address pc;					// Address of assembly language instruction
	private int uniq;					// Sub-address for distinguishing multiple PcodeOps at one
										// instruction address. Does not change over lifetime of PcodeOp
	private int order;					// Contains relative position information of PcodeOps within
										// a basic block, may change as basic block is edited.
	
	/**
	 * Construct a sequence number for an instruction at an address and sequence of pcode op within
	 * that instructions set of pcode.
	 * 
	 * @param instrAddr address of instruction
	 * @param sequenceNum sequence of pcode op with an instructions pcode ops
	 */
	public SequenceNumber(Address instrAddr, int sequenceNum) {
		pc = instrAddr;
		uniq = sequenceNum;
	}
	
	/**
	 * @return get address of instruction this sequence belongs to
	 */
	public Address getTarget() {
		return pc;
	}
	
	/**
	 * Get unique Sub-address for distinguishing multiple PcodeOps at one
	 * instruction address.
	 * Does not change over lifetime of PcodeOp
	 * 
	 * @return unique id for a pcode op within a given instruction
	 */
	public int getTime() {
		return uniq;
	}

	/**
	 * Set unique Sub-address for distinguishing multiple PcodeOps at one
	 * instruction address.
	 * Does not change over lifetime of PcodeOp
	 * 
	 * @param t unique id
	 */
	public void setTime(int t) {
		uniq = t;	
	}
	
	/**
	 * Get relative position information of PcodeOps within
	 * a basic block, may change as basic block is edited.
	 * 
	 * @return relative position of pcode in a basic block
	 */
	public int getOrder() {
		return order;
	}
	
	/**
	 * Set relative position information of PcodeOps within
	 * a basic block, may change as basic block is edited.
	 * 
	 * @param o relative position of pcodeOp within a basic block
	 */
	public void setOrder(int o) {
		order = o;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
    public boolean equals(Object o) {
		if (!(o instanceof SequenceNumber)) return false;
		SequenceNumber sq = (SequenceNumber) o;
		return (pc.equals(sq.pc)&&(uniq==sq.uniq));
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(SequenceNumber sq)  {
		int val = pc.compareTo(sq.pc);
		if (val != 0) return val;
		if (uniq < sq.uniq) return -1;
		if (sq.uniq < uniq) return 1;
		return 0;
	}

	/**
	 * @return  Build XML tag for SequenceNumber
	 */
	public StringBuilder buildXML() {
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<seqnum");
		AddressSpace space = pc.getAddressSpace();
		SpecXmlUtils.encodeStringAttribute(resBuf, "space", space.getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "offset", pc.getOffset());
		if (uniq != -1)
			SpecXmlUtils.encodeUnsignedIntegerAttribute(resBuf, "uniq", uniq);
		resBuf.append("/>");
		return resBuf;		
	}
	
	/**
	 * Create a new Sequence number from XML SAX tree element.
	 * 
	 * @param parser the xml parser
	 * @param factory pcode factory used to create new pcode
	 * 
	 * @return new sequence number
	 */
	public static SequenceNumber readXML(XmlPullParser parser,AddressFactory factory) {
	    XmlElement el = parser.start("seqnum");
		String attrstring = el.getAttribute("uniq");
		int uniq;
		if (attrstring != null)
			uniq = SpecXmlUtils.decodeInt(attrstring);
		else
			uniq = -1;				// Should fill in with something from factory
		String space = el.getAttribute("space");	
		AddressSpace spc = factory.getAddressSpace(space);
		long offset = SpecXmlUtils.decodeLong(el.getAttribute("offset"));
		parser.end(el);
		return new SequenceNumber(spc.getAddress(offset),uniq);
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return ("("
			+ pc.getAddressSpace().getName()
			+ ", 0x"
			+ Long.toHexString(pc.getOffset())
			+ ", "
			+ uniq
			+ ", "
			+ order
			+ ")");
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
    public int hashCode() {
		return pc.hashCode() + uniq;			// Don't hash order, as this is mutable
	}

}
