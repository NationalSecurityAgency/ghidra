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

import ghidra.program.model.address.Address;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;

/**
 * Placeholder for a basic block (BlockBasic) within a structured
 * control-flow graph. It originally mirrors the in and out edges of
 * the basic block, but edges may be modified during the structuring process.
 * This copy holds a reference to the actual basic block
 */
public class BlockCopy extends PcodeBlock {
	private Object ref;			// Reference to basic block of which this is a copy
	private Address address;	// Address upon entry to the basic block
	private int altindex;		// Alternate index for correlating this block with result structure
	
	public BlockCopy() {
		super();
		blocktype = PcodeBlock.COPY;
		address = Address.NO_ADDRESS;
		ref = null;
	}
	
	public BlockCopy(Object r,Address addr) {
		super();
		ref = r;
		blocktype = PcodeBlock.COPY;
		address = addr;
	}

	@Override
	public Address getStart() {
		return address;
	}

	@Override
	public Address getStop() {
		return address;
	}

	/**
	 * @return the underlying basic block Object
	 */
	public Object getRef() {
		return ref;
	}
	
	/**
	 * Used (by BlockGraph.transferObjectRef) to reset the internal Object and Address 
	 * @param r is the internal Object
	 * @param addr is the Address
	 */
	protected void set(Object r, Address addr) {
		ref = r;
		address = addr;
	}

	/**
	 * @return the alternative index, used as an id for the original basic block Object
	 */
	public int getAltIndex() {
		return altindex;
	}

	@Override
	public void saveXmlHeader(StringBuilder buf) {
		super.saveXmlHeader(buf);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "altindex", altindex);
	}

	@Override
	public void restoreXmlHeader(XmlElement el) throws PcodeXMLException {
		super.restoreXmlHeader(el);
		altindex = SpecXmlUtils.decodeInt(el.getAttribute("altindex"));
	}
}
