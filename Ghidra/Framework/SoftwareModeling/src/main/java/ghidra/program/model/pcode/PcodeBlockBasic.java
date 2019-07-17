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

import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

import ghidra.program.model.address.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
/**
 * 
 *
 * A basic block constructed from PcodeOps
 */
public class PcodeBlockBasic extends PcodeBlock {
	private ListLinked<PcodeOp> oplist;						// List of PcodeOps making up the basic block
	private AddressSet cover;								// Addresses of instructions making up the block
	
	PcodeBlockBasic() {
		super();
		blocktype = PcodeBlock.BASIC;
		oplist = new ListLinked<PcodeOp>();
		cover = new AddressSet();
	}

	@Override
	public Address getStart() {
		return cover.getMinAddress();
	}

	@Override
	public Address getStop() {
		return cover.getMaxAddress();
	}

	/**
	 * Is the given address in the range of instructions represented by this basic block 
	 * @param addr is the Address
	 * @return true if the Address is contained
	 */
	public boolean contains(Address addr) {
		return cover.contains(addr);
	}

	/**
	 * Insert a new PcodeOp before a specific point in the list of PcodeOps
	 * @param iter points to the PcodeOp to insert before
	 * @param op is the new PcodeOp to insert
	 */
	protected void insertBefore(Iterator<PcodeOp> iter, PcodeOp op) {
		PcodeOpAST opast = (PcodeOpAST)op;
		opast.setParent(this);
		Iterator<PcodeOp> newiter = oplist.insertBefore(iter,op);
		opast.setBasicIter(newiter);
	}
	
	/**
	 * Insert a new PcodeOp after a specific point in the list of PcodeOps
	 * @param iter points to the PcodeOp to insert after
	 * @param op is the new PcodeOp to insert
	 */
	protected void insertAfter(Iterator<PcodeOp> iter, PcodeOp op) {
		PcodeOpAST opast = (PcodeOpAST)op;
		opast.setParent(this);
		Iterator<PcodeOp> newiter = oplist.insertAfter(iter,opast);
		opast.setBasicIter(newiter);
	}

	/**
	 * Insert a PcodeOp at the end of the block
	 * @param op is the PcodeOp to insert
	 */
	protected void insertEnd(PcodeOp op) {
		PcodeOpAST opast = (PcodeOpAST)op;
		opast.setParent(this);
		Iterator<PcodeOp> newiter = oplist.add(opast);
		opast.setBasicIter(newiter);
	}
	
	/**
	 * Remove a PcodeOp from the block
	 * @param op is the PcodeOp to remove
	 */
	protected void remove(PcodeOp op) {
		PcodeOpAST opast = (PcodeOpAST)op;
		opast.setParent(null);
		oplist.remove(op.getBasicIter());
	}
	
	/**
	 * @return an iterator over the PcodeOps in this basic block
	 */
	public Iterator<PcodeOp> getIterator() {
		return oplist.iterator();
	}

	@Override
	public void saveXmlBody(Writer writer) throws IOException {
		writer.append("<rangelist>\n");
		AddressRangeIterator iter = cover.getAddressRanges(true);
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			StringBuilder buffer = new StringBuilder();
			buffer.append("<range");
			SpecXmlUtils.encodeStringAttribute(buffer, "space", range.getAddressSpace().getName());
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "first",
				range.getMinAddress().getOffset());
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "last",
				range.getMaxAddress().getOffset());
			writer.append(buffer);
		}
		writer.append("</rangelist>\n");
	}

	@Override
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		AddressFactory addressFactory = resolver.getAddressFactory();
		XmlElement rangelistel = parser.start("rangelist");
		while (parser.peek().isStart()) {
			XmlElement rangeel = parser.start("range");
			String spc = rangeel.getAttribute("space");
			long offset = SpecXmlUtils.decodeLong(rangeel.getAttribute("first"));
			AddressSpace addressSpace = addressFactory.getAddressSpace(spc);
			Address start = addressSpace.getAddress(offset);
			offset = SpecXmlUtils.decodeLong(rangeel.getAttribute("last"));
			Address stop = addressSpace.getAddress(offset);
			cover.addRange(start, stop);
			parser.end(rangeel);
		}

		parser.end(rangelistel);
	}
}
