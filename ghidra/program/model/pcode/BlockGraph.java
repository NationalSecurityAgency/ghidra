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
import java.util.ArrayList;

import ghidra.program.model.address.AddressFactory;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A block (with in edges and out edges) that contains other blocks
 *
 */
public class BlockGraph extends PcodeBlock {
	private ArrayList<PcodeBlock> list;			// List of blocks within the super-block
	private int maxindex;						// -index- contains minimum -maxindex- contains max
	
	public BlockGraph() {
		super();
		blocktype = PcodeBlock.GRAPH;
		list = new ArrayList<PcodeBlock>();
		maxindex = -1;
	}
	
	/**
	 * Add a block to this container. There are (initially) no edges between
	 * it and any other block in the container.
	 * @param bl is the new block to add
	 */
	public void addBlock(PcodeBlock bl) {
		int min,max;
		if (bl instanceof BlockGraph) {
			BlockGraph gbl = (BlockGraph)bl;
			min = gbl.index;
			max = gbl.maxindex;
		}
		else {
			min = bl.index;
			max = min;
		}
		
		if (list.isEmpty()) {
			index = min;
			maxindex = max;
		}
		else {
			if (min < index)
				index = min;
			if (max > maxindex)
				maxindex = max;
		}
		bl.parent = this;
		list.add(bl);
	}

	/**
	 * Assign a unique index to all blocks in this container. After this call,
	 * getBlock(i) will return the block that satisfies block.getIndex() == i
	 */
	public void setIndices() {
		for(int i=0;i<list.size();++i) {
			list.get(i).index = i;
		}
		index = 0;
		maxindex = list.size()-1;
	}
	
	/**
	 * @return the number of blocks in this container
	 */
	public int getSize() {
		return list.size();
	}
	
	/**
	 * Retrieve the i-th block from this container
	 * @param i is the index of the block to fetch
	 * @return
	 */
	public PcodeBlock getBlock(int i) {
		return list.get(i);
	}

	/**
	 * Add a directed edge between two blocks in this container
	 * @param begin is the "from" block of the edge
	 * @param end is the "to" block of the edge
	 */
	public void addEdge(PcodeBlock begin,PcodeBlock end) {
		end.addInEdge(begin, 0);
	}

	/**
	 * Recursively run through this structured BlockGraph finding the BlockCopy leaves.
	 * Using the BlockCopy altindex, lookup the original BlockCopy in -ingraph- and
	 * transfer the Object ref and Address into the leaf 
	 * @param ingraph is the original flow graph
	 */
	public void transferObjectRef(BlockGraph ingraph) {
		ArrayList<BlockGraph> queue = new ArrayList<BlockGraph>();
		int pos = 0;
		queue.add(this);
		while (pos < queue.size()) {
			BlockGraph curgraph = queue.get(pos);
			pos += 1;
			int sz = curgraph.getSize();
			for (int i = 0; i < sz; ++i) {
				PcodeBlock block = curgraph.getBlock(i);
				if (block instanceof BlockCopy) {
					BlockCopy copyblock = (BlockCopy) block;
					int altindex = copyblock.getAltIndex();
					if (altindex < ingraph.getSize()) {
						PcodeBlock block2 = ingraph.getBlock(altindex);
						if (block2 instanceof BlockCopy) {
							BlockCopy copyblock2 = (BlockCopy) block2;
							copyblock.set(copyblock2.getRef(), copyblock2.getStart());	// Transfer the object reference
						}
					}
				}
				else if (block instanceof BlockGraph)
					queue.add((BlockGraph) block);
			}
		}
	}

	@Override
	public void saveXmlBody(Writer writer) throws IOException {
		super.saveXmlBody(writer);
		for(int i=0;i<list.size();++i) {
			PcodeBlock bl = list.get(i);
			StringBuilder buf = new StringBuilder();
			buf.append("<bhead");
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "index", bl.getIndex());
			String name = PcodeBlock.typeToName(bl.blocktype);
			SpecXmlUtils.encodeStringAttribute(buf, "type", name);
			buf.append("/>\n");
			writer.write(buf.toString());
		}
		for(int i=0;i<list.size();++i) {
			PcodeBlock bl = list.get(i);
			bl.saveXml(writer);
		}
	}

	@Override
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		BlockMap newresolver = new BlockMap(resolver);
		super.restoreXmlBody(parser, newresolver);
		ArrayList<PcodeBlock> tmplist = new ArrayList<PcodeBlock>();
		while(parser.peek().isStart()) {
			if (!parser.peek().getName().equals("bhead"))
				break;
			XmlElement el = parser.start();
			int ind = SpecXmlUtils.decodeInt(el.getAttribute("index"));
			String name = el.getAttribute("type");
			PcodeBlock newbl = newresolver.createBlock(name, ind);
			tmplist.add(newbl);
			parser.end(el);
		}
		newresolver.sortLevelList();
		for(int i=0;i<tmplist.size();++i) {
			PcodeBlock bl = tmplist.get(i);
			bl.restoreXml(parser, newresolver);
			addBlock(bl);
		}
	}

	/**
	 * Restore all blocks and edges in this container from an XML stream.
	 * @param parser is the XML stream parser
	 * @param factory is the AddressFactory used to construct any Address
	 * @throws PcodeXMLException if part of the XML description is invalid
	 */
	public void restoreXml(XmlPullParser parser, AddressFactory factory) throws PcodeXMLException {
		BlockMap resolver = new BlockMap(factory);
		restoreXml(parser,resolver);
		resolver.resolveGotoReferences();
	}
}
