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

import ghidra.program.model.address.Address;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Blocks of PcodeOps
 */
public class PcodeBlock {
	int index;
	int blocktype;
	PcodeBlock parent;
	private ArrayList<BlockEdge> intothis;						// Blocks flowing into this block
	private ArrayList<BlockEdge> outofthis;						// Blocks into which this block flows

	public final static int PLAIN = 0;
	public final static int BASIC = 1;
	public final static int GRAPH = 2;
	public final static int COPY = 3;
	public final static int GOTO = 4;
	public final static int MULTIGOTO = 5;
	public final static int LIST = 6;
	public final static int CONDITION = 7;
	public final static int PROPERIF = 8;
	public final static int IFELSE = 9;
	public final static int IFGOTO = 10;
	public final static int WHILEDO = 11;
	public final static int DOWHILE = 12;
	public final static int SWITCH = 13;
	public final static int INFLOOP = 14;

	public static String typeToName(int type) {
		switch (type) {
			case PLAIN:
				return "plain";
			case BASIC:
				return "basic";
			case GRAPH:
				return "graph";
			case COPY:
				// this a trick for the decompiler c-side
				return "plain";
			case GOTO:
				return "goto";
			case MULTIGOTO:
				return "multigoto";
			case LIST:
				return "list";
			case CONDITION:
				return "condition";
			case PROPERIF:
				return "properif";
			case IFELSE:
				return "ifelse";
			case IFGOTO:
				return "ifgoto";
			case WHILEDO:
				return "whiledo";
			case DOWHILE:
				return "dowhile";
			case SWITCH:
				return "switch";
			case INFLOOP:
				return "infloop";
		}
		return null;
	}

	public static int nameToType(String name) {
		switch (name.charAt(0)) {
			case 'c':
				return COPY;
			case 'd':
				return DOWHILE;
			case 'g':
				if (name.equals("goto")) {
					return GOTO;
				}
				return GRAPH;
			case 'i':
				if (name.equals("ifelse")) {
					return IFELSE;
				}
				if (name.equals("infloop")) {
					return INFLOOP;
				}
				return IFGOTO;
			case 'l':
				return LIST;
			case 'm':
				return MULTIGOTO;
			case 'p':
				if (name.equals("properif")) {
					return PROPERIF;
				}
				return PLAIN;
			case 's':
				return SWITCH;
			case 'w':
				return WHILEDO;
		}
		return -1;
	}

	@Override
	public String toString() {
		return typeToName(blocktype) + "@" + getStart();
	}

	public static class BlockEdge {
		public int label;			// Label of this edge
		public PcodeBlock point;	// Other end of the edge
		public int reverse_index;	// Index for edge coming other way

		public BlockEdge(PcodeBlock pt, int lab, int rev) {
			label = lab;
			point = pt;
			reverse_index = rev;
		}

		/**
		 * For use with restoreXml
		 */
		public BlockEdge() {
		}

		/**
		 * Save edge as XML assuming we already know what block we are in
		 * @param buffer to write tag to
		 */
		public void saveXml(StringBuilder buffer) {
			buffer.append("<edge");
			// We are not saving label currently
			SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "end", point.getIndex());	// Reference to other end of edge
			SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "rev", reverse_index);	// Position within other blocks edgelist
			buffer.append("/>\n");
		}

		/**
		 * Restore meta-data for a single edge
		 * @param parser
		 * @param resolver used to recover PcodeBlock reference
		 * @throws PcodeXMLException
		 */
		public void restoreXml(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
			XmlElement el = parser.start("edge");
			label = 0;		// Tag does not currently contain info about label
			int endIndex = SpecXmlUtils.decodeInt(el.getAttribute("end"));
			point = resolver.findLevelBlock(endIndex);
			if (point == null)
				throw new PcodeXMLException("Bad serialized edge in block graph");
			reverse_index = SpecXmlUtils.decodeInt(el.getAttribute("rev"));
			parser.end(el);
		}

		public void restoreXml(XmlPullParser parser, ArrayList<? extends PcodeBlock> blockList)
				throws PcodeXMLException {
			XmlElement el = parser.start("edge");
			label = 0;		// Tag does not currently contain info about label
			int endIndex = SpecXmlUtils.decodeInt(el.getAttribute("end"));
			point = blockList.get(endIndex);
			if (point == null)
				throw new PcodeXMLException("Bad serialized edge in block list");
			reverse_index = SpecXmlUtils.decodeInt(el.getAttribute("rev"));
			parser.end(el);
		}

		@Override
		public String toString() {
			return "Edge -> " + point;
		}
	}

	public PcodeBlock() {
		index = -1;
		blocktype = PLAIN;
		parent = null;
		intothis = new ArrayList<BlockEdge>();
		outofthis = new ArrayList<BlockEdge>();
	}

	public int getType() {
		return blocktype;
	}

	/**
	 * @return the first Address covered by this block
	 */
	public Address getStart() {
		return Address.NO_ADDRESS;
	}

	/**
	 * @return the last Address covered by this block
	 */
	public Address getStop() {
		return Address.NO_ADDRESS;
	}

	public void setIndex(int i) {
		index = i;
	}

	public int getIndex() {
		return index;
	}

	public PcodeBlock getParent() {
		return parent;
	}

	protected void addInEdge(PcodeBlock b, int lab) {
		int ourrev = b.outofthis.size();
		int brev = intothis.size();
		intothis.add(new BlockEdge(b, lab, ourrev));
		b.outofthis.add(new BlockEdge(this, lab, brev));
	}

	/**
	 * Restore the next input edge via XML
	 * @param parser
	 * @param resolver
	 * @throws PcodeXMLException
	 */
	protected void restoreNextInEdge(XmlPullParser parser, BlockMap resolver)
			throws PcodeXMLException {
		BlockEdge inEdge = new BlockEdge();
		intothis.add(inEdge);
		inEdge.restoreXml(parser, resolver);
		while(inEdge.point.outofthis.size() <= inEdge.reverse_index) {
			inEdge.point.outofthis.add(null);
		}
		BlockEdge outEdge = new BlockEdge(this,0,intothis.size()-1);
		inEdge.point.outofthis.set(inEdge.reverse_index, outEdge);
	}

	/**
	 * Restore the next input edge via XML. Resolve block indices via a blockList
	 * @param parser
	 * @param blockList allows lookup of PcodeBlock via index
	 * @throws PcodeXMLException
	 */
	protected void restoreNextInEdge(XmlPullParser parser,
			ArrayList<? extends PcodeBlock> blockList) throws PcodeXMLException {
		BlockEdge inEdge = new BlockEdge();
		intothis.add(inEdge);
		inEdge.restoreXml(parser, blockList);
		while(inEdge.point.outofthis.size() <= inEdge.reverse_index) {
			inEdge.point.outofthis.add(null);
		}
		BlockEdge outEdge = new BlockEdge(this,0,intothis.size()-1);
		inEdge.point.outofthis.set(inEdge.reverse_index, outEdge);
	}

	public PcodeBlock getIn(int i) {
		return intothis.get(i).point;
	}

	public PcodeBlock getOut(int i) {
		return outofthis.get(i).point;
	}

	/**
	 * Get reverse index of the i-th outgoing block. I.e this.getOut(i).getIn(reverse_index) == this
	 * @param i is the outgoing block to request reverse index from
	 * @return the reverse index
	 */
	public int getOutRevIndex(int i) {
		return outofthis.get(i).reverse_index;
	}

	/**
	 * Get reverse index of the i-th incoming block. I.e. this.getIn(i).getOut(reverse_index) == this
	 * @param i is the incoming block to request reverse index from
	 * @return the reverse index
	 */
	public int getInRevIndex(int i) {
		return intothis.get(i).reverse_index;
	}

	/**
	 * Assuming paths out of this block depend on a boolean condition
	 * @return the PcodeBlock coming out of this if the condition is false
	 */
	public PcodeBlock getFalseOut() {
		return outofthis.get(0).point;
	}

	/**
	 * Assuming paths out of this block depend on a boolean condition
	 * @return the PcodeBlock coming out of this if the condition is true
	 */
	public PcodeBlock getTrueOut() {
		return outofthis.get(1).point;
	}

	public int getInSize() {
		return intothis.size();
	}

	public int getOutSize() {
		return outofthis.size();
	}

	public int calcDepth(PcodeBlock leaf) {
		int depth = 0;
		while (leaf != this) {
			if (leaf == null) {
				return -1;
			}
			leaf = leaf.getParent();
			depth += 1;
		}
		return depth;
	}

	public PcodeBlock getFrontLeaf() {
		PcodeBlock bl = this;
		while (bl instanceof BlockGraph) {
			bl = ((BlockGraph) bl).getBlock(0);
		}
		return bl;
	}

	public void saveXmlHeader(StringBuilder buffer) {
		SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "index", index);
	}

	public void restoreXmlHeader(XmlElement el) throws PcodeXMLException {
		index = SpecXmlUtils.decodeInt(el.getAttribute("index"));
	}

	/**
	 * Serialize information about the block to XML,
	 * other than header and edge info
	 * @param writer is where to serialize to
	 * @throws IOException if there is a problem with the stream
	 */
	public void saveXmlBody(Writer writer) throws IOException {
		// No body by default
	}

	public void saveXmlEdges(Writer writer) throws IOException {
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < intothis.size(); ++i) {
			intothis.get(i).saveXml(buf);
		}
		writer.write(buf.toString());
	}

	/**
	 * Restore the any additional information beyond header and edges from XML
	 * @param parser is the XML parser
	 * @param resolver is for looking up edge references
	 * @throws PcodeXMLException for invalid XML descriptions
	 */
	public void restoreXmlBody(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		// No body to restore by default
	}

	public void restoreXmlEdges(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		while (parser.peek().isStart()) {
			if (!parser.peek().getName().equals("edge")) {
				return;
			}
			restoreNextInEdge(parser, resolver);
		}
	}

	public void saveXml(Writer writer) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<block");
		saveXmlHeader(buf);
		buf.append(">\n");
		writer.write(buf.toString());
		saveXmlBody(writer);
		saveXmlEdges(writer);
		writer.write("</block>\n");
	}

	public void restoreXml(XmlPullParser parser, BlockMap resolver) throws PcodeXMLException {
		XmlElement el = parser.start("block");
		restoreXmlHeader(el);
		restoreXmlBody(parser, resolver);
		restoreXmlEdges(parser, resolver);
		parser.end(el);
	}
}
