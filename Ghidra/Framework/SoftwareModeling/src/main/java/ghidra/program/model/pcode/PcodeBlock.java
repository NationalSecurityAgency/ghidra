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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.Address;

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
		 * Encode edge to stream assuming we already know what block we are in
		 * @param encoder is the stream encoder
		 * @throws IOException for errors writing to underlying stream
		 */
		public void encode(Encoder encoder) throws IOException {
			encoder.openElement(ELEM_EDGE);
			// We are not encoding label currently

			// Reference to other end of edge
			encoder.writeSignedInteger(ATTRIB_END, point.getIndex());
			// Position within other blocks edgelist
			encoder.writeSignedInteger(ATTRIB_REV, reverse_index);
			encoder.closeElement(ELEM_EDGE);
		}

		/**
		 * Decode a single edge
		 * @param decoder is the stream decoder
		 * @param resolver used to recover PcodeBlock reference
		 * @throws PcodeXMLException for invalid encodings
		 */
		public void decode(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
			int el = decoder.openElement(ELEM_EDGE);
			label = 0;		// Tag does not currently contain info about label
			int endIndex = (int) decoder.readSignedInteger(ATTRIB_END);
			point = resolver.findLevelBlock(endIndex);
			if (point == null) {
				throw new PcodeXMLException("Bad serialized edge in block graph");
			}
			reverse_index = (int) decoder.readSignedInteger(ATTRIB_REV);
			decoder.closeElement(el);
		}

		public void decode(Decoder decoder, ArrayList<? extends PcodeBlock> blockList)
				throws PcodeXMLException {
			int el = decoder.openElement(ELEM_EDGE);
			label = 0;		// Tag does not currently contain info about label
			int endIndex = (int) decoder.readSignedInteger(ATTRIB_END);
			point = blockList.get(endIndex);
			if (point == null) {
				throw new PcodeXMLException("Bad serialized edge in block list");
			}
			reverse_index = (int) decoder.readSignedInteger(ATTRIB_REV);
			decoder.closeElement(el);
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
		intothis = new ArrayList<>();
		outofthis = new ArrayList<>();
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
	 * Decode the next input edge from the stream
	 * @param decoder is the stream decoder
	 * @param resolver is used to find PcodeBlocks
	 * @throws PcodeXMLException for any invalid encoding
	 */
	protected void decodeNextInEdge(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
		BlockEdge inEdge = new BlockEdge();
		intothis.add(inEdge);
		inEdge.decode(decoder, resolver);
		while (inEdge.point.outofthis.size() <= inEdge.reverse_index) {
			inEdge.point.outofthis.add(null);
		}
		BlockEdge outEdge = new BlockEdge(this, 0, intothis.size() - 1);
		inEdge.point.outofthis.set(inEdge.reverse_index, outEdge);
	}

	/**
	 * Decode the next input edge from the stream. Resolve block indices via a blockList
	 * @param decoder is the stream decoder
	 * @param blockList allows lookup of PcodeBlock via index
	 * @throws PcodeXMLException for any invalid encoding
	 */
	protected void decodeNextInEdge(Decoder decoder, ArrayList<? extends PcodeBlock> blockList)
			throws PcodeXMLException {
		BlockEdge inEdge = new BlockEdge();
		intothis.add(inEdge);
		inEdge.decode(decoder, blockList);
		while (inEdge.point.outofthis.size() <= inEdge.reverse_index) {
			inEdge.point.outofthis.add(null);
		}
		BlockEdge outEdge = new BlockEdge(this, 0, intothis.size() - 1);
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

	/**
	 * Encode basic attributes to stream. Assume this block's element is already started.
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	protected void encodeHeader(Encoder encoder) throws IOException {
		encoder.writeSignedInteger(ATTRIB_INDEX, index);
	}

	protected void decodeHeader(Decoder decoder) throws PcodeXMLException {
		index = (int) decoder.readSignedInteger(ATTRIB_INDEX);
	}

	/**
	 * Encode information about the block to stream,
	 * other than header and edge info
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	protected void encodeBody(Encoder encoder) throws IOException {
		// No body by default
	}

	/**
	 * Encode information about this blocks edges to stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	protected void encodeEdges(Encoder encoder) throws IOException {
		for (BlockEdge element : intothis) {
			element.encode(encoder);
		}
	}

	/**
	 * Restore the any additional information beyond header and edges from stream
	 * @param decoder is the stream decoder
	 * @param resolver is for looking up edge references
	 * @throws PcodeXMLException for invalid encoding
	 */
	protected void decodeBody(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
		// No body to restore by default
	}

	protected void decodeEdges(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
		for (;;) {
			int el = decoder.peekElement();
			if (el != ELEM_EDGE.id()) {
				break;
			}
			decodeNextInEdge(decoder, resolver);
		}
	}

	/**
	 * Encode this block to a stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_BLOCK);
		encodeHeader(encoder);
		encodeBody(encoder);
		encodeEdges(encoder);
		encoder.closeElement(ELEM_BLOCK);
	}

	/**
	 * Decode this block from a stream
	 * @param decoder is the stream decoder
	 * @param resolver is the map from reference to block object
	 * @throws PcodeXMLException for errors in the encoding
	 */
	public void decode(Decoder decoder, BlockMap resolver) throws PcodeXMLException {
		int el = decoder.openElement(ELEM_BLOCK);
		decodeHeader(decoder);
		decodeBody(decoder, resolver);
		decodeEdges(decoder, resolver);
		decoder.closeElement(el);
	}
}
