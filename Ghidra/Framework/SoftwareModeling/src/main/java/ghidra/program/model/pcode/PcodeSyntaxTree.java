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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Varnodes and PcodeOps in a coherent graph structure
 */
public class PcodeSyntaxTree implements PcodeFactory {

	private AddressFactory addrFactory;
	private PcodeDataTypeManager datatypeManager;
	private HashMap<Integer, Varnode> refmap;					// Obtain varnode by id
	private HashMap<Integer, PcodeOp> oprefmap;				// Obtain op by SequenceNumber unique id
	private HashMap<Integer,VariableStorage> joinmap;			// logical map of joined objects
	private int joinAllocate;								// next offset to be allocated in join map
	private PcodeOpBank opbank;
	private VarnodeBank vbank;
	private ArrayList<PcodeBlockBasic> bblocks;					// Basic blocks for this syntax tree
	private int uniqId;								// Next uniqId for a created varnode

	public PcodeSyntaxTree(AddressFactory afact, PcodeDataTypeManager dtmanage) {
		addrFactory = afact;
		datatypeManager = dtmanage;
		refmap = null;
		oprefmap = null;
		joinmap = null;
		joinAllocate = 0;
		opbank = new PcodeOpBank();
		vbank = new VarnodeBank();
		bblocks = new ArrayList<PcodeBlockBasic>();
		uniqId = 0;
	}

	public void clear() {
		refmap = null;
		oprefmap = null;
		joinmap = null;
		joinAllocate = 0;
		vbank.clear();
		opbank.clear();
		bblocks = new ArrayList<PcodeBlockBasic>();
		uniqId = 0;
	}

	private static Varnode getVarnodePiece(String pieceStr, AddressFactory addrFactory)
			throws PcodeXMLException {
// TODO: Can't handle register name since addrFactory can't handle this
		String[] varnodeTokens = pieceStr.split(":");
		if (varnodeTokens.length != 3) {
			throw new PcodeXMLException("Invalid XML addr piece: " + pieceStr);
		}
		AddressSpace space = addrFactory.getAddressSpace(varnodeTokens[0]);
		if (space == null) {
			throw new PcodeXMLException("Invalid XML addr, space not found: " + pieceStr);
		}
		if (!varnodeTokens[1].startsWith("0x")) {
			throw new PcodeXMLException("Invalid XML addr piece offset: " + pieceStr);
		}
		long offset;
		try {
			offset = Long.parseUnsignedLong(varnodeTokens[1].substring(2), 16);
		}
		catch (NumberFormatException e) {
			throw new PcodeXMLException("Invalid XML addr piece offset: " + pieceStr);
		}
		int size;
		try {
			size = Integer.parseInt(varnodeTokens[2]);
		}
		catch (NumberFormatException e) {
			throw new PcodeXMLException("Invalid XML addr piece size: " + pieceStr);
		}
		return new Varnode(space.getAddress(offset), size);
	}

	/**
	 * Read an XML join address with "piece" attributes
	 * 
	 * @param el SAX parse tree element
	 * @param addr join address associated with pieces
	 * 
	 * @return the VariableStorage associated with xml
	 * @throws PcodeXMLException
	 * @throws InvalidInputException
	 */
	@Override
	public VariableStorage readXMLVarnodePieces(XmlElement el, Address addr) throws PcodeXMLException, InvalidInputException {
		ArrayList<Varnode> list = new ArrayList<Varnode>();
		int index = 1;
		String nextPiece = "piece" + index;
		while (el.hasAttribute(nextPiece)) {
			String pieceStr = el.getAttribute(nextPiece);
			list.add(getVarnodePiece(pieceStr, addrFactory));
			nextPiece = "piece" + ++index;
		}
		Varnode[] pieces = new Varnode[list.size()];
		list.toArray(pieces);

		return allocateJoinStorage(addr.getOffset(), pieces);
	}

	private VariableStorage allocateJoinStorage(long offset,Varnode[] pieces) throws InvalidInputException {
		VariableStorage storage;
		try {
			storage = new VariableStorage(datatypeManager.getProgram(),pieces);
		} catch (InvalidInputException e) {
			storage = null;
		}
		if (storage == null) {
			// TODO: VariableStorage probably needs to support more piece combinations
			// The decompiler can generate joins that can't be stored.
			// We fill in an emergency storage location in the unique space in these cases
			// because generally we only need a placeholder in the syntax tree.
			// Using a unique allows renaming to work using DynamicHash
			// These awkward joins in many cases are a symptom of other problems, like
			// bad prototypes causing the decompiler to produce weird stuff
			// TODO: We should emit some kind of warning
			int sz = 0;
			for (Varnode piece : pieces) {
				sz += piece.getSize();
			}
			Address uniqaddr = addrFactory.getUniqueSpace().getAddress(0x20000000);
			storage = new VariableStorage(datatypeManager.getProgram(),uniqaddr,sz);
		}
		Integer offObject;
		int roundsize = (storage.size() + 15) & 0xfffffff0;
		if (offset < 0) {
			offObject = new Integer(joinAllocate);
			joinAllocate += roundsize;
		}
		else {
			offObject = new Integer((int)offset);
			offset += roundsize;
			if (offset > joinAllocate) {
				joinAllocate = (int)offset;
			}
		}
		if (joinmap == null) {
			joinmap = new HashMap<Integer,VariableStorage>();
		}
		joinmap.put(offObject, storage);
		return storage;
	}

	private VariableStorage findJoinStorage(long offset) {
		if (joinmap == null) {
			return null;
		}
		return joinmap.get(new Integer((int)offset));
	}

	@Override
	public VariableStorage buildStorage(Varnode vn) throws InvalidInputException {
		Address addr = vn.getAddress();
		if (addr.getAddressSpace().getType() == AddressSpace.TYPE_VARIABLE) {
			return findJoinStorage(addr.getOffset());
		}
		return new VariableStorage(datatypeManager.getProgram(),vn);
	}

	/**
	 * Returns an iterator for all Varnodes in the tree ordered by Address
	 */
	public Iterator<VarnodeAST> locRange() {
		return vbank.locRange();
	}

	/**
	 * return Iterator to all Varnodes in the indicated AddressSpace
	 * @param spc -- AddressSpace to restrict Iterator to
	 * @return -- Iterator to Varnodes
	 */
	public Iterator<VarnodeAST> getVarnodes(AddressSpace spc) {
		return vbank.locRange(spc);
	}

	/**
	 * return all Varnodes that start at a given Address
	 * @param addr -- Address of Varnodes
	 * @return -- Iterator to Varnodes
	 */
	public Iterator<VarnodeAST> getVarnodes(Address addr) {
		return vbank.locRange(addr);
	}

	/**
	 * return all Varnodes of a given size that start at a given Address
	 * @param sz -- Size of Varnodes
	 * @param addr -- Starting Address of Varnodes
	 * @return -- Iterator to Varnodes
	 */
	public Iterator<VarnodeAST> getVarnodes(int sz, Address addr) {
		return vbank.locRange(sz, addr);
	}

	/**
	 * return first instance of a Varnode with given size, starting Address,
	 * and bound to an instruction at the given Address
	 * @param sz  -- size of Varnode
	 * @param addr -- starting Address of Varnode
	 * @param pc -- Address of instruction writing to Varnode
	 * @return -- the Varnode
	 */
	public Varnode findVarnode(int sz, Address addr, Address pc) {
		return vbank.find(sz, addr, pc, -1);
	}

	/**
	 * return Varnode of given size and starting Address defined by a PcodeOp
	 * with a given SequenceNumber
	 * @param sz -- size of Varnode
	 * @param addr -- starting Address of Varnode
	 * @param sq -- SequenceNumber of PcodeOp defining the Varnode
	 * @return -- the Varnode
	 */
	public Varnode findVarnode(int sz, Address addr, SequenceNumber sq) {
		return vbank.find(sz, addr, sq.getTarget(), sq.getTime());
	}

	/**
	 * return Varnode of given size and starting Address, which is also an input
	 * @param sz -- size of Varnode
	 * @param addr -- starting Address of Varnode
	 * @return -- the Varnode
	 */
	public Varnode findInputVarnode(int sz, Address addr) {
		return vbank.findInput(sz, addr);
	}

	public int getNumVarnodes() {
		return vbank.size();
	}

	/**
	 * return all PcodeOps (alive or dead) ordered by SequenceNumber
	 * @return -- Iterator to PcodeOps
	 */
	public Iterator<PcodeOpAST> getPcodeOps() {
		return opbank.allOrdered();
	}

	/**
	 * return all PcodeOps associated with a particular instruction Address
	 * @param addr -- Address of instruction generating PcodeOps
	 * @return -- Iterator to PcodeOps
	 */
	public Iterator<PcodeOpAST> getPcodeOps(Address addr) {
		return opbank.allOrdered(addr);
	}

	public PcodeOp getPcodeOp(SequenceNumber sq) {
		return opbank.findOp(sq);
	}

	/**
	 * @deprecated
	 * @return the varnode bank for this syntax tree
	 */
	@Deprecated
	public VarnodeBank getVbank() {
		return vbank;
	}

	public ArrayList<PcodeBlockBasic> getBasicBlocks() {
		return bblocks;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addrFactory;
	}

	@Override
	public PcodeDataTypeManager getDataTypeManager() {
		return datatypeManager;
	}

	@Override
	public Varnode newVarnode(int sz, Address addr) {
		Varnode vn = vbank.create(sz, addr, uniqId);
		uniqId += 1;
		return vn;
	}

	@Override
	public Varnode newVarnode(int sz, Address addr, int id) {
		Varnode vn = vbank.create(sz, addr, id);
		if (uniqId <= id) {
			uniqId = id + 1;
		}
		if (refmap != null) {
			refmap.put(id, vn);
		}
		return vn;
	}

	@Override
	public Varnode createFromStorage(Address addr,VariableStorage storage, int logicalSize) {
		Varnode[] pieces = storage.getVarnodes();

		// This is the most common case, 1 piece, and address is pulled from the piece
		if ((pieces.length == 1) && (addr == null)) {
			Varnode vn = newVarnode(pieces[0].getSize(), pieces[0].getAddress());
			return vn;
		}

		// Anything past here allocates varnode from the JOIN (VARIABLE) space.
		// addr should be non-null ONLY if it is in the JOIN space
		try {
			if (addr == null) {		// addr can still be null for join space varnode
				long joinoffset = joinAllocate;				// Next available offset
				storage = allocateJoinStorage(-1, pieces);	// is allocated from JOIN space
				addr = AddressSpace.VARIABLE_SPACE.getAddress(joinoffset);
			} else {
				storage = allocateJoinStorage(addr.getOffset(), pieces);
			}
		} catch (InvalidInputException e) {
			return null;
		}
		Varnode vn = newVarnode(logicalSize, addr);
		return vn;
	}

	@Override
	public Varnode setInput(Varnode vn, boolean val) {
		if ((!vn.isInput()) && val) {
			return vbank.setInput(vn);
		}
		if (vn.isInput() && (!val)) {
			vbank.makeFree(vn);
		}
		return vn;
	}

	private void buildVarnodeRefs() {
		refmap = new HashMap<Integer, Varnode>((int) (1.5 * vbank.size()));
		Iterator<?> iter = vbank.locRange();			// Iterate over all varnodes
		while (iter.hasNext()) {
			VarnodeAST vn = (VarnodeAST) iter.next();
			refmap.put(vn.getUniqueId(), vn);
		}
	}

	@Override
	public Varnode getRef(int id) {
		if (refmap == null) {
			return null;
		}
		return refmap.get(id);
	}

	@Override
	public HighSymbol getSymbol(long symbolId) {
		return null;
	}

	@Override
	public void setDataType(Varnode vn, DataType type) {
		// Not supporting DataType in varnode currently		
	}

	@Override
	public void setAddrTied(Varnode vn, boolean val) {
		VarnodeAST vnast = (VarnodeAST) vn;
		vnast.setAddrtied(val);
	}

	@Override
	public void setPersistent(Varnode vn, boolean val) {
		VarnodeAST vnast = (VarnodeAST) vn;
		vnast.setPersistent(val);
	}

	@Override
	public void setUnaffected(Varnode vn, boolean val) {
		VarnodeAST vnast = (VarnodeAST) vn;
		vnast.setUnaffected(val);
	}

	@Override
	public void setMergeGroup(Varnode vn, short val) {
		VarnodeAST vnast = (VarnodeAST) vn;
		vnast.setMergeGroup(val);
	}

	private void buildOpRefs() {
		oprefmap = new HashMap<Integer, PcodeOp>((int) (1.5 * opbank.size()));
		Iterator<?> iter = opbank.allOrdered();
		while (iter.hasNext()) {
			PcodeOp op = (PcodeOp) iter.next();
			oprefmap.put(op.getSeqnum().getTime(), op);
		}
	}

	@Override
	public PcodeOp getOpRef(int id) {
		if (oprefmap == null) {
			buildOpRefs();
		}
		return oprefmap.get(id);
	}

	public void insertBefore(PcodeOp newop, PcodeOp follow) {
		PcodeOpAST newopast = (PcodeOpAST) newop;
		PcodeOpAST followast = (PcodeOpAST) follow;
		PcodeBlockBasic bblock = followast.getParent();
		bblock.insertBefore(followast.getBasicIter(), newopast);
		opbank.markAlive(newopast);
	}

	public void insertAfter(PcodeOp newop, PcodeOp prev) {
		PcodeOpAST newopast = (PcodeOpAST) newop;
		PcodeOpAST prevast = (PcodeOpAST) prev;
		PcodeBlockBasic bblock = prevast.getParent();
		bblock.insertAfter(prevast.getBasicIter(), newopast);
		opbank.markAlive(newopast);
	}

	public void setOpcode(PcodeOp op, int opc) {
		opbank.changeOpcode(op, opc);
	}

	public void setOutput(PcodeOp op, Varnode vn) {
		if (vn == op.getOutput())
		 {
			return;			// Output already set to this
		}
		if (op.getOutput() != null) {
			unSetOutput(op);
		}

		if (vn.getDef() != null) {
			unSetOutput(vn.getDef());
		}
		vn = vbank.setDef(vn, op);
		op.setOutput(vn);
	}

	public void unSetOutput(PcodeOp op) {
		Varnode vn = op.getOutput();
		if (vn == null)
		 {
			return;		// Nothing to do
		}
		op.setOutput(null);
		vbank.makeFree(vn);
	}

	public void setInput(PcodeOp op, Varnode vn, int slot) {
		if (slot >= op.getNumInputs())
		 {
			op.setInput(null, slot);					// Expand number of inputs as necessary
		}
		if (op.getInput(slot) != null) {
			unSetInput(op, slot);
		}
		if (vn != null) {
			VarnodeAST vnast = (VarnodeAST) vn;
			vnast.addDescendant(op);
			op.setInput(vnast, slot);
		}
	}

	public void unSetInput(PcodeOp op, int slot) {
		VarnodeAST vn = (VarnodeAST) op.getInput(slot);
		vn.removeDescendant(op);
		op.setInput(null, slot);
	}

	public void unInsert(PcodeOp op) {
		opbank.markDead(op);
		op.getParent().remove(op);
	}

	public void delete(PcodeOp op) {
		opbank.destroy(op);
	}

	public void unlink(PcodeOpAST op) {
		unSetOutput(op);
		for (int i = 0; i < op.getNumInputs(); ++i) {
			unSetInput(op, i);
		}
		if (op.getParent() != null) {
			unInsert(op);
		}
	}

	@Override
	public PcodeOp newOp(SequenceNumber sq, int opc, ArrayList<Varnode> inputs, Varnode output)
			throws UnknownInstructionException {
		PcodeOp op = opbank.create(opc, inputs.size(), sq);
		if (output != null) {
			setOutput(op, output);
		}
		for (int i = 0; i < inputs.size(); ++i) {
			setInput(op, inputs.get(i), i);
		}
		if (oprefmap != null) {
			oprefmap.put(sq.getTime(), op);
		}
		return op;
	}

	private void readVarnodeXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("varnodes");
		while (parser.peek().isStart()) {
			Varnode.readXML(parser, this);
		}
		parser.end(el);
	}

	private void readBasicBlockXML(XmlPullParser parser, BlockMap resolver)
			throws PcodeXMLException {
		XmlElement el = parser.start("block");
		int order = 0;
		PcodeBlockBasic bl = new PcodeBlockBasic();
		bl.restoreXmlHeader(el);
		bl.restoreXmlBody(parser, resolver);
		while (parser.peek().isStart()) {
			PcodeOp op = PcodeOp.readXML(parser, this);
			op.setOrder(order);
			order += 1;
			bl.insertEnd(op);
		}
		int index = bl.getIndex();
		while (bblocks.size() <= index) {
			bblocks.add(null);
		}
		bblocks.set(index, bl);
		parser.end(el);
	}

	private void readBlockEdgeXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("blockedge");
		int blockInd = SpecXmlUtils.decodeInt(el.getAttribute("index"));
		PcodeBlockBasic curBlock = bblocks.get(blockInd);
		while (parser.peek().isStart()) {
			curBlock.restoreNextInEdge(parser, bblocks);
		}
		parser.end(el);
	}

	public void readXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("ast");
		if (!vbank.isEmpty()) {
			clear();
		}
		readVarnodeXML(parser);
		buildVarnodeRefs();										// Build the HashMap
		BlockMap blockMap = new BlockMap(addrFactory);
		while (parser.peek().isStart()) {
			XmlElement subel = parser.peek();
			if (subel.getName().equals("block")) {
				readBasicBlockXML(parser, blockMap);		// Read a basic block and all its PcodeOps				
			}
			else {
				readBlockEdgeXML(parser);
			}
		}
		parser.end(el);
	}

}
