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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.NotYetImplementedException;

/**
 * 
 *
 * Class for converting ConstructTpl into a pcode ops given
 * a particular InstructionContext
 */
public abstract class PcodeEmit {

	private PcodeOverride override;
	private SleighParserContext parsercontext;
	private InstructionContext instcontext;
	private ParserWalker walker;
	private FlowOverride flowOverride;
	private Address startAddress;
	private Address defaultFallAddress;
	private Address fallOverride;
	private int fallOffset;
	private UniqueAddressFactory uniqueFactory;
	private VarnodeData outcache;
	protected VarnodeData[] incache;
	private VarnodeData[] dyncache;
	protected ArrayList<Integer> labeldef = null;
	protected int numOps = 0;							// Number of PcodeOps generated so far
	private int labelbase = 0;
	private int labelcount = 0;
	private boolean inDelaySlot = false;				// Are we currently emitting delayslot p-code
	private AddressSpace const_space;
	private AddressSpace uniq_space;
	private long uniquemask;
	private long uniqueoffset;
	private AddressSpace overlayspace = null;

	/**
	 * Pcode emitter constructor for empty or unimiplemented instructions
	 */
	protected PcodeEmit() {
	}

	/**
	 * Pcode emitter constructor
	 * @param walk is the ParserWalker state for the tree that needs to be walked to generate pcode
	 * @param ictx is the InstructionContext interface to resolve requests for context
	 * @param fallOffset default instruction fall offset (i.e., instruction length including delay slotted instructions)
	 * @param override required if pcode overrides are to be utilized
	 * @param uniqueFactory required when override specified or if overlay normalization is required
	 */
	public PcodeEmit(ParserWalker walk, InstructionContext ictx, int fallOffset,
			PcodeOverride override, UniqueAddressFactory uniqueFactory) {
		this.walker = walk;
		this.parsercontext = walk.getParserContext();
		this.instcontext = ictx;
		this.const_space = walk.getConstSpace();
		this.startAddress = parsercontext.getAddr();
		AddressSpace myspace = startAddress.getAddressSpace();
		if (myspace.isOverlaySpace()) {
			overlayspace = myspace;
			startAddress = ((OverlayAddressSpace) myspace).getOverlayedSpace().getAddress(
				startAddress.getOffset());
		}
		this.fallOffset = fallOffset;
		this.uniqueFactory = uniqueFactory;
		this.override = override;
		SleighInstructionPrototype sleighproto = parsercontext.getPrototype();
		if (sleighproto != null) {
			SleighLanguage sleighlang = (SleighLanguage) sleighproto.getLanguage();
			uniq_space = sleighlang.getAddressFactory().getUniqueSpace();
			uniquemask = sleighlang.getUniqueAllocationMask();
			uniqueoffset = (startAddress.getOffset() & uniquemask) << 4;
		}
		else {		// This can happen for CallFixup snippets, but these don't need their temporary vars patched up
			uniq_space = null;
			uniquemask = 0;
			uniqueoffset = 0;
		}

		if (override != null) {
			if (uniqueFactory == null) {
				throw new IllegalArgumentException(
					"uniqueFactory required when override is specified");
			}
			flowOverride = override.getFlowOverride();
			if (flowOverride == FlowOverride.NONE) {
				flowOverride = null;
			}
			fallOverride = override.getFallThroughOverride();
			if (fallOverride != null) {
				Address instrAddr = override.getInstructionStart();
				try {
					defaultFallAddress = instrAddr.addNoWrap(fallOffset);
					fallOffset = (int) fallOverride.subtract(instrAddr);
				}
				catch (AddressOverflowException e) {
					fallOverride = null;
					defaultFallAddress = null;
				}
			}
		}

		incache = new VarnodeData[8];	// Maximum number of inputs
		dyncache = null;
	}

	private void setUniqueOffset(Address addr) {
		uniqueoffset = (addr.getOffset() & uniquemask) << 4;
	}

	public Address getStartAddress() {
		return startAddress;
	}

	public int getFallOffset() {
		return fallOffset;
	}

	public ParserWalker getWalker() {
		return walker;
	}

	/**
	 * Make a note of the current op index, and associate
	 * it with the label index from the label template,
	 * so that the label can later be resolved to a relative
	 * address by resolveRelatives
	 * @param op = the label template op
	 */
	private void setLabel(OpTpl op) {
		if (labeldef == null) {
			labeldef = new ArrayList<Integer>();
		}
		int labelindex = (int) op.getInput()[0].getOffset().getReal() + labelbase;
		while (labeldef.size() <= labelindex) {
			labeldef.add(null);
		}
		labeldef.set(labelindex, numOps);
	}

	/**
	 * Make a note of a reference to a label within a
	 * BRANCH or CBRANCH op, so that it can later be resolved
	 * to a relative address.  We assume that the varnode
	 * reference is the first input to the op in question,
	 * so all we need to store is the index of the op
	 */
	abstract void addLabelRef();

	/**
	 * Now that we have seen all label templates and references
	 * convert the collected references into full relative
	 * addresses
	 */
	public abstract void resolveRelatives();

	/**
	 * Now that all pcode has been generated, including special
	 * overrides and injections, ensure that a fallthrough override
	 * adds a final branch to prevent dropping out the bottom.  This
	 * addresses both fall-through cases:
	 * <ul>
	 * <li>last pcode op has fall-through</li>
	 * <li>internal label used to branch beyond last pcode op</li>
	 * </ul>
	 */
	void resolveFinalFallthrough() {
		try {
			if (fallOverride == null || fallOverride.equals(getStartAddress().add(fallOffset))) {
				return;
			}
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}

		VarnodeData dest = new VarnodeData();
		dest.space = fallOverride.getAddressSpace().getPhysicalSpace();
		dest.offset = fallOverride.getOffset();
		dest.size = dest.space.getPointerSize();

		dump(startAddress, PcodeOp.BRANCH, new VarnodeData[] { dest }, 1, null);
	}

	abstract void dump(Address instrAddr, int opcode, VarnodeData[] in, int isize, VarnodeData out);

	private boolean dumpBranchOverride(OpTpl opt) {
		int opcode = opt.getOpcode();
		VarnodeTpl[] inputs = opt.getInput();
		if (opcode == PcodeOp.CALL) {
			OpTpl callopt = new OpTpl(PcodeOp.BRANCH, null, inputs);
			dump(callopt);
			flowOverride = null;
			return true;
		}
		else if (opcode == PcodeOp.CALLIND || opcode == PcodeOp.RETURN) {
			OpTpl callopt = new OpTpl(PcodeOp.BRANCHIND, null, inputs);
			dump(callopt);
			flowOverride = null;
			return true;
		}
		return false;
	}

	private void dumpNullReturn() {

		VarnodeTpl nullAddr =
			new VarnodeTpl(new ConstTpl(const_space), new ConstTpl(ConstTpl.REAL, 0),
				new ConstTpl(ConstTpl.REAL, const_space.getPointerSize()));

		OpTpl retOpt = new OpTpl(PcodeOp.RETURN, null, new VarnodeTpl[] { nullAddr });
		dump(retOpt);
	}

	private boolean dumpCallOverride(OpTpl opt, boolean returnAfterCall) {
		int opcode = opt.getOpcode();
		VarnodeTpl[] inputs = opt.getInput();
		if (opcode == PcodeOp.BRANCH) {
			int offsetType = inputs[0].getOffset().getType();
			if (offsetType == ConstTpl.J_RELATIVE || offsetType == ConstTpl.J_START ||
				offsetType == ConstTpl.J_NEXT) {
				return false;
			}
			OpTpl callopt = new OpTpl(PcodeOp.CALL, null, inputs);
			dump(callopt);
			if (returnAfterCall) {
				dumpNullReturn();
			}
			flowOverride = null;
			return true;
		}
		else if (opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.RETURN) {
			OpTpl callopt = new OpTpl(PcodeOp.CALLIND, null, inputs);
			dump(callopt);
			if (returnAfterCall) {
				dumpNullReturn();
			}
			flowOverride = null;
			return true;
		}
		else if (opcode == PcodeOp.CBRANCH) {
			int offsetType = inputs[0].getOffset().getType();
			if (offsetType == ConstTpl.J_RELATIVE || offsetType == ConstTpl.J_START ||
				offsetType == ConstTpl.J_NEXT) {
				return false;
			}

			//   CBRANCH <dest>,<cond>
			// -- maps to --
			//   tmp = BOOL_NEGATE <cond>
			//   CBRANCH <label>,tmp
			//   CALL <dest>
			//   <label>

			Address tmpAddr = uniqueFactory.getNextUniqueAddress();
			VarnodeTpl tmp = new VarnodeTpl(new ConstTpl(tmpAddr.getAddressSpace()),
				new ConstTpl(ConstTpl.REAL, tmpAddr.getOffset()), inputs[1].getSize());
			int labelIndex = labelcount++;
			VarnodeTpl label = new VarnodeTpl(new ConstTpl(const_space),
				new ConstTpl(ConstTpl.J_RELATIVE, labelIndex), new ConstTpl(ConstTpl.REAL, 8));
			VarnodeTpl dest = inputs[0];
			VarnodeTpl cond = inputs[1];

			OpTpl negOpt = new OpTpl(PcodeOp.BOOL_NEGATE, tmp, new VarnodeTpl[] { cond });
			dump(negOpt);

			OpTpl cbranchOpt = new OpTpl(PcodeOp.CBRANCH, null, new VarnodeTpl[] { label, tmp });
			dump(cbranchOpt);

			OpTpl callOpt = new OpTpl(PcodeOp.CALL, null, new VarnodeTpl[] { dest });
			dump(callOpt);

			if (returnAfterCall) {
				dumpNullReturn();
			}

			OpTpl labelOpt = new OpTpl(PcodeOp.PTRADD, null, new VarnodeTpl[] { label });
			setLabel(labelOpt);

			flowOverride = null;
			return true;
		}
		else if ((opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) && returnAfterCall) {
			dump(opt); // dump original call
			dumpNullReturn();
			flowOverride = null;
			return true;
		}
		return false;
	}

	private boolean dumpReturnOverride(OpTpl opt) {
		int opcode = opt.getOpcode();
		VarnodeTpl[] inputs = opt.getInput();

		if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CALL) {
			int offsetType = inputs[0].getOffset().getType();
			if (offsetType == ConstTpl.J_RELATIVE || offsetType == ConstTpl.J_START ||
				offsetType == ConstTpl.J_NEXT) {
				return false;
			}

			AddressSpace defaultAddressSpace = walker.getCurSpace();
			int ptrSize = defaultAddressSpace.getPointerSize();

			//   BRANCH <dest>  (or CALL)
			// -- maps to --
			//   tmp = COPY &<dest>
			//   RETURN tmp

			Address tmpAddr = uniqueFactory.getNextUniqueAddress();
			VarnodeTpl tmp = new VarnodeTpl(new ConstTpl(tmpAddr.getAddressSpace()),
				new ConstTpl(ConstTpl.REAL, tmpAddr.getOffset()),
				new ConstTpl(ConstTpl.REAL, ptrSize));

			VarnodeTpl destAddr = new VarnodeTpl(new ConstTpl(const_space), inputs[0].getOffset(),
				new ConstTpl(ConstTpl.REAL, ptrSize));

			OpTpl copyOpt = new OpTpl(PcodeOp.COPY, tmp, new VarnodeTpl[] { destAddr });
			dump(copyOpt);

			OpTpl retOpt = new OpTpl(PcodeOp.RETURN, null, new VarnodeTpl[] { tmp });
			dump(retOpt);

			flowOverride = null;
			return true;
		}
		else if (opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.CALLIND) {
			OpTpl callopt = new OpTpl(PcodeOp.RETURN, null, inputs);
			dump(callopt);
			flowOverride = null;
			return true;
		}
		else if (opcode == PcodeOp.CBRANCH) {
			int offsetType = inputs[0].getOffset().getType();
			if (offsetType == ConstTpl.J_RELATIVE || offsetType == ConstTpl.J_START ||
				offsetType == ConstTpl.J_NEXT) {
				return false;
			}

			AddressSpace defaultAddressSpace = walker.getCurSpace();
			int ptrSize = defaultAddressSpace.getPointerSize();

			//   CBRANCH <dest>,<cond>
			// -- maps to --
			//   tmp = BOOL_NEGATE <cond>
			//   CBRANCH <label>,tmp
			//   tmp2 = COPY &<dest>
			//   RETURN <dest>
			//   <label>

			Address tmpAddr = uniqueFactory.getNextUniqueAddress();
			VarnodeTpl tmp = new VarnodeTpl(new ConstTpl(tmpAddr.getAddressSpace()),
				new ConstTpl(ConstTpl.REAL, tmpAddr.getOffset()), inputs[1].getSize());

			tmpAddr = uniqueFactory.getNextUniqueAddress();
			VarnodeTpl tmp2 = new VarnodeTpl(new ConstTpl(tmpAddr.getAddressSpace()),
				new ConstTpl(ConstTpl.REAL, tmpAddr.getOffset()),
				new ConstTpl(ConstTpl.REAL, ptrSize));

			VarnodeTpl destAddr = new VarnodeTpl(new ConstTpl(const_space), inputs[0].getOffset(),
				new ConstTpl(ConstTpl.REAL, ptrSize));

			int labelIndex = labelcount++;
			VarnodeTpl label = new VarnodeTpl(new ConstTpl(const_space),
				new ConstTpl(ConstTpl.J_RELATIVE, labelIndex), new ConstTpl(ConstTpl.REAL, 8));
			VarnodeTpl cond = inputs[1];

			OpTpl negOpt = new OpTpl(PcodeOp.BOOL_NEGATE, tmp, new VarnodeTpl[] { cond });
			dump(negOpt);

			OpTpl cbranchOpt = new OpTpl(PcodeOp.CBRANCH, null, new VarnodeTpl[] { label, tmp });
			dump(cbranchOpt);

			OpTpl copyOpt = new OpTpl(PcodeOp.COPY, tmp2, new VarnodeTpl[] { destAddr });
			dump(copyOpt);

			OpTpl retOpt = new OpTpl(PcodeOp.RETURN, null, new VarnodeTpl[] { tmp2 });
			dump(retOpt);

			OpTpl labelOpt = new OpTpl(PcodeOp.PTRADD, null, new VarnodeTpl[] { label });
			setLabel(labelOpt);

			flowOverride = null;
			return true;
		}
		return false;
	}

	private boolean dumpFlowOverride(OpTpl opt) {
		if (flowOverride == null || opt.getOutput() != null) {
			return false; // only call, branch and return instructions can be affected
		}
		if (flowOverride == FlowOverride.BRANCH) {
			return dumpBranchOverride(opt);
		}
		else if (flowOverride == FlowOverride.CALL) {
			return dumpCallOverride(opt, false);
		}
		else if (flowOverride == FlowOverride.CALL_RETURN) {
			return dumpCallOverride(opt, true);
		}
		else if (flowOverride == FlowOverride.RETURN) {
			return dumpReturnOverride(opt);
		}
		return false;
	}

	/**
	 * Convert a varnode template into a concrete varnode
	 * @param vntpl is the varnode template
	 * @param vn is the resulting concrete varnode
	 */
	private void generateLocation(VarnodeTpl vntpl, VarnodeData vn) {
		vn.space = vntpl.getSpace().fixSpace(walker);
		vn.size = (int) vntpl.getSize().fix(walker);
		if (vn.space == const_space) {
			vn.offset =
				vntpl.getOffset().fix(walker) & ConstTpl.calc_mask[vn.size > 8 ? 8 : vn.size];
		}
		else if (vn.space == uniq_space) {
			vn.offset = vntpl.getOffset().fix(walker) | uniqueoffset;
		}
		else {
			vn.offset = vn.space.truncateOffset(vntpl.getOffset().fix(walker));
		}
	}

	/**
	 * Generate a concrete pointer varnode for a dynamic varnode template
	 * @param vntpl is the VarnodeTpl
	 * @param vn is the resulting concrete varnode
	 * @return the AddressSpace into which the pointer points
	 */
	private AddressSpace generatePointer(VarnodeTpl vntpl, VarnodeData vn) {
		FixedHandle hand = walker.getFixedHandle(vntpl.getOffset().getHandleIndex());
		vn.space = hand.offset_space;
		vn.size = hand.offset_size;
		if (vn.space == const_space) {
			vn.offset = hand.offset_offset & ConstTpl.calc_mask[vn.size];
		}
		else if (vn.space == uniq_space) {
			vn.offset = hand.offset_offset | uniqueoffset;
		}
		else {
			vn.offset = vn.space.truncateOffset(hand.offset_offset);
		}
		return hand.space;
	}

	private void dump(OpTpl opt) {

		VarnodeTpl vn, outvn;
		int isize = opt.getInput().length;

		// First build all the inputs
		for (int i = 0; i < isize; ++i) {
			vn = opt.getInput()[i];
			incache[i] = new VarnodeData();
			if (vn.isDynamic(walker)) {
				dyncache = new VarnodeData[3];
				dyncache[0] = new VarnodeData();
				dyncache[1] = new VarnodeData();
				dyncache[2] = new VarnodeData();
				generateLocation(vn, incache[i]);	// Temporary storage
				dyncache[2].space = incache[i].space;
				dyncache[2].offset = incache[i].offset;
				dyncache[2].size = incache[i].size;
				AddressSpace spc = generatePointer(vn, dyncache[1]);
				dyncache[0].space = const_space;
				dyncache[0].offset = spc.getSpaceID();
				dyncache[0].size = 4;		// Size of spaceid
				dump(startAddress, PcodeOp.LOAD, dyncache, 2, dyncache[2]);
				numOps += 1;
			}
			else {
				generateLocation(vn, incache[i]);
			}
		}
		if ((isize > 0) && (opt.getInput()[0].isRelative())) {
			incache[0].offset += labelbase;
			addLabelRef();
		}
		outvn = opt.getOutput();
		if (outvn != null) {
			outcache = new VarnodeData();
			if (outvn.isDynamic(walker)) {
				if (dyncache == null) {
					dyncache = new VarnodeData[3];
					dyncache[0] = new VarnodeData();
					dyncache[1] = new VarnodeData();
					dyncache[2] = new VarnodeData();
				}
				generateLocation(outvn, outcache);	// Temporary storage
				dump(startAddress, opt.getOpcode(), incache, isize, outcache);
				numOps += 1;
				dyncache[2].space = outcache.space;
				dyncache[2].offset = outcache.offset;
				dyncache[2].size = outcache.size;
				AddressSpace spc = generatePointer(outvn, dyncache[1]);
				dyncache[0].space = const_space;
				dyncache[0].offset = spc.getSpaceID();
				dyncache[0].size = 4;		// Size of spaceid;
				dump(startAddress, PcodeOp.STORE, dyncache, 3, null);
				numOps += 1;
			}
			else {
				generateLocation(outvn, outcache);
				dump(startAddress, opt.getOpcode(), incache, isize, outcache);
				numOps += 1;
			}
		}
		else {
			dump(startAddress, opt.getOpcode(), incache, isize, null);
			numOps += 1;
		}
	}

	private void appendBuild(OpTpl bld, int secnum)
			throws UnknownInstructionException, MemoryAccessException {
		// Recover operand index from build statement
		int index = (int) bld.getInput()[0].getOffset().getReal();
		Symbol sym = walker.getConstructor().getOperand(index).getDefiningSymbol();
		if ((sym == null) || (!(sym instanceof SubtableSymbol))) {
			return;
		}

		walker.pushOperand(index);
		Constructor ct = walker.getConstructor();
		if (secnum >= 0) {
			ConstructTpl construct = ct.getNamedTempl(secnum);
			if (construct == null) {
				buildEmpty(ct, secnum);
			}
			else {
				build(construct, secnum);
			}
		}
		else {
			ConstructTpl construct = ct.getTempl();
			build(construct, -1);
		}
		walker.popOperand();
	}

	/**
	 * Insert the p-code of instruction(s) in the delay slot at this point in the p-code generation for the current instruction
	 * @param op is the DELAYSLOT directive
	 * @throws UnknownInstructionException
	 * @throws MemoryAccessException
	 */
	private void delaySlot(OpTpl op) throws UnknownInstructionException, MemoryAccessException {

		if (inDelaySlot) {
			throw new SleighException(
				"Delay Slot recursion problem for Instruction at " + walker.getAddr());
		}
		inDelaySlot = true;
		Address baseaddr = parsercontext.getAddr();
		int falloffset = parsercontext.getPrototype().getLength();
		int delaySlotByteCnt = parsercontext.getPrototype().getDelaySlotByteCount();
		ParserWalker oldwalker = walker;
		long olduniqueoffset = uniqueoffset;
		int bytecount = 0;
		do {
			Address addr = baseaddr.add(falloffset);
			setUniqueOffset(addr);
			try {
				parsercontext = (SleighParserContext) instcontext.getParserContext(addr);
			}
			catch (UnknownContextException e) {
				throw new UnknownInstructionException(
					"Could not find cached delayslot parser context");
			}
			int len = parsercontext.getPrototype().getLength();
			walker = new ParserWalker(parsercontext);
			walker.baseState();
			build(walker.getConstructor().getTempl(), -1);
			falloffset += len;
			bytecount += len;
		}
		while (bytecount < delaySlotByteCnt);
		walker = oldwalker;				// Restore the tree walk for the base instruction
		parsercontext = walker.getParserContext();
		uniqueoffset = olduniqueoffset;
		inDelaySlot = false;
	}

	/**
	 * Inject the p-code for a different instruction at this point in the p-code generation for current instruction
	 * @param bld is the CROSSBUILD directive containing the section number and address parameters
	 * @param secnum is the section number of the section containing the CROSSBUILD directive
	 * @throws UnknownInstructionException
	 * @throws MemoryAccessException
	 */
	private void appendCrossBuild(OpTpl bld, int secnum)
			throws UnknownInstructionException, MemoryAccessException {
		if (secnum >= 0) {
			throw new SleighException(
				"CROSSBUILD recursion problem for instruction at " + walker.getAddr());
		}
		secnum = (int) bld.getInput()[1].getOffset().getReal();
		VarnodeTpl vn = bld.getInput()[0];
		AddressSpace spc = vn.getSpace().fixSpace(walker);
		Address addr = spc.getTruncatedAddress(vn.getOffset().fix(walker), false);
		// translate the address into the overlayspace if we have an overlayspace.
		if (overlayspace != null) {
			addr = overlayspace.getOverlayAddress(addr);
		}
		ParserWalker oldwalker = walker;
		long olduniqueoffset = uniqueoffset;
		setUniqueOffset(addr);
		try {
			parsercontext = (SleighParserContext) instcontext.getParserContext(addr);
		}
		catch (UnknownContextException e) {
			throw new UnknownInstructionException(
				"Could not find cached crossbuild parser context");
		}

		walker = new ParserWalker(parsercontext, oldwalker.getParserContext());
		walker.baseState();
		Constructor ct = walker.getConstructor();
		ConstructTpl construct = ct.getNamedTempl(secnum);
		if (construct == null) {
			buildEmpty(ct, secnum);
		}
		else {
			build(construct, secnum);
		}
		walker = oldwalker;
		parsercontext = walker.getParserContext();
		uniqueoffset = olduniqueoffset;
	}

	public void build(ConstructTpl construct, int secnum)
			throws UnknownInstructionException, MemoryAccessException {
		if (construct == null) {
			throw new NotYetImplementedException(
				"Semantics for this instruction are not implemented");
		}

		int oldbase = labelbase;	// Recursively save old labelbase
		labelbase = labelcount;
		labelcount += construct.getNumLabels();

		OpTpl[] optpllist = construct.getOpVec();
		for (OpTpl op : optpllist) {
			switch (op.getOpcode()) {
				case PcodeOp.MULTIEQUAL:		// Build placeholder
					appendBuild(op, secnum);
					break;
				case PcodeOp.INDIRECT:			// Delay slot placeholder
					delaySlot(op);
					break;
				case PcodeOp.PTRADD:			// Label placeholder
					setLabel(op);
					break;
				case PcodeOp.PTRSUB:			// Crossbuild placeholder
					appendCrossBuild(op, secnum);
					break;
				default:
					if (inDelaySlot || (flowOverride == null) || !dumpFlowOverride(op)) {
						dump(op);
					}
					break;
			}
		}
		labelbase = oldbase;	// Restore old labelbase
	}

	/**
	 * Build a named p-code section of a constructor that contains only implied BUILD directives
	 * @param ct Constructor to build section for
	 * @param secnum index of the section to be built
	 * @throws MemoryAccessException 
	 * @throws UnknownInstructionException 
	 */
	private void buildEmpty(Constructor ct, int secnum)
			throws UnknownInstructionException, MemoryAccessException {
		int numops = ct.getNumOperands();

		for (int i = 0; i < numops; ++i) {
			TripleSymbol sym = ct.getOperand(i).getDefiningSymbol();
			if ((sym == null) || (!(sym instanceof SubtableSymbol))) {
				continue;
			}

			walker.pushOperand(i);
			ConstructTpl construct = walker.getConstructor().getNamedTempl(secnum);
			if (construct == null) {
				buildEmpty(walker.getConstructor(), secnum);
			}
			else {
				build(construct, secnum);
			}
			walker.popOperand();
		}
	}

	void checkOverlays(int opcode, VarnodeData[] in, int isize, VarnodeData out) {
		if (overlayspace != null) {
			if (uniqueFactory == null) {
				return;
			}
			if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
				int spaceId = (int) in[0].offset;
				AddressSpace space = uniqueFactory.getAddressFactory().getAddressSpace(spaceId);
				if (space.isOverlaySpace()) {
					space = ((OverlayAddressSpace) space).getOverlayedSpace();
					in[0].offset = space.getSpaceID();
				}
			}
			for (int i = 0; i < isize; ++i) {
				VarnodeData v = in[0];
				if (v.space.equals(overlayspace)) {
					v.space = ((OverlayAddressSpace) v.space).getOverlayedSpace();
				}
			}
			if (out != null) {
				if (out.space.equals(overlayspace)) {
					out.space = ((OverlayAddressSpace) out.space).getOverlayedSpace();
				}
			}
		}
	}

	/**
	 * Applies opcode-specific overrides
	 * @param opcode opcode of instruction
	 * @param in input varnodes
	 * @return opcode of modified instruction
	 */
	int checkOverrides(int opcode, VarnodeData[] in) {
		if (override == null) {
			return opcode;
		}

		//If there is an overriding call reference on an indirect call, change it to  
		//to a direct call, unless a call override has already been applied at this instruction
		if (opcode == PcodeOp.CALLIND && !override.isCallOverrideRefApplied()) {
			Address callRef = override.getOverridingReference(RefType.CALL_OVERRIDE_UNCONDITIONAL);
			if (callRef != null) {
				VarnodeData dest = in[0];
				dest.space = callRef.getAddressSpace();
				dest.offset = callRef.getOffset();
				dest.size = dest.space.getPointerSize();
				override.setCallOverrideRefApplied();
				return PcodeOp.CALL;
			}
		}

		//CALLOTHER ops can be overridden with RefType.CALLOTHER_OVERRIDE_CALL 
		//or RefType.CALLOTHER_OVERRIDE_JUMP  
		//Call overrides take precedence over jump overrides
		//override at most one callother pcode op per native instruction
		boolean callOtherOverrideApplied = override.isCallOtherCallOverrideRefApplied() ||
			override.isCallOtherJumpOverrideApplied();
		if (opcode == PcodeOp.CALLOTHER && !callOtherOverrideApplied) {
			Address overrideRef = override.getOverridingReference(RefType.CALLOTHER_OVERRIDE_CALL);
			VarnodeData dest = in[0];
			if (overrideRef != null) {
				dest.space = overrideRef.getAddressSpace();
				dest.offset = overrideRef.getOffset();
				dest.size = dest.space.getPointerSize();
				override.setCallOtherCallOverrideRefApplied();
				return PcodeOp.CALL;
			}
			overrideRef = override.getOverridingReference(RefType.CALLOTHER_OVERRIDE_JUMP);
			if (overrideRef != null) {
				dest.space = overrideRef.getAddressSpace();
				dest.offset = overrideRef.getOffset();
				dest.size = dest.space.getPointerSize();
				override.setCallOtherJumpOverrideRefApplied();
				return PcodeOp.BRANCH;
			}
		}

		// Simple call reference override - grab destination from appropriate reference
		// Only perform reference override if destination function does not have a call-fixup		
		if (opcode == PcodeOp.CALL && !override.isCallOverrideRefApplied() &&
			!override.hasCallFixup(in[0].space.getAddress(in[0].offset))) {
			VarnodeData dest = in[0];
			//call to override.getPrimaryCallReference kept for backward compatibility with
			//old call override mechanism
			//old mechanism has precedence over new
			Address callRef = override.getPrimaryCallReference();
			boolean overridingRef = false;
			if (callRef == null) {
				callRef = override.getOverridingReference(RefType.CALL_OVERRIDE_UNCONDITIONAL);
				overridingRef = true;
			}
			//every call instruction automatically has a call-type reference to the call target
			//we don't want these references to count as overrides - only count as an override
			//via explicitly changing the destination or using a CALL_OVERRIDE_UNCONDITIONAL reference
			if (callRef != null && (overridingRef || actualOverride(dest, callRef))) {
				dest.space = callRef.getAddressSpace();
				dest.offset = callRef.getOffset();
				dest.size = dest.space.getPointerSize();
				override.setCallOverrideRefApplied();
				return PcodeOp.CALL;
			}
		}

		// Fall-through override - alter branch to next instruction
		if (fallOverride != null && (opcode == PcodeOp.CBRANCH || opcode == PcodeOp.BRANCH)) {
			//don't apply fallthrough overrides into the constant space
			if (in[0].space.getType() == AddressSpace.TYPE_CONSTANT) {
				return opcode;
			}
			VarnodeData dest = in[0];
			if (defaultFallAddress.getOffset() == dest.offset) {
				dest.space = fallOverride.getAddressSpace();
				dest.offset = fallOverride.getOffset();
				dest.size = dest.space.getPointerSize();
				return opcode;
			}
		}

		//if there is an overriding jump reference, change a conditional jump to an
		//unconditional jump with the target given by the reference
		if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) &&
			!override.isJumpOverrideRefApplied()) {
			//if the destination varnode is in the const space, it's a pcode-relative branch.
			//these should not be overridden
			if (in[0].space.getType() == AddressSpace.TYPE_CONSTANT) {
				return opcode;
			}
			Address overrideRef =
				override.getOverridingReference(RefType.JUMP_OVERRIDE_UNCONDITIONAL);
			if (overrideRef != null) {
				VarnodeData dest = in[0];
				dest.space = overrideRef.getAddressSpace();
				dest.offset = overrideRef.getOffset();
				dest.size = dest.space.getPointerSize();
				override.setJumpOverrideRefApplied();
				return PcodeOp.BRANCH;
			}
		}
		return opcode;
	}

	// Used to check whether the address from a potentially overriding reference 
	// actually changes the call destination
	private boolean actualOverride(VarnodeData data, Address addr) {
		if (!data.space.equals(addr.getAddressSpace())) {
			return true;
		}
		if (data.offset != addr.getOffset()) {
			return true;
		}
		return false;
	}
}
