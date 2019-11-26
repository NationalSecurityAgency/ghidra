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
 * Created on Feb 9, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;

/**
 * 
 *
 * The InstructionPrototype for sleigh languages.
 * The prototype is unique up to the tree of Constructors.
 * Variations in the bit pattern that none of the Constructor
 * mask/values care about get lumped under the same prototype
 */
public class SleighInstructionPrototype implements InstructionPrototype {
	// Flowflags for resolving flowType
	public final static int RETURN = 0x01;
	public final static int CALL_INDIRECT = 0x02;
	public final static int BRANCH_INDIRECT = 0x04;
	public final static int CALL = 0x08;
	public final static int JUMPOUT = 0x10;
	public final static int NO_FALLTHRU = 0x20;		// op does not fallthru
	public final static int BRANCH_TO_END = 0x40;
	public final static int CROSSBUILD = 0x80;
	public final static int LABEL = 0x100;

	static public class FlowRecord {
		public ConstructState addressnode;		// Constructor state containing destination address of flow
		public OpTpl op;						// The pcode template producing the flow
		public int flowFlags;					// flags associated with this flow		
	}

	static public class FlowSummary {
		public int delay;
		public boolean hasCrossBuilds;
		public ArrayList<FlowRecord> flowState;
		public OpTpl lastop;

		public FlowSummary() {
			delay = 0;
			hasCrossBuilds = false;
			flowState = null;
			lastop = null;
		}
	}

	private SleighLanguage language;
	private boolean isindelayslot;
	private FlowType flowType; // null if instruction has cross-build
	private int[] opresolve; // operand indexes in mnemonic constructor
	private RefType[] opRefTypes;
	private List<FlowRecord> flowStateList; // States of operands which are code addresses
	private int delaySlotByteCnt;

	private boolean hasCrossBuilds;
	private ArrayList<ArrayList<FlowRecord>> flowStateListNamed;

	private final static PcodeOp[] emptyPCode = new PcodeOp[0];
	private final static Object[] emptyObject = new Object[0];
	private final static Address[] emptyFlow = new Address[0];

	private ContextCache contextCache;
//	private InstructionContext instructionContextCache;
	private int length;
	private ConstructState rootState;
	private ConstructState mnemonicState; // state for print mnemonic
	private int hashcode;

	private Mask instrMask;
	private Mask[] operandMasks;

	public SleighInstructionPrototype(SleighLanguage lang, MemBuffer buf,
			ProcessorContextView context, ContextCache cache, boolean inDelaySlot,
			SleighDebugLogger debug) throws UnknownInstructionException, MemoryAccessException {
		this.language = lang;
		this.contextCache = cache;
		this.isindelayslot = inDelaySlot;

		rootState = new ConstructState(null);

		SleighParserContext protoContext = new SleighParserContext(buf, this, context);

		resolve(lang.getRootDecisionNode(), protoContext, debug);
	}

	@Override
	public int getLength() {
		return length;
	}

	ConstructState getMnemonicState() {
		return mnemonicState;
	}

	/**
	 * Cache the Constructor state which represents the base
	 * mnemonic, and the operands to that mnemonic
	 * Cache the operand states for each operand in printing order
	 */
	private void cacheMnemonicState() {
		mnemonicState = rootState;
		Constructor ct = mnemonicState.getConstructor();
		int index = ct.getFlowthruIndex();
		while (index >= 0) {
			mnemonicState = mnemonicState.getSubState(index);
			ct = mnemonicState.getConstructor();
			index = ct.getFlowthruIndex();
		}

		opresolve = ct.getOpsPrintOrder();

		opRefTypes = new RefType[opresolve.length];
		Arrays.fill(opRefTypes, null);

//		for(int j=0;j<opstate.length;++j)	// Transform array to states
//			opstate[j] = getStateOperand(mnemonicstate,opstate[j]);
	}

	@Override
	public boolean hasDelaySlots() {
		return delaySlotByteCnt != 0;
	}

	@Override
	public boolean hasCrossBuildDependency() {
		return hasCrossBuilds;
	}

	private static void addExplicitFlow(ConstructState state, OpTpl op, int flags,
			FlowSummary summary) {
		if (summary.flowState == null)
			summary.flowState = new ArrayList<>();
		FlowRecord res = new FlowRecord();
		summary.flowState.add(res);
		res.flowFlags = flags;
		res.op = op;
		res.addressnode = null;
		VarnodeTpl dest = op.getInput()[0];		// First varnode input contains the destination address
		if ((flags & (JUMPOUT | CALL | CROSSBUILD)) == 0)
			return;
		// If the flow is out of the instruction, store the ConstructState so we can easily calculate address
		if (state == null)
			return;
		if ((flags & CROSSBUILD) != 0) {
			res.addressnode = state;
		}
		else if (dest.getOffset().getType() == ConstTpl.HANDLE) {
			int oper = dest.getOffset().getHandleIndex();
			Constructor ct = state.getConstructor();
			OperandSymbol sym = ct.getOperand(oper);
			if (sym.isCodeAddress()) {
				res.addressnode = state.getSubState(oper);
			}
		}
	}

	/**
	 * Walk the pcode templates in the order they would be emitted.
	 * Collect flowFlags FlowRecords
	 * @param walker the pcode template walker
	 */
	public static FlowSummary walkTemplates(OpTplWalker walker) {
		FlowSummary res = new FlowSummary();
		int destType;
		int flags;

		while (walker.isState()) {
			Object state = walker.nextOpTpl();
			if (state == null) {
				walker.popBuild();
				continue;
			}
			else if (state instanceof Integer) {
				walker.pushBuild(((Integer) state).intValue());
				continue;
			}
			res.lastop = (OpTpl) state;
			switch (res.lastop.getOpcode()) {
				case PcodeOp.PTRSUB:			// encoded crossbuild directive
					res.hasCrossBuilds = true;
					addExplicitFlow(walker.getState(), res.lastop, CROSSBUILD, res);
					break;
				case PcodeOp.BRANCHIND:
					addExplicitFlow(null, res.lastop, BRANCH_INDIRECT | NO_FALLTHRU, res);
					break;
				case PcodeOp.BRANCH:
					destType = res.lastop.getInput()[0].getOffset().getType();
					if (destType == ConstTpl.J_NEXT)
						flags = BRANCH_TO_END;
					else if (destType == ConstTpl.J_START)
						flags = NO_FALLTHRU;
					else if (destType == ConstTpl.J_RELATIVE)
						flags = NO_FALLTHRU;
					else
						flags = JUMPOUT | NO_FALLTHRU;
					addExplicitFlow(walker.getState(), res.lastop, flags, res);
					break;
				case PcodeOp.CBRANCH:
					destType = res.lastop.getInput()[0].getOffset().getType();
					if (destType == ConstTpl.J_NEXT)
						flags = BRANCH_TO_END;
					else if ((destType != ConstTpl.J_START) && (destType != ConstTpl.J_RELATIVE))
						flags = JUMPOUT;
					else
						flags = 0;
					addExplicitFlow(walker.getState(), res.lastop, flags, res);
					break;
				case PcodeOp.CALL:
					addExplicitFlow(walker.getState(), res.lastop, CALL, res);
					break;
				case PcodeOp.CALLIND:
					addExplicitFlow(null, res.lastop, CALL_INDIRECT, res);
					break;
				case PcodeOp.RETURN:
					addExplicitFlow(null, res.lastop, RETURN | NO_FALLTHRU, res);
					break;
				case PcodeOp.PTRADD:			// Encoded label build directive
					addExplicitFlow(null, res.lastop, LABEL, res);
					break;
				case PcodeOp.INDIRECT:			// Encode delayslot
					destType = (int) res.lastop.getInput()[0].getOffset().getReal();
					if (destType > res.delay)
						res.delay = destType;
				default:
					break;

			}
		}
		return res;
	}

	public static FlowType flowListToFlowType(List<FlowRecord> flowstate) {
		if (flowstate == null)
			return RefType.FALL_THROUGH;
		int flags = 0;
		for (FlowRecord rec : flowstate) {
			flags &= ~(NO_FALLTHRU | CROSSBUILD | LABEL);
			flags |= rec.flowFlags;
		}
		return convertFlowFlags(flags);
	}

	/**
	 * Walk the Constructor tree gathering ConstructStates which are flow destinations (flowStateList)
	 * flowFlags and delayslot directives
	 */
	private void cacheTreeInfo() {
		OpTplWalker walker = new OpTplWalker(rootState, -1);
		FlowSummary summary = walkTemplates(walker);

		delaySlotByteCnt = summary.delay;
		hasCrossBuilds = summary.hasCrossBuilds;
		if (summary.flowState != null) {
			flowStateList = summary.flowState;
			flowType = flowListToFlowType(summary.flowState);
		}
		else {
			flowStateList = new ArrayList<>();
			flowType = RefType.FALL_THROUGH;
		}

		flowStateListNamed = null;
		int numsects = language.numSections();
		if (numsects > 0) {
			flowStateListNamed = new ArrayList<>();
			for (int i = 0; i < numsects; ++i) {
				flowStateListNamed.add(null);
				walker = new OpTplWalker(rootState, i);
				summary = walkTemplates(walker);
				flowStateListNamed.set(i, summary.flowState);
			}
		}
	}

	private static FlowType convertFlowFlags(int flowFlags) {

		if ((flowFlags & LABEL) != 0)
			flowFlags |= BRANCH_TO_END;
		flowFlags &= ~(CROSSBUILD | LABEL);
		// NOTE: If prototype has cross-build, flow must be determined dynamically
		switch (flowFlags) { // Convert flags to a standard flowtype
			case 0:
			case BRANCH_TO_END:
				return RefType.FALL_THROUGH;
			case CALL:
				return RefType.UNCONDITIONAL_CALL;
			case CALL | NO_FALLTHRU | RETURN:
				return RefType.CALL_TERMINATOR;
			case CALL_INDIRECT | NO_FALLTHRU | RETURN:
				return RefType.COMPUTED_CALL_TERMINATOR;
			case CALL | BRANCH_TO_END:
				return RefType.CONDITIONAL_CALL; // This could be wrong but doesn't matter much
			case CALL | NO_FALLTHRU | JUMPOUT:
				return RefType.COMPUTED_JUMP;
			case CALL | NO_FALLTHRU | BRANCH_TO_END | RETURN:
				return RefType.UNCONDITIONAL_CALL;
			case CALL_INDIRECT:
				return RefType.COMPUTED_CALL;
			case BRANCH_INDIRECT | NO_FALLTHRU:
				return RefType.COMPUTED_JUMP;
			case BRANCH_INDIRECT | BRANCH_TO_END:
			case BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END:
			case BRANCH_INDIRECT | JUMPOUT | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_COMPUTED_JUMP;
			case CALL_INDIRECT | BRANCH_TO_END:
			case CALL_INDIRECT | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_COMPUTED_CALL;
			case RETURN | NO_FALLTHRU:
				return RefType.TERMINATOR;
			case RETURN | BRANCH_TO_END:
			case RETURN | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_TERMINATOR;
			case JUMPOUT:
				return RefType.CONDITIONAL_JUMP;
			case JUMPOUT | NO_FALLTHRU:
				return RefType.UNCONDITIONAL_JUMP;
			case JUMPOUT | NO_FALLTHRU | BRANCH_TO_END:
				return RefType.CONDITIONAL_JUMP;
			case JUMPOUT | NO_FALLTHRU | RETURN:
				return RefType.JUMP_TERMINATOR;
			case JUMPOUT | NO_FALLTHRU | BRANCH_INDIRECT:
				return RefType.COMPUTED_JUMP; //added for tableswitch in jvm
			case BRANCH_INDIRECT | NO_FALLTHRU | RETURN:
				return RefType.JUMP_TERMINATOR;
			case NO_FALLTHRU:
				return RefType.TERMINATOR;
			case BRANCH_TO_END | JUMPOUT:
				return RefType.CONDITIONAL_JUMP;
			case NO_FALLTHRU | BRANCH_TO_END:
				return RefType.FALL_THROUGH;
			default:
				break;
		}
		return RefType.INVALID;
	}

	void cacheInfo(MemBuffer memBuf, ProcessorContextView context, boolean computeMasks) {
		length = rootState.getLength();
		cacheTreeInfo();
		cacheMnemonicState();
		if (computeMasks) {
			cacheInstructionMasks(memBuf, context);
		}
	}

	private void cacheInstructionMasks(MemBuffer memBuf, ProcessorContextView context) {
		SleighDebugLogger sdl =
			new SleighDebugLogger(memBuf, context, language, SleighDebugMode.MASKS_ONLY);
		if (!sdl.parseFailed()) {
			operandMasks = new Mask[getNumOperands()];
			instrMask = new MaskImpl(sdl.getInstructionMask());
			for (int i = 0; i < operandMasks.length; i++) {
				operandMasks[i] = new MaskImpl(sdl.getOperandValueMask(i));
			}
		}
	}

	@Override
	public int hashCode() {
		return hashcode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		return (hashCode() == obj.hashCode()); // Trust entirely in hash
	}

	@Override
	public Mask getInstructionMask() {
		return instrMask;
	}

	@Override
	public Mask getOperandValueMask(int operandIndex) {
		if (operandMasks == null) {
			return null;
		}
		return operandMasks[operandIndex];
	}

	@Override
	public FlowType getFlowType(InstructionContext context) {
		if (!hasCrossBuilds)
			return flowType;
		int flags = 0;
		try {
			flags = gatherFlags(0, context, -1);
		}
		catch (MemoryAccessException e) {
			return RefType.INVALID;
		}
		catch (UnknownContextException e) {
			return RefType.INVALID;
		}
		return convertFlowFlags(flags);
	}

	@Override
	public int getDelaySlotByteCount() {
		return delaySlotByteCnt;
	}

	@Override
	public int getDelaySlotDepth(InstructionContext context) {
		int delayInstrCnt = 0;
		int byteCnt = 0;
		int offset = getLength();
		if (delaySlotByteCnt == 1) {
			return 1;
		}
		try {
			ReadOnlyProcessorContext roContext =
				new ReadOnlyProcessorContext(context.getProcessorContext());
			while (byteCnt < delaySlotByteCnt) {
				MemBuffer delaymem = new WrappedMemBuffer(context.getMemBuffer(), offset);
				SleighInstructionPrototype proto =
					(SleighInstructionPrototype) language.parse(delaymem, roContext, true);
				int len = proto.getLength();
				offset += len;
				byteCnt += len;
				++delayInstrCnt;
			}
		}
		catch (Exception e) {
		}
		return delayInstrCnt;
	}

	@Override
	public boolean isInDelaySlot() {
		return isindelayslot;
	}

	@Override
	public int getNumOperands() {
		return opresolve.length;
	}

	@Override
	public int getOpType(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length)
			return OperandType.DYNAMIC;

		SleighParserContext protoContext;
		try {
			protoContext = (SleighParserContext) context.getParserContext();
		}
		catch (MemoryAccessException e) {
			return OperandType.DYNAMIC;
		}
		ConstructState opState = mnemonicState.getSubState(opresolve[opIndex]);
		FixedHandle hand = protoContext.getFixedHandle(opState);
		if (hand.isInvalid())
			return OperandType.DYNAMIC;
		int indirect = isIndirect(opresolve[opIndex]) ? OperandType.INDIRECT : 0;
		if (hand.offset_space == null) { // Static handle
			int type = hand.space.getType();
			if (type == AddressSpace.TYPE_REGISTER)
				return OperandType.REGISTER | indirect;
			if (type == AddressSpace.TYPE_CONSTANT)
				return OperandType.SCALAR | indirect;
			OperandSymbol sym = mnemonicState.getConstructor().getOperand(opresolve[opIndex]);
			if (sym.isCodeAddress())
				return (OperandType.ADDRESS | OperandType.CODE | indirect);
			if (type == AddressSpace.TYPE_RAM)
				return (OperandType.ADDRESS | OperandType.DATA | indirect);
		}
		return OperandType.DYNAMIC | indirect;
	}

	private boolean isIndirect(int sleighOpIndex) {
		Constructor constructor = mnemonicState.getConstructor();
		ConstructTpl templ = constructor.getTempl();
		if (templ == null) {
			return false;
		}
		OpTpl[] opVec = templ.getOpVec();
		for (OpTpl opTpl : opVec) {
			int opcode = opTpl.getOpcode();
			if (opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND) {
				VarnodeTpl varnodeTpl = opTpl.getInput()[0];
				ConstTpl space = varnodeTpl.getSpace();
				if (space.getType() == ConstTpl.HANDLE && space.getHandleIndex() == sleighOpIndex) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public Address getFallThrough(InstructionContext context) {
		if (flowType.hasFallthrough()) {
			try {
				return context.getAddress().addNoWrap(getFallThroughOffset(context));
			}
			catch (AddressOverflowException e) {
			}
		}
		return null;
	}

	@Override
	public int getFallThroughOffset(InstructionContext context) {
		if (delaySlotByteCnt <= 0) {
			return getLength();
		}

		try {
			int offset = getLength();
			int bytecount = 0;
			ReadOnlyProcessorContext roContext =
				new ReadOnlyProcessorContext(context.getProcessorContext());
			do {
				MemBuffer delaymem = new WrappedMemBuffer(context.getMemBuffer(), offset);
				SleighInstructionPrototype proto =
					(SleighInstructionPrototype) language.parse(delaymem, roContext, true);
				int len = proto.getLength();
				offset += len;
				bytecount += len;
			}
			while (bytecount < delaySlotByteCnt);
			return offset;
		}
		catch (Exception e) {
			return getLength();
		}
	}

	private int gatherFlags(int curflags, InstructionContext context, int secnum)
			throws MemoryAccessException, UnknownContextException {
		List<FlowRecord> curlist = null;
		if (secnum < 0)
			curlist = flowStateList;
		else if ((flowStateListNamed != null) && (secnum < flowStateListNamed.size()))
			curlist = flowStateListNamed.get(secnum);

		if (curlist == null)
			return curflags;

		for (FlowRecord rec : curlist) {
			if ((rec.flowFlags & CROSSBUILD) != 0) {
				ParserWalker walker =
					new ParserWalker((SleighParserContext) context.getParserContext());
				walker.subTreeState(rec.addressnode);

				VarnodeTpl vn = rec.op.getInput()[0];
				AddressSpace spc = vn.getSpace().fixSpace(walker);
				Address addr = spc.getTruncatedAddress(vn.getOffset().fix(walker), false);
				addr = handleOverlayAddress(context, addr);
				SleighParserContext crosscontext =
					(SleighParserContext) context.getParserContext(addr);
				int newsecnum = (int) rec.op.getInput()[1].getOffset().getReal();
				SleighInstructionPrototype crossproto = crosscontext.getPrototype();
				curflags = crossproto.gatherFlags(curflags, context, newsecnum);
			}
			else {
				curflags &= ~(CROSSBUILD | LABEL | NO_FALLTHRU);
				curflags |= rec.flowFlags;
			}
		}
		return curflags;
	}

	private Address handleOverlayAddress(InstructionContext context, Address addr) {
		AddressSpace addressSpace = context.getAddress().getAddressSpace();
		if (addressSpace.isOverlaySpace()) {
			OverlayAddressSpace ospace = (OverlayAddressSpace) addressSpace;
			addr = ospace.getOverlayAddress(addr);
		}
		return addr;
	}

	/**
	 * Gather all the flow records (perhaps across multiple InstructionPrototypes via crossbuilds) and convert to Addresses
	 * @param res is the resulting flow Addresses
	 * @param parsecontext is the parsing context for the current instruction
	 * @param context is the context for the particular address so crossbuilds can be resolved
	 * @throws MemoryAccessException
	 * @throws UnknownContextException
	 */
	private void gatherFlows(ArrayList<Address> res, SleighParserContext parsecontext,
			InstructionContext context, int secnum)
			throws MemoryAccessException, UnknownContextException {
		List<FlowRecord> curlist = null;
		if (secnum < 0)
			curlist = flowStateList;
		else if ((flowStateListNamed != null) && (secnum < flowStateListNamed.size()))
			curlist = flowStateListNamed.get(secnum);

		if (curlist == null)
			return;

		for (FlowRecord rec : curlist) {
			if ((rec.flowFlags & CROSSBUILD) != 0) {
				ParserWalker walker = new ParserWalker(parsecontext);
				walker.subTreeState(rec.addressnode);

				VarnodeTpl vn = rec.op.getInput()[0];
				AddressSpace spc = vn.getSpace().fixSpace(walker);
				Address addr = spc.getTruncatedAddress(vn.getOffset().fix(walker), false);
				addr = handleOverlayAddress(context, addr);
				SleighParserContext crosscontext =
					(SleighParserContext) context.getParserContext(addr);
				int newsecnum = (int) rec.op.getInput()[1].getOffset().getReal();
				SleighInstructionPrototype crossproto = crosscontext.getPrototype();
				crossproto.gatherFlows(res, crosscontext, context, newsecnum);
			}
			else if ((rec.flowFlags & (JUMPOUT | CALL)) != 0) {
				FixedHandle hand = parsecontext.getFixedHandle(rec.addressnode);
				if (!hand.isInvalid() && hand.offset_space == null) {
					Address addr = getHandleAddr(hand, parsecontext.getAddr().getAddressSpace());
					res.add(addr);
				}
			}
		}
	}

	@Override
	public Address[] getFlows(InstructionContext context) {

		if (flowStateList.size() == 0)
			return emptyFlow;

		ArrayList<Address> addresses = new ArrayList<>();
		try {
			gatherFlows(addresses, (SleighParserContext) context.getParserContext(), context, -1);
		}
		catch (MemoryAccessException e) {
			return emptyFlow;
		}
		catch (UnknownContextException e) {
			return emptyFlow;
		}

		if (addresses.size() == 0)
			return emptyFlow;
		return addresses.toArray(new Address[addresses.size()]);
	}

	@Override
	public String getSeparator(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex > opresolve.length) {
			return null;
		}

		try {
			Constructor ct = mnemonicState.getConstructor();
			return ct.printSeparator(opIndex);
		}
		catch (Exception e) {
			return null;
		}
	}

	@Override
	public ArrayList<Object> getOpRepresentationList(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return null;
		}
		ArrayList<Object> list = new ArrayList<>();

		SleighParserContext protoContext;
		try {
			protoContext = (SleighParserContext) context.getParserContext();
			Constructor ct = mnemonicState.getConstructor();

			OperandSymbol sym = ct.getOperand(opresolve[opIndex]);
			ParserWalker walker = new ParserWalker(protoContext);
			walker.subTreeState(mnemonicState);
			sym.printList(walker, list);
		}
		catch (Exception e) {
		}

		AddressSpace curSpace = context.getAddress().getAddressSpace();
		ArrayList<Object> objList = new ArrayList<>();
		for (Object obj : list) {
			if (obj instanceof Character) {
				objList.add(obj);
			}
			else {
				addHandleObject(curSpace, (FixedHandle) obj, objList);
			}
		}
		return objList;
	}

	OperandSymbol getOperandSymbol(int opIndex, MemBuffer buf, ProcessorContextView context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return null;
		}
		try {
			Constructor ct = mnemonicState.getConstructor();
			return ct.getOperand(opresolve[opIndex]);
		}
		catch (Exception e) {
		}
		return null;
	}

	@Override
	public Address getAddress(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return null;
		}

		FixedHandle hand = null;
		SleighParserContext protoContext;
		try {
			protoContext = (SleighParserContext) context.getParserContext();
			ConstructState opState = mnemonicState.getSubState(opresolve[opIndex]);
			hand = protoContext.getFixedHandle(opState);
			if (hand.isInvalid())
				return null;
		}
		catch (Exception e) {
			return null;
		}
		if ((hand.offset_space == null) && (hand.space.getType() == AddressSpace.TYPE_RAM)) {
			return getHandleAddr(hand, context.getAddress().getAddressSpace());
		}
		return null;
	}

	@Override
	public Scalar getScalar(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return null;
		}

		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();

			ConstructState opState = mnemonicState.getSubState(opresolve[opIndex]);
			FixedHandle hand = protoContext.getFixedHandle(opState);
			if (hand.isInvalid())
				return null;
			if (hand.space.getType() == AddressSpace.TYPE_CONSTANT) {
				int size = hand.size;
				if (size == 0) {
					size = hand.offset_size;
					if (size == 0) {
						size = language.getDefaultSpace().getPointerSize();
					}
				}
				boolean signed = hand.offset_offset < 0;
				return new Scalar(size * 8, hand.offset_offset, signed);
			}
		}
		catch (Exception e) {
		}
		return null;
	}

	@Override
	public Register getRegister(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return null;
		}

		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();
			ConstructState opState = mnemonicState.getSubState(opresolve[opIndex]);
			FixedHandle hand = protoContext.getFixedHandle(opState);
			if (hand.isInvalid())
				return null;
			if (hand.space.getType() == AddressSpace.TYPE_REGISTER) {
				return language.getRegister(hand.space, hand.offset_offset, hand.size);
			}
		}
		catch (Exception e) {
		}
		return null;
	}

	@Override
	public Object[] getOpObjects(int opIndex, InstructionContext context) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return emptyObject;
		}
		List<Object> list = new ArrayList<>();
		for (Object obj : getOpRepresentationList(opIndex, context)) {
			if (!(obj instanceof Character)) {
				list.add(obj);
			}
		}
		Object[] retobj = new Object[list.size()];
		list.toArray(retobj);
		return retobj;
	}

	@Override
	public boolean hasDelimeter(int opIndex) {
		return (opIndex < opresolve.length - 1);
	}

	@Override
	public Object[] getInputObjects(InstructionContext context) {
		PcodeOp[] pcode = null;
		try {
			pcode = getPcode(context, null, null);
		}
		catch (Exception e) {
			return new Object[0];
		}
		HashSet<Object> inlist = new HashSet<>();
		HashSet<Object> outlist = new HashSet<>();
		for (PcodeOp element : pcode) {
			getInputObjects(element, inlist, outlist);
			getResultObject(element, outlist);
		}

		return inlist.toArray(new Object[0]);
	}

	private void getInputObjects(PcodeOp pcode, HashSet<Object> inputObjects,
			HashSet<Object> writtenObjects) {
		Varnode[] varNode = pcode.getInputs();
		int vi = 0;
		// if this is a store or load instruction, skip over address space
		int opID = pcode.getOpcode();
		if (opID == PcodeOp.CALL || opID == PcodeOp.BRANCH) {
			return; // flow only
		}
		if (opID == PcodeOp.CBRANCH) {
			++vi; // ignore flow address
		}
		else if (opID == PcodeOp.STORE) {
			++vi; // ignore space ID
		}
		else if (opID == PcodeOp.LOAD) {
			if (varNode[1].isConstant()) {
				AddressSpace space =
					language.getAddressFactory().getAddressSpace((int) varNode[0].getOffset());
				if (space != null) {
					Address inAddr = space.getAddress(varNode[1].getOffset());
					// check that we didn't write to the location
					if (!writtenObjects.contains(inAddr)) {
						inputObjects.add(inAddr);
					}
					return;
				}
			}
			++vi; // ignore space ID
		}
		for (; vi < varNode.length; vi++) {
			Varnode node = varNode[vi];
			Object obj = getVarnodeObject(node);
			if (obj != null && !writtenObjects.contains(obj)) {
				inputObjects.add(obj);
			}
		}
	}

	@Override
	public Object[] getResultObjects(InstructionContext context) {
		PcodeOp[] pcode = null;
		try {
			pcode = getPcode(context, null, null);
		}
		catch (Exception e) {
			return new Object[0];
		}
		HashSet<Object> results = new HashSet<>();
		for (PcodeOp element : pcode) {
			getResultObject(element, results);
		}

		return results.toArray(new Object[0]);
	}

	private void getResultObject(PcodeOp pcode, HashSet<Object> results) {
		Varnode[] varNode = pcode.getInputs();
		if (pcode.getOpcode() == PcodeOp.STORE) {
			if (varNode[1].isConstant()) {
				AddressSpace space =
					language.getAddressFactory().getAddressSpace((int) varNode[0].getOffset());
				if (space != null) {
					results.add(space.getAddress(varNode[1].getOffset()));
				}
			}
		}
		else {
			Object obj = getVarnodeObject(pcode.getOutput());
			if (obj != null) {
				results.add(obj);
			}
		}
	}

	private Object getVarnodeObject(Varnode node) {
		if (node == null) {
			return null;
		}
		if (node.isConstant()) {
			int bitsize = node.getSize() * 8;
			bitsize = bitsize > 64 ? 64 : bitsize;
			boolean signed = node.getOffset() < 0;
			Scalar scalar = new Scalar(bitsize, node.getOffset(), signed);
			return scalar;
		}
		if (node.isAddress() || node.isRegister()) {
			Register reg = language.getRegister(node.getAddress(), node.getSize());

			return reg != null ? reg : node.getAddress();
		}
		return null;
	}

	@Override
	public PcodeOp[] getPcode(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory) {
		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();
			int fallOffset = getLength();
			if (delaySlotByteCnt > 0) {
				int bytecount = 0;
				do {
					Address addr = context.getAddress().add(fallOffset);
					SleighParserContext delay =
						(SleighParserContext) context.getParserContext(addr);
					int len = delay.getPrototype().getLength();
					fallOffset += len;
					bytecount += len;
				}
				while (bytecount < delaySlotByteCnt);
				protoContext.setDelaySlotLength(bytecount);
			}
			ParserWalker walker = new ParserWalker(protoContext);
			walker.baseState();
			PcodeEmitObjects emit =
				new PcodeEmitObjects(walker, context, fallOffset, override, uniqueFactory);
			emit.build(walker.getConstructor().getTempl(), -1);
			emit.resolveRelatives();
			if (!isindelayslot) {
				emit.resolveFinalFallthrough();
			}
			protoContext.setDelaySlotLength(0);
			return emit.getPcodeOp();
		}
		catch (NotYetImplementedException e) {
			// unimpl
		}
		catch (Exception e) {
			Msg.error(this, "Pcode error at " + context.getAddress() + ": " + e.getMessage());
		}
		PcodeOp[] res = new PcodeOp[1];
		res[0] = new PcodeOp(context.getAddress(), 0, PcodeOp.UNIMPLEMENTED);
		return res;
	}

	@Override
	public PackedBytes getPcodePacked(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory) {
		int fallOffset = getLength();
		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();
			if (delaySlotByteCnt > 0) {
				int bytecount = 0;
				do {
					Address addr = context.getAddress().add(fallOffset);
					SleighParserContext delay =
						(SleighParserContext) context.getParserContext(addr);
					int len = delay.getPrototype().getLength();
					fallOffset += len;
					bytecount += len;
				}
				while (bytecount < delaySlotByteCnt);
				protoContext.setDelaySlotLength(bytecount);
			}
			ParserWalker walker = new ParserWalker(protoContext);
			walker.baseState();
			PcodeEmitPacked emit =
				new PcodeEmitPacked(walker, context, fallOffset, override, uniqueFactory);
			emit.write(PcodeEmitPacked.inst_tag);
			emit.dumpOffset(emit.getFallOffset());

			// Write out the sequence number as a space and an offset
			Address instrAddr = emit.getStartAddress();
			int spcindex = instrAddr.getAddressSpace().getUnique();
			emit.write(spcindex + 0x20);
			emit.dumpOffset(instrAddr.getOffset());

			emit.build(walker.getConstructor().getTempl(), -1);
			emit.resolveRelatives();
			if (!isindelayslot) {
				emit.resolveFinalFallthrough();
			}
			protoContext.setDelaySlotLength(0);
			emit.write(PcodeEmitPacked.end_tag); // Terminate the inst_tag
			return emit.getPackedBytes();
		}
		catch (NotYetImplementedException e) {
			// unimpl
		}
		catch (Exception e) {
			Msg.error(this, "Pcode error at " + context.getAddress() + ": " + e.getMessage());
		}
		PcodeEmitPacked emit = new PcodeEmitPacked();
		emit.write(PcodeEmitPacked.unimpl_tag);
		emit.dumpOffset(length);
		return emit.getPackedBytes();
	}

	@Override
	public PcodeOp[] getPcode(InstructionContext context, int opIndex) {
		if (opIndex < 0 || opIndex >= opresolve.length) {
			return emptyPCode;
		}

		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();
			OperandSymbol sym = mnemonicState.getConstructor().getOperand(opresolve[opIndex]);
			if (sym.getDefiningSymbol() instanceof SubtableSymbol) {
				ParserWalker walker = new ParserWalker(protoContext);
				walker.subTreeState(mnemonicState);
				walker.pushOperand(opresolve[opIndex]);
				PcodeEmitObjects emit = new PcodeEmitObjects(walker);
				emit.build(walker.getConstructor().getTempl(), -1);
				emit.resolveRelatives();
				if (!isindelayslot) {
					emit.resolveFinalFallthrough();
				}
				return emit.getPcodeOp();
			}
		}
		catch (Exception e) {
		}
		return emptyPCode;
	}

	@Override
	public RefType getOperandRefType(int opIndex, InstructionContext context,
			PcodeOverride override, UniqueAddressFactory uniqueFactory) {
		if (opIndex < 0 || opIndex >= opRefTypes.length) {
			return null;
		}

		boolean hasOverride = false;
		if (override != null) {
			// TODO: should call override be considered?
			hasOverride = override.getFlowOverride() != FlowOverride.NONE ||
				override.getFallThroughOverride() != null;
		}

		if (!hasOverride) {
			// try to use cached value
			RefType refType = opRefTypes[opIndex];
			if (refType != null) {
				return refType;
			}
			cacheDefaultOperandRefTypes(context, uniqueFactory);
			return opRefTypes[opIndex];
		}

		// Override exists - unable to use cached value
		SleighParserContext protoContext;
		try {
			protoContext = (SleighParserContext) context.getParserContext();
		}
		catch (MemoryAccessException e) {
			return RefType.DATA;
		}
		PcodeOp[] pcode = getPcode(context, override, uniqueFactory);
		if (pcode == null || pcode.length == 0) {
			return RefType.DATA;
		}

		ConstructState opState = mnemonicState.getSubState(opresolve[opIndex]);
		FixedHandle opHandle = protoContext.getFixedHandle(opState);

		if (opHandle == null || opHandle.isInvalid()) {
			return null;
		}
		RefType refType = RefType.DATA;
		if (opHandle.isDynamic()) {
			refType = getDynamicOperandRefType(opHandle, pcode);
		}
		else {
			Varnode var = opHandle.getStaticVarnode();
			if (var != null) {
				refType = getStaticOperandRefType(var, pcode);
			}
		}
		return refType;
	}

	private void cacheDefaultOperandRefTypes(InstructionContext context,
			UniqueAddressFactory uniqueFactory) {

		// Resolve handles for each operand
		SleighParserContext protoContext;
		try {
			protoContext = (SleighParserContext) context.getParserContext();
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}
		PcodeOp[] pcode = getPcode(context, null, uniqueFactory);
		if (pcode == null || pcode.length == 0) {
			return;
		}
		FixedHandle[] opHandles = new FixedHandle[opresolve.length];
		for (int index = 0; index < opresolve.length; index++) {
			ConstructState opState = mnemonicState.getSubState(opresolve[index]);
			opHandles[index] = protoContext.getFixedHandle(opState);
		}
		for (int index = 0; index < opHandles.length; index++) {
			if (opHandles[index] == null || opHandles[index].isInvalid() ||
				opRefTypes[index] != null) {
				continue;
			}
			RefType refType = RefType.DATA;
			if (opHandles[index].isDynamic()) {
				refType = getDynamicOperandRefType(opHandles[index], pcode);
			}
			else {
				Varnode var = opHandles[index].getStaticVarnode();
				if (var != null) {
					refType = getStaticOperandRefType(var, pcode);
				}
			}
			opRefTypes[index] = refType;
			for (int n = index + 1; n < opHandles.length; n++) {
				if (opHandles[index].equals(opHandles[n])) {
					opRefTypes[n] = refType;
				}
			}
		}
	}

	private RefType getStaticOperandRefType(Varnode var, PcodeOp[] pcode) {
		if (var.isConstant()) {
			return RefType.DATA;
		}
		boolean isRead = false;
		boolean isWrite = false;
		for (PcodeOp element : pcode) {
			Varnode[] inputs = element.getInputs();
			switch (element.getOpcode()) {

				case PcodeOp.BRANCHIND:
				case PcodeOp.CALLIND:
				case PcodeOp.RETURN:
					if (inputs[0].equals(var)) {
						return RefType.INDIRECTION;
					}
					break;

				case PcodeOp.BRANCH:
					if (inputs[0].equals(var)) {
						return RefType.UNCONDITIONAL_JUMP;
					}
					break;

				case PcodeOp.CBRANCH:
					if (inputs[0].equals(var)) {
						return RefType.CONDITIONAL_JUMP;
					}
					break;

				case PcodeOp.CALL:
					if (inputs[0].equals(var)) {
						return RefType.UNCONDITIONAL_CALL;
					}
					break;

			}
			if (!var.isUnique()) {
				if (var.equals(element.getOutput())) {
					isWrite = true;
				}
				for (Varnode input : element.getInputs()) {
					if (var.equals(input)) {
						isRead = true;
					}
				}
			}
		}
		if (isRead && isWrite) {
			return RefType.READ_WRITE;
		}
		if (isRead) {
			return RefType.READ;
		}
		if (isWrite) {
			return RefType.WRITE;
		}
		return RefType.DATA;
	}

	private RefType getDynamicOperandRefType(FixedHandle hand, PcodeOp[] pcode) {
		Varnode offset = hand.getDynamicOffset();
		Varnode staticAddr = hand.getStaticVarnode();
		Varnode temp = hand.getDynamicTemp();
		boolean isRead = false;
		boolean isWrite = false;
		for (PcodeOp element : pcode) {
			Varnode[] inputs = element.getInputs();
			switch (element.getOpcode()) {

				case PcodeOp.LOAD:
					if (temp.equals(element.getOutput())) {
						isRead = true;
					}
					break;

				case PcodeOp.STORE:
					if (offset.equals(inputs[1]) && temp.equals(inputs[2])) {
						isWrite = true;
					}
					break;

				case PcodeOp.BRANCHIND:
				case PcodeOp.CALLIND:
				case PcodeOp.RETURN:
					if (inputs[0].equals(temp) || inputs[0].equals(staticAddr)) {
						return RefType.INDIRECTION;
					}
					break;

				case PcodeOp.BRANCH:
					if (inputs[0].equals(staticAddr)) {
						return RefType.UNCONDITIONAL_JUMP;
					}
					break;

				case PcodeOp.CBRANCH:
					if (inputs[0].equals(staticAddr)) {
						return RefType.CONDITIONAL_JUMP;
					}
					break;

				case PcodeOp.CALL:
					if (inputs[0].equals(staticAddr)) {
						return RefType.UNCONDITIONAL_CALL;
					}
					break;

			}
		}
		if (isRead && isWrite) {
			return RefType.READ_WRITE;
		}
		if (isRead) {
			return RefType.READ;
		}
		if (isWrite) {
			return RefType.WRITE;
		}
		return RefType.DATA;
	}

	@Override
	public String getMnemonic(InstructionContext context) {

		try {
			SleighParserContext protoContext = (SleighParserContext) context.getParserContext();
			ParserWalker walker = new ParserWalker(protoContext);
			walker.baseState();
			String mnemonic = walker.getConstructor().printMnemonic(walker);
			if (this.isindelayslot) {
				mnemonic = "_" + mnemonic;
			}
			return mnemonic;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		Msg.error(this, "*****  SLEIGH instruction PROBLEM at " + context.getAddress());
		return "UNKNOWN";
	}

	private void resolve(DecisionNode root, SleighParserContext protoContext,
			SleighDebugLogger debug) throws MemoryAccessException, UnknownInstructionException {

		if (debug != null && debug.isVerboseEnabled()) {
			debug.append("resolving constructor for instruction bytes at: " +
				protoContext.getAddr().toString(true) + "\n");
		}

		ParserWalker walker = new ParserWalker(protoContext);
		walker.baseState();
		walker.setOffset(0);
		Constructor ct = root.resolve(walker, debug);		// Base constructor
		walker.setConstructor(ct);
		ct.applyContext(walker, debug);

		while (walker.isState()) {
			ct = walker.getConstructor();
			int oper = walker.getOperand();
			int numoper = ct.getNumOperands();
			while (oper < numoper) {
				OperandSymbol sym = ct.getOperand(oper);
				int off = walker.getOffset(sym.getOffsetBase()) + sym.getRelativeOffset();
				walker.allocateOperand();
				walker.setOffset(off);
				TripleSymbol tsym = sym.getDefiningSymbol();
				if (tsym != null) {
					if (debug != null) {
						debug.append(tsym.getName() + ": resolving...\n");
						debug.indent();
						debug.startPatternGroup(sym.getName());
					}
					Constructor subct = tsym.resolve(walker, debug);
					if (subct != null) {
						walker.setConstructor(subct);
						subct.applyContext(walker, debug);
						if (debug != null)
							debug.indent();
						break;
					}
					if (debug != null) {
						walker.popOperand();
						debug.dumpFixedHandle(sym.getName(), tsym, walker, language);
						walker.pushOperand(oper);
						debug.endPatternGroup(true);
						debug.dropIndent();
					}
				}
				else {
					if (debug != null)
						debug.dumpPattern(sym, walker);
				}
				walker.setCurrentLength(sym.getMinimumLength());
				walker.popOperand();
				oper += 1;
			}
			if (oper >= numoper) {			// Finished processing constructor
				walker.calcCurrentLength(ct.getMinimumLength(), numoper);
				walker.popOperand();
				if (debug != null) {
					if (walker.isState()) {
						debug.dropIndent();
						debug.endPatternGroup(true);
						debug.dropIndent();
					}
				}

			}
		}

		hashcode = rootState.hashCode();
		if (isindelayslot) {
			hashcode += 0xFABFAB;
		}
	}

	private void resolveHandles(SleighParserContext protoContext) throws MemoryAccessException {
		ParserWalker walker = new ParserWalker(protoContext);
		walker.baseState();
		while (walker.isState()) {
			Constructor ct = walker.getConstructor();
			int oper = walker.getOperand();
			int numoper = ct.getNumOperands();
			while (oper < numoper) {
				OperandSymbol sym = ct.getOperand(oper);
				walker.pushOperand(oper);		// Descend into node
				TripleSymbol triple = sym.getDefiningSymbol();
				if (triple != null) {
					if (triple instanceof SubtableSymbol) {
						break;
					}
					FixedHandle handle = walker.getParentHandle();
					triple.getFixedHandle(handle, walker);
				}
				else { // Must be an expression
					PatternExpression patexp = sym.getDefiningExpression();
					long res = patexp.getValue(walker);
					FixedHandle hand = walker.getParentHandle();
					hand.space = protoContext.getConstSpace();
					hand.offset_space = null;
					hand.offset_offset = res;
					hand.size = 0;
				}
				walker.popOperand();
				oper += 1;
			}
			if (oper >= numoper) {
				ConstructTpl templ = ct.getTempl();
				if (templ != null) {
					HandleTpl res = templ.getResult();
					if (res != null) // Pop up handle to containing operand
						res.fix(walker.getParentHandle(), walker);
					else
						walker.getParentHandle().setInvalid();
				}
				walker.popOperand();
			}
		}
	}

	/**
	 * Reconstruct the ParserContext's internal packed context array and its list of global ContextSet directives
	 * by walking a previously resolved ConstructState tree
	 * @param protoContext is the SleighParserContext containing the tree and holding the context results
	 * @param debug
	 * @throws MemoryAccessException
	 */
	private void reconstructContext(SleighParserContext protoContext, SleighDebugLogger debug)
			throws MemoryAccessException {
		ParserWalker walker = new ParserWalker(protoContext);
		walker.baseState();
		while (walker.isState()) {
			Constructor ct = walker.getConstructor();
			if (ct != null) {
				int oper = walker.getOperand();
				int numoper = ct.getNumOperands();
				if (oper == 0)		// Upon first entry to this Constructor
					ct.applyContext(walker, debug); // Apply its context changes
				if (oper < numoper) {
					walker.pushOperand(oper);
					continue;
				}
			}
			walker.popOperand();
		}
	}

	private boolean addHandleObject(AddressSpace curSpace, FixedHandle handle,
			ArrayList<Object> list) {
		if (handle.isInvalid()) {
			return false;
		}
		int type = handle.space.getType();
		if (type == AddressSpace.TYPE_REGISTER) {
			Register reg;
			reg = language.getRegister(handle.space, handle.offset_offset, handle.size);
			if (reg == null) {
				list.add("<BAD_register_" + handle.offset_offset + ":" + handle.size + ">");
			}
			else {
				list.add(reg);
			}
			return true;
		}
		else if (type == AddressSpace.TYPE_CONSTANT) {
			Scalar sc;
			int size = handle.size;
			if (size == 0) {
				size = handle.offset_size;
				if (size == 0) {
					size = language.getDefaultSpace().getPointerSize();
				}
			}
			boolean signed = handle.offset_offset < 0;
			sc = new Scalar(size * 8, handle.offset_offset, signed);
			list.add(sc);
			return true;
		}
		else if (type == AddressSpace.TYPE_RAM) {
			if (handle.offset_space == null) {
				Address addr = getHandleAddr(handle, curSpace);
				if (addr != null) {
					if (addr.getAddressSpace().hasMappedRegisters()) {
						Register reg = language.getRegister(addr, handle.size);
						if (reg != null) {
							list.add(reg);
							return true;
						}
					}
					list.add(addr);
					return true;
				}
			}
			// could be simply taking the value of a register as an address
			else if (handle.offset_space.getType() == AddressSpace.TYPE_REGISTER) {
				Register reg = language.getRegister(handle.offset_space, handle.offset_offset,
					handle.offset_size);
				list.add(reg);
				return true;
			}

		}
		return false;
	}

	private Address getHandleAddr(FixedHandle hand, AddressSpace curSpace) {

		if (hand.isInvalid() || hand.space.getType() == AddressSpace.TYPE_UNIQUE ||
			hand.offset_space != null) {
			return null;
		}
		Address newaddr = hand.space.getTruncatedAddress(hand.offset_offset, false);

		newaddr = newaddr.getPhysicalAddress();

		// if we are in an address space, translate it
		if (curSpace.isOverlaySpace()) {
			newaddr = curSpace.getOverlayAddress(newaddr);
		}
		return newaddr;
	}

	@Override
	public SleighParserContext getParserContext(MemBuffer buf,
			ProcessorContextView processorContext) throws MemoryAccessException {
		SleighParserContext newContext = new SleighParserContext(buf, this, processorContext);
		reconstructContext(newContext, null);
		resolveHandles(newContext);

		return newContext;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.lang.InstructionPrototype#getPseudoParserContext(ghidra.program.model.address.Address, ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContextView)
	 */
	@Override
	public ParserContext getPseudoParserContext(Address addr, MemBuffer buffer,
			ProcessorContextView processorContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException, MemoryAccessException {
		ReadOnlyProcessorContext roContext = new ReadOnlyProcessorContext(processorContext);
		int offset = (int) addr.subtract(buffer.getAddress());
		MemBuffer nearbymem = new WrappedMemBuffer(buffer, offset);
		SleighInstructionPrototype proto =
			(SleighInstructionPrototype) language.parse(nearbymem, roContext, true);
		SleighParserContext newContext =
			new SleighParserContext(nearbymem, proto, processorContext);
		reconstructContext(newContext, null);
		resolveHandles(newContext);
		return newContext;
	}

	ConstructState getRootState() {
		return rootState;
	}

	ContextCache getContextCache() {
		return contextCache;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	/**
	 * Used for testing and diagnostics: list the constructor line numbers used to resolve this
	 * encoding
	 * 
	 * This includes braces to describe the tree structure
	 * @see AssemblyResolvedConstructor#dumpConstructorTree()
	 * @return the constructor tree
	 */
	public String dumpConstructorTree() {
		return rootState.dumpConstructorTree();
	}
}
