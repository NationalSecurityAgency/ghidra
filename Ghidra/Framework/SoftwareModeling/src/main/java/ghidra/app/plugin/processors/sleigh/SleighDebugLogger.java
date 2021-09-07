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
package ghidra.app.plugin.processors.sleigh;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighParserContext.ContextSet;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.app.plugin.processors.sleigh.pattern.PatternBlock;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.StringUtilities;

/**
 * <code>SleighDebugLogger</code> provides the ability to obtain detailed instruction
 * parse details.
 */
public class SleighDebugLogger {

	public enum SleighDebugMode {
		VERBOSE, MASKS_ONLY
	}

	private StringBuffer buffer = new StringBuffer();
	private int indentLevel = 0;
	private String indent = "";
	private boolean atLineStart = true;

//	private Program program;
//	private Address start;
	private Register contextBaseRegister;
	private MemBuffer buf;
	private SleighDebugMode mode;

	private PatternGroup mainGroup = new PatternGroup(null, null);
	private Map<String, PatternGroup> mainSubGroups = new HashMap<String, PatternGroup>();
	private PatternGroup currentGroup = mainGroup;
	private int currentDepth = 0;

	private byte[] instructionMask;
	private List<byte[]> operandMasks = new ArrayList<byte[]>();

	private ProcessorContextView context;
	private SleighInstructionPrototype prototype;
	private InstructionContext instrContext;
	private byte[] bytes;

	/**
	 * Performs a parse debug at the specified memory location within program.
	 * @param buf the memory buffer
	 * @param context the processor context
	 * @param language the sleigh language
	 * @param mode the sleigh debug mode
	 * @throws IllegalArgumentException if program language provider is not Sleigh
	 */
	public SleighDebugLogger(MemBuffer buf, ProcessorContextView context, Language language,
			SleighDebugMode mode) {
		this.buf = buf;
		this.context = context;
		this.mode = mode;

		if (!(context instanceof MyProcessorContextView)) {
			this.context = new MyProcessorContextView(context);
		}

		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException(
				"unsupport language provider: " + language.getClass().getSimpleName());
		}

		ContextCache contextCache = new ContextCache();
		contextBaseRegister = language.getContextBaseRegister();
		if (contextBaseRegister != Register.NO_CONTEXT) {
			contextCache.registerVariable(contextBaseRegister);
		}

		if (mode == SleighDebugMode.VERBOSE) {
			append("\nNOTE: bitrange's number leftmost/most-significant bit as 0 (zero).\n");
			append("      This bit numbering agrees with the context field specification\n");
			append("      but differs from token field specification.  The bit correspondence\n");
			append("      for token fields depends upon the specific token size/endianess and\n");
			append("      current byte-offset of pattern matcher.\n\n");

			int contextSize = contextCache.getContextSize();
			if (contextSize != 0) {
				int[] contextBytes = new int[contextSize];
				contextCache.getContext(context, contextBytes);
				append("initial context bits: ");
				append(contextBytes, -1, 0);
				append("\n");
			}
		}

		try {
			prototype = new SleighInstructionPrototype((SleighLanguage) language, buf, context,
				contextCache, false, this);

			prototype.cacheInfo(buf, context, false);

			instrContext = new DebugInstructionContext();

			bytes = new byte[prototype.getLength()];
			buf.getBytes(bytes, 0);

			if (mode == SleighDebugMode.VERBOSE) {

				dumpFinalGlobalSets();

				append("\nPrototype parse successful: ");
				append(getPrototypeRepresentation(prototype, instrContext));
				append("\nInstruction length = " + prototype.getLength() + " bytes");
			}
		}
		catch (Exception e) {
			indentLevel = 0;
			indent = getIndent();
			append("\nPrototype parse failed: " + e.getMessage());
			prototype = null;
		}
	}

	/**
	 * Performs a parse debug at the specified memory location within program.
	 * @param program the program the memory location is found in
	 * @param start the start address of the memory location
	 * @param mode the sleigh debug mode
	 * @throws IllegalArgumentException if program language provider is not Sleigh
	 */
	public SleighDebugLogger(Program program, Address start, SleighDebugMode mode) {
		this(new MemoryBufferImpl(program.getMemory(), start),
			new MyProcessorContextView(program.getProgramContext(), start), program.getLanguage(),
			mode);
	}

	private class DebugInstructionContext implements InstructionContext {

		private ParserContext parserContext;

		@Override
		public Address getAddress() {
			return buf.getAddress();
		}

		@Override
		public ProcessorContextView getProcessorContext() {
			return context;
		}

		@Override
		public MemBuffer getMemBuffer() {
			return buf;
		}

		@Override
		public ParserContext getParserContext() throws MemoryAccessException {
			if (parserContext == null) {
				parserContext = prototype.getParserContext(buf, context);
			}
			return parserContext;
		}

		@Override
		public ParserContext getParserContext(Address instructionAddress)
				throws UnknownContextException, MemoryAccessException {
			if (instructionAddress.equals(buf.getAddress())) {
				return getParserContext();
			}
			append("Warning! ignored request for instruction context at " + instructionAddress);
			return null;
		}

	}

	/**
	 * @return true if constructed for verbose logging
	 */
	public boolean isVerboseEnabled() {
		return mode == SleighDebugMode.VERBOSE;
	}

	/**
	 * @return true if a parse error was detected, otherwise false is returned.
	 * The methods getMaskedBytes() and getInstructionMask() should
	 * only be invoked if this method returns false.
	 */
	public boolean parseFailed() {
		return prototype == null;
	}

	/**
	 * Get list of constructor names with line numbers.
	 * Any debug mode may be used.
	 * @return list
	 */
	public List<String> getConstructorLineNumbers() {

		List<String> list = new ArrayList<String>();
		if (prototype == null) {
			return list;
		}
		try {
			SleighParserContext pos = prototype.getParserContext(buf, context);
			ParserWalker walker = new ParserWalker(pos);
			walker.baseState();
			dumpSymbolLineNumbers(list, walker);
		}
		catch (Exception e) {
			// ignore
		}
		return list;
	}

	private void dumpSymbolLineNumbers(List<String> list, ParserWalker walker)
			throws MemoryAccessException, UnknownInstructionException {

		Constructor ct = walker.getConstructor();
		String tableName = ct.getParent().getName();
		List<String> printPieces = ct.getPrintPieces();
		String name = printPieces.size() == 0 ? "\n" : printPieces.get(0);
		if (!"instruction".equals(tableName) || name.startsWith("\n")) {
			name = tableName;
		}

		list.add(name + "(" + ct.getSourceFile() + ":" + Integer.toString(ct.getLineno()) + ")");

		int flowthruindex = ct.getFlowthruIndex();
		if (flowthruindex != -1) {
			Symbol sym = ct.getOperand(flowthruindex).getDefiningSymbol();
			if (sym instanceof SubtableSymbol) {
				walker.pushOperand(flowthruindex);
				dumpSymbolLineNumbers(list, walker);
				walker.popOperand();
				return;
			}
		}

		int numOperands = ct.getNumOperands();
		for (int i = 0; i < numOperands; i++) {
			OperandSymbol sym = ct.getOperand(i);
			TripleSymbol tsym = sym.getDefiningSymbol();
			if (tsym != null) {
				walker.pushOperand(i);
				Constructor subct = walker.getConstructor();
				if (subct != null) {
// 					subct.applyContext(protoContext, newOpState, this);     // Do we really need this???
					dumpSymbolLineNumbers(list, walker);
				}
				walker.popOperand();
			}
		}
	}

	/**
	 * Append a binary formatted integer value with the specified range of bits
	 * bracketed to the log.  A -1 value for both startbit and bitcount disable the
	 * bit range bracketing. 
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param value integer value
	 * @param startbit identifies the first most-significant bit within the
	 * bracketed range (left-most value bit is bit-0, right-most value bit is bit-31)
	 * @param bitcount number of bits included within range
	 */
	public void append(int value, int startbit, int bitcount) {
		if (!isVerboseEnabled()) {
			return;
		}
		byte[] bytes = new byte[4];
		for (int n = 3; n >= 0; n--) {
			bytes[n] = (byte) value;
			value >>>= 8;
		}
		append(bytes, startbit, bitcount);
	}

	/**
	 * Append a binary formatted integer array with the specified range of bits
	 * bracketed to the log.  A -1 value for both startbit and bitcount disable the
	 * bit range bracketing.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param value integer array
	 * @param startbit identifies the first most-significant bit within the
	 * {@literal bracketed range (left-most value[0] bit is bit-0, right-most value[n] bit is bit-<32(n+1)-1> ).}
	 * @param bitcount number of bits included within range
	 */
	public void append(int[] value, int startbit, int bitcount) {
		if (!isVerboseEnabled()) {
			return;
		}
		byte[] bytes = new byte[value.length * 4];
		for (int i = 0; i < value.length; i++) {
			int v = value[i];
			int baseIndex = i * 4;
			for (int n = 3; n >= 0; n--) {
				bytes[baseIndex + n] = (byte) v;
				v >>>= 8;
			}
		}
		append(bytes, startbit, bitcount);
	}

	/**
	 * Append a binary formatted byte array with the specified range of bits
	 * bracketed to the log.  A -1 value for both startbit and bitcount disable the
	 * bit range bracketing.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param value byte array
	 * @param startbit identifies the first most-significant bit within the
	 * {@literal bracketed range (left-most value[0] bit is bit-0, right-most value[n] bit is bit-<8(n+1)-1> ).}
	 * @param bitcount number of bits included within range
	 */
	public void append(byte[] value, int startbit, int bitcount) {
		if (!isVerboseEnabled()) {
			return;
		}
		int startByte = startbit / 8;
		startbit = startbit % 8;
		int endbit = (startbit + bitcount - 1);
		int endByte = startByte + (endbit / 8);
		endbit = endbit % 8;

		for (int i = 0; i < value.length; i++) {
			String byteStr = StringUtilities.pad(Integer.toBinaryString(value[i] & 0xff), '0', 8);
			if (startbit >= 0) {
				if (endByte == i) {
					byteStr =
						byteStr.substring(0, endbit + 1) + ")" + byteStr.substring(endbit + 1);
				}
				if (startByte == i) {
					byteStr = byteStr.substring(0, startbit) + "(" + byteStr.substring(startbit);
				}
			}
			append(byteStr);
			if (i < (value.length - 1)) {
				append(".");
			}
		}
	}

	/**
	 * Append message string to log buffer.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param str message string
	 */
	public void append(String str) {
		if (!isVerboseEnabled()) {
			return;
		}
		int index = str.indexOf('\n');
		while (index >= 0) {
			checkLineStart();
			buffer.append(str.substring(0, index + 1));
			str = str.substring(index + 1);
			atLineStart = true;
			index = str.indexOf('\n');
		}
		if (str.length() != 0) {
			checkLineStart();
			buffer.append(str);
		}
	}

	private void checkLineStart() {
		if (atLineStart) {
			buffer.append(indent);
			atLineStart = false;
		}
	}

	/**
	 * Shift log indent right
	 */
	public void indent() {
		++indentLevel;
		indent = getIndent();
	}

	public void indent(int levels) {
		indentLevel += levels;
		indent = getIndent();
	}

	/**
	 * Shift log indent left
	 */
	public void dropIndent() {
		if (indentLevel > 0) {
			--indentLevel;
			indent = getIndent();
		}
	}

	public void dropIndent(int levels) {
		if (indentLevel > 0) {
			indentLevel -= levels;
			if (indentLevel < 0) {
				indentLevel = 0;
			}
			indent = getIndent();
		}
	}

	private String getIndent() {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < indentLevel; i++) {
			buf.append("   ");
		}
		return buf.toString();
	}

	/**
	 * Return log text
	 */
	@Override
	public String toString() {
		return buffer.toString();
	}

	/**
	 * Dump constructor details to the log
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param subtableName constructor name
	 * @param c constructor
	 */
	void dumpConstructor(String subtableName, Constructor c) {
		if (!isVerboseEnabled()) {
			return;
		}
		if (subtableName != null) {
			append(" " + subtableName);
		}
		else {
			SubtableSymbol parent = c.getParent();
			if (parent != null) {
				String name = parent.getName();
				if (!"instruction".equals(name)) {
					append(" " + name);
				}
			}
		}
		append(": ");
		append("{line# ");
		append(Integer.toString(c.getLineno()));
		append("} ");
		List<String> printPieces = c.getPrintPieces();
		if (printPieces.size() == 0) {
			for (int i = 0; i < c.getNumOperands(); i++) {
				if (i != 0) {
					append(", ");
				}
				OperandSymbol operand = c.getOperand(i);
				append("<");
				append(operand.getName());
				append(">");
			}
		}
		else {
			for (String piece : printPieces) {
				if (piece.startsWith("\n")) {
					int symIndex = piece.charAt(1) - 'A';
					OperandSymbol sym = c.getOperand(symIndex);
					append("<");
					append(sym.getName());
					append(">");
				}
				else {
					append(piece);
				}
			}
		}
		append("\n");
	}

	/**
	 * Dump fixed handle associated with a constructor symbol to the log.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param name
	 * @param definingSymbol
	 * @param pos
	 * @param subState
	 * @param language
	 * @throws MemoryAccessException
	 */
	void dumpFixedHandle(String name, TripleSymbol definingSymbol, ParserWalker walker,
			Language language) throws MemoryAccessException {

		if (!isVerboseEnabled()) {
			return;
		}

		append(name);
		append(": ");

		FixedHandle hand = new FixedHandle();
		definingSymbol.getFixedHandle(hand, walker);

		if (hand.space.getType() == AddressSpace.TYPE_CONSTANT) {
			append("constant ");
			try {
				Scalar s = new Scalar(8 * hand.size, hand.offset_offset);
				append(s.toString(16, false, false, "0x", ""));
			}
			catch (Exception e) {
				append("Bad Value: " + e.getMessage());
			}
		}
		else {
			Address addr = hand.space.getAddress(hand.offset_offset);
			Register reg = language.getRegister(addr, hand.size);
			if (reg != null) {
				append("register ");
				append(reg.getName());
			}
			else {
				append("memory ");
				append(addr.toString(true));
			}
		}
		append(" (size:");
		append(Integer.toString(hand.size));
		append(")\n");
	}

	/**
	 * Dump pattern details to the log.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param sym
	 * @param pos
	 * @param subState
	 * @throws MemoryAccessException
	 */
	void dumpPattern(OperandSymbol sym, ParserWalker walker) throws MemoryAccessException {
		if (!isVerboseEnabled()) {
			return;
		}
		String name = sym.getName();
		PatternExpression definingExpression = sym.getDefiningExpression();

//		int offset;
//		int i = sym.getOffsetBase();
		// if i<0, i.e. the offset of the operand is
		// constructor relative, it is possible that the
		// branch corresponding to the operand has not
		// been constructed yet. Context expressions
		// are evaluated BEFORE the constructor's branches
		// are created. So we have to calculate the
		// offset explicitly

//		if (i < 0) {
//			offset = subState.getParent().getOffset() + sym.getRelativeOffset();
//		}
//		else {
//			offset = subState.getOffset();
//		}

		append(name);
		append(": ");
		append(definingExpression.getClass().getSimpleName());
		append(" = ");

		try {
			Scalar s =
				new Scalar(32, definingExpression.getValue(walker), isSigned(definingExpression));
			append(s.toString(16, false, true, "0x", ""));
		}
		catch (Exception e) {
			append("Bad Value: " + e.getMessage());
		}
		append("\n");
	}

	/**
	 * Dump context pattern details.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param maskvec
	 * @param valvec
	 * @param byteOffset
	 * @param pos
	 */
	public void dumpContextPattern(int[] maskvec, int[] valvec, int byteOffset,
			SleighParserContext pos) {
		if (!isVerboseEnabled()) {
			return;
		}
		if (contextBaseRegister == null) {
			return;
		}

		assert (maskvec.length == valvec.length);

		// build-up RegisterValue byte array which contains mask bytes starting at index 0 followed by the value bytes

		int[] currentValue = new int[(contextBaseRegister.getMinimumByteSize() + 3) / 4];
		for (int i = 0; i < currentValue.length; i++) {
			currentValue[i] = pos.getContextBytes(i * 4, 4);
		}
		byte[] maskActualValue = new byte[currentValue.length * 4 * 2];
		System.arraycopy(getBytes(currentValue), 0, maskActualValue, maskActualValue.length / 2,
			maskActualValue.length / 2);

		int vecByteCnt =
			Math.min(contextBaseRegister.getMinimumByteSize() - byteOffset, maskvec.length * 4);

		byte[] maskPatternValue = new byte[2 * contextBaseRegister.getMinimumByteSize()];
		System.arraycopy(getBytes(valvec), 0, maskPatternValue,
			(maskPatternValue.length / 2) + byteOffset, vecByteCnt);

		byte[] mask = getBytes(maskvec);
		System.arraycopy(mask, 0, maskActualValue, byteOffset, vecByteCnt);
		System.arraycopy(mask, 0, maskPatternValue, byteOffset, vecByteCnt);

		RegisterValue actualValue = new RegisterValue(contextBaseRegister, maskActualValue);
		RegisterValue matchValue = new RegisterValue(contextBaseRegister, maskPatternValue);

		indent(4);
		int baseRegSize = contextBaseRegister.getMinimumByteSize() * 8;
		for (Register reg : contextBaseRegister.getChildRegisters()) {
			RegisterValue childMatchValue = matchValue.getRegisterValue(reg);
			RegisterValue childActualValue = actualValue.getRegisterValue(reg);
			if (childMatchValue.hasAnyValue()) {
				BigInteger actual = childActualValue.getUnsignedValueIgnoreMask();
				BigInteger match = childMatchValue.getUnsignedValueIgnoreMask();
				String partialMatch = childMatchValue.hasValue() ? "" : "*";
				String matchStr = match.equals(actual) ? " Match"
						: (" Failed (=0x" + Long.toHexString(actual.longValue()) + ")");
				int msb = baseRegSize - reg.getLeastSignificatBitInBaseRegister() - 1;
				int lsb = msb - reg.getBitLength() + 1;
				append(partialMatch + reg.getName() + "(" + lsb + "," + msb + ") == 0x" +
					Long.toHexString(match.longValue()) + matchStr);
				append("\n");
			}
		}
		dropIndent(4);
	}

	/**
	 * Dump transient context setting details.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param pos instruction context
	 * @param num 4-byte offset within base context register for mask and value
	 * @param value 4-byte context value
	 * @param mask 4-byte context mask
	 */
	public void dumpContextSet(SleighParserContext pos, int num, int value, int mask) {

		if (!isVerboseEnabled()) {
			return;
		}

		int[] currentValue = new int[(contextBaseRegister.getMinimumByteSize() + 3) / 4];
		for (int i = 0; i < currentValue.length; i++) {
			currentValue[i] = pos.getContextBytes(i * 4, 4);
		}
		currentValue[num] = (currentValue[num] & (~mask)) | (mask & value); // combine with current value using mask
		byte[] maskActualValue = new byte[currentValue.length * 4 * 2];
		System.arraycopy(getBytes(currentValue), 0, maskActualValue, maskActualValue.length / 2,
			maskActualValue.length / 2);
		int byteOffset = num * 4;
		System.arraycopy(getBytes(new int[] { mask }), 0, maskActualValue, byteOffset, 4);

		RegisterValue actualValue = new RegisterValue(contextBaseRegister, maskActualValue);

		indent(2);
		int baseRegSize = contextBaseRegister.getMinimumByteSize() * 8;
		for (Register reg : contextBaseRegister.getChildRegisters()) {
			RegisterValue childActualValue = actualValue.getRegisterValue(reg);
			if (childActualValue.hasAnyValue()) {
				BigInteger actual = childActualValue.getUnsignedValueIgnoreMask();
				int msb = baseRegSize - reg.getLeastSignificatBitInBaseRegister() - 1;
				int lsb = msb - reg.getBitLength() + 1;
				append("Set " + reg.getName() + "(" + lsb + "," + msb + ") = 0x" +
					Long.toHexString(actual.longValue()) + "\n");
			}
		}
		dropIndent(2);
	}

	/**
	 * Dump globalset details.  The target address is currently not included in the log.
	 * NOTE: Method has no affect unless constructed with VERBOSE logging mode.
	 * @param pos
	 * @param state
	 * @param sym
	 * @param num
	 * @param mask
	 * @param value
	 * @throws MemoryAccessException
	 */
	public void dumpGlobalSet(SleighParserContext pos, ConstructState state, TripleSymbol sym,
			int num, int mask, int value) throws MemoryAccessException {

		if (!isVerboseEnabled()) {
			return;
		}

		// TODO: state is not fully resolved making it impossible to
		// extract fixed handle (i.e., context address) from symbol

		dumpGlobalSet(state, num, mask, value, null);
	}

	private void dumpGlobalSet(ConstructState state, int num, int mask, int value,
			Address setAddr) {

		byte[] maskActualValue = new byte[contextBaseRegister.getMinimumByteSize() * 2];
		int byteOffset = num * 4;
		System.arraycopy(getBytes(new int[] { value }), 0, maskActualValue,
			(maskActualValue.length / 2) + byteOffset, 4);
		System.arraycopy(getBytes(new int[] { mask }), 0, maskActualValue, byteOffset, 4);

		RegisterValue actualValue = new RegisterValue(contextBaseRegister, maskActualValue);

		String msg = "Commit future value" + (setAddr != null ? (" at " + setAddr) : "") + ": ";

		indent(2);
		int baseRegSize = contextBaseRegister.getMinimumByteSize() * 8;
		for (Register reg : contextBaseRegister.getChildRegisters()) {
			RegisterValue childActualValue = actualValue.getRegisterValue(reg);
			if (childActualValue.hasAnyValue()) {
				BigInteger actual = childActualValue.getUnsignedValueIgnoreMask();
				int msb = baseRegSize - reg.getLeastSignificatBitInBaseRegister() - 1;
				int lsb = msb - reg.getBitLength() + 1;

				append(msg + reg.getName() + "(" + lsb + "," + msb + ") = 0x" +
					Long.toHexString(actual.longValue()) + "\n");
			}
		}
		dropIndent(2);
	}

	private void dumpFinalGlobalSets() throws MemoryAccessException {
		SleighParserContext protoContext = prototype.getParserContext(buf, context);
		ParserWalker walker = new ParserWalker(protoContext);
		Iterator<ContextSet> contextCommits = protoContext.getContextCommits();
		while (contextCommits.hasNext()) {
			ContextSet set = contextCommits.next();
			walker.subTreeState(set.point);
			FixedHandle hand = new FixedHandle();
			// FIXME: review after Chris has checked the SleighParserContext.applyCommits method
			set.sym.getFixedHandle(hand, walker);
			// TODO: this is a hack. Addresses that are computed end up in the
			// constant space and we must factor-in the wordsize.
			long offset = hand.offset_offset;
			AddressSpace curSpace = buf.getAddress().getAddressSpace();
			if (hand.space.getType() == AddressSpace.TYPE_CONSTANT) {
				offset = offset * curSpace.getAddressableUnitSize();
			}
			Address address = curSpace.getAddress(offset);
			dumpGlobalSet(set.point, set.num, set.mask, set.value, address);
		}
	}

	private byte[] getBytes(int[] ints) {
		byte[] bytes = new byte[ints.length * 4];
		for (int i = 0; i < ints.length; i++) {
			int baseIndex = i * 4;
			int val = ints[i];
			bytes[baseIndex + 3] = (byte) val;
			val >>= 8;
			bytes[baseIndex + 2] = (byte) val;
			val >>= 8;
			bytes[baseIndex + 1] = (byte) val;
			val >>= 8;
			bytes[baseIndex] = (byte) val;
		}
		return bytes;
	}

	private boolean isSigned(PatternExpression definingExpression) {
		if (definingExpression instanceof TokenField) {
			return ((TokenField) definingExpression).hasSignbit();
		}
		if (definingExpression instanceof ContextField) {
			return ((ContextField) definingExpression).hasSignbit();
		}
		if (definingExpression instanceof BinaryExpression) {
			BinaryExpression binaryExpr = (BinaryExpression) definingExpression;
			return isSigned(binaryExpr.getLeft()) || isSigned(binaryExpr.getRight());
		}
		return false;
	}

	//
	// The following methods are used to accumulate the pattern
	// which uniquely matches the target instruction
	//

	/**
	 * Start new pattern group for a specific sub-table.  
	 * A null can correspond to a top-level constructor or 
	 * low level complex pattern (AND, OR).  All committed unnamed groups 
	 * with the same parent group will be combined.
	 * @param name group name or null for unnamed group
	 */
	public void startPatternGroup(String name) {
		PatternGroup newGroup = new PatternGroup(currentGroup, name);
		if (currentGroup == mainGroup && name != null) { // FIXME !!!!!!!!!!!!!!!!!!!!
			// keep main sub-groups
			mainSubGroups.put(name, newGroup);
		}
		currentGroup = newGroup;
		++currentDepth;
	}

	/**
	 * Terminate the current pattern group
	 * @param commit if false group will be discarded, if true group will be retained
	 */
	public void endPatternGroup(boolean commit) {
//append(">>> " + (commit ? "keep" : "discard" ) + " group: " + currentGroup.name + "\n");
		PatternGroup parent = currentGroup.getParent();
		if (commit) {
			parent.add(currentGroup);
		}
		currentGroup = parent;
		--currentDepth;
	}

	/**
	 * Add instruction bit pattern to the current pattern group.
	 * @param offset base offset at which the specified maskvalue
	 * can be applied.
	 * @param maskvalue pattern mask/value
	 */
	public void addInstructionPattern(int offset, PatternBlock maskvalue) {
		currentGroup.add(new InstructionBitPattern(offset, maskvalue));
	}

	/**
	 * Add instruction context pattern to the current pattern group.
	 * @param maskvalue pattern mask/value
	 */
	public void addContextPattern(PatternBlock maskvalue) {
		// TODO: not implemented
	}

	private void buildMasks() {
		if (prototype == null || currentDepth != 0) {
			throw new IllegalStateException("Pattern is not complete");
		}
		if (instructionMask != null) {
			return;
		}

		instructionMask = mainGroup.getMask(prototype.getLength());

		for (int i = 0; i < getNumOperands(); i++) {

			byte[] opMask = buildOperandMask(i);
			operandMasks.add(opMask);

			// ensure that operand mask bits are not included in instruction mask
			clearBits(instructionMask, opMask);
		}

	}

	private void clearBits(byte[] destMask, byte[] clearSrcMask) {
		for (int i = 0; i < destMask.length; i++) {
			destMask[i] &= ~clearSrcMask[i];
		}
	}

	private byte[] buildOperandMask(int opIndex) {
		byte[] mask = new byte[instructionMask.length];
//		DumbMemBufferImpl buf = new DumbMemBufferImpl(program.getMemory(), start);
		OperandSymbol sym = prototype.getOperandSymbol(opIndex, buf, context);
		if (sym == null) {
			return mask;
		}
		ConstructState mnemonicState = prototype.getMnemonicState();
		combineOperandMask(mnemonicState, sym, mask);

		boolean emptyMask = true;
		for (byte element : mask) {
			if (element != 0) {
				emptyMask = false;
				break;
			}
		}

		if (emptyMask) {
			// attempt to steal operand symbol pattern bits from instruction mask
			// if operand value bits not identified above
			PatternGroup symGroup = mainSubGroups.get(sym.getName());
			if (symGroup != null) {
				mask = symGroup.getMask(mask.length);
			}
		}

		return mask;
	}

	/**
	 * Returns the instruction bit mask which identifies those bits used to uniquely identify
	 * the instruction (includes addressing modes, generally excludes register selector bits
	 * associated with attaches or immediate values used in for semantic values only).
	 * @throws IllegalStateException if prototype parse failed
	 * @see #getFormattedInstructionMask(int) getFormattedInstructionMask(-1)
	 */
	public byte[] getInstructionMask() {
		buildMasks();
		return instructionMask;
	}

	/**
	 * Return general/operand bit mask formatted as a String
	 * @param opIndex operand index or -1 for mnemonic mask
	 * @return bit mask string
	 */
	public String getFormattedInstructionMask(int opIndex) {
		byte[] mask = opIndex < 0 ? getInstructionMask() : getOperandValueMask(opIndex);
		return getFormattedBytes(mask);
	}

	/**
	 * Return general/operand bit values formatted as a String
	 * @param opIndex operand index or -1 for mnemonic bit values
	 * @return bit value string
	 */
	public String getFormattedMaskedValue(int opIndex) {
		byte[] mask = opIndex < 0 ? getInstructionMask() : getOperandValueMask(opIndex);
		byte[] value = getMaskedBytes(mask);
		return getFormattedBytes(value);
	}

	/**
	 * Convenience method for formatting bytes as a bit sequence
	 * @param value byte array
	 * @return binary formatted bytes
	 */
	public static String getFormattedBytes(byte[] value) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < value.length; i++) {
			String byteStr = StringUtilities.pad(Integer.toBinaryString(value[i] & 0xff), '0', 8);
			buf.append(byteStr);
			if (i < (value.length - 1)) {
				buf.append(" ");
			}
		}
		return buf.toString();
	}

	/**
	 * Get the number of operands for the resulting prototype
	 * @return operand count
	 * @throws IllegalStateException if prototype parse failed
	 */
	public int getNumOperands() {
		if (prototype == null) {
			throw new IllegalStateException("Pattern is not complete");
		}
		return prototype.getNumOperands();
	}

	/**
	 * Apply an appropriate mask for the resulting instruction bytes
	 * to obtain the corresponding masked bytes.
	 * @param mask instruction, operand or similarly sized mask
	 * @return masked instruction bytes
	 */
	public byte[] getMaskedBytes(byte[] mask) {
		if (prototype == null) {
			throw new IllegalStateException("Pattern is not complete");
		}
		if (mask.length != bytes.length) {
			throw new IllegalArgumentException("inappropriate mask");
		}
		byte[] result = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			result[i] = (byte) (mask[i] & bytes[i]);
		}
		return result;
	}

	/**
	 * Get the byte value mask corresponding to the specified operand.
	 * @param opIndex operand index within the instruction representation
	 * @return byte mask or null if operand does not have a corresponding sub-constructor or attach
	 * @throws IllegalStateException if prototype parse failed
	 * @throws IndexOutOfBoundsException if opIndex is not a valid operand index
	 */
	public byte[] getOperandValueMask(int opIndex) {
		buildMasks();
		return operandMasks.get(opIndex);
	}

	private void combineOperandMask(ConstructState state, OperandSymbol sym, byte[] mask) {
		PatternExpression patternExpression = null;
		int hand = sym.getIndex();
		TripleSymbol triple = sym.getDefiningSymbol();
		if (triple != null) {
			if (triple instanceof SubtableSymbol) {
				ConstructState subState = state.getSubState(hand);
				combineSymbolMask(subState, mask);
			}
			else {
				patternExpression = triple.getPatternExpression();
			}
		}
		else {
			patternExpression = sym.getDefiningExpression();
		}

		if (sym.getOffsetBase() < 0) {
			combinePatternMask(state, patternExpression,
				state.getOffset() + sym.getRelativeOffset(), mask);
		}
		else {
			ConstructState subState = state.getSubState(hand);
			combinePatternMask(subState, patternExpression, subState.getOffset(), mask);
		}
	}

	private void combinePatternMask(ConstructState state, PatternExpression patternExpression,
			int patternOffset, byte[] mask) {
		if (patternExpression instanceof UnaryExpression) {
			combinePatternMask(state, ((UnaryExpression) patternExpression).getUnary(),
				patternOffset, mask);
		}
		else if (patternExpression instanceof BinaryExpression) {
			combinePatternMask(state, ((BinaryExpression) patternExpression).getLeft(),
				patternOffset, mask);
			combinePatternMask(state, ((BinaryExpression) patternExpression).getRight(),
				patternOffset, mask);
		}
		else if (patternExpression instanceof OperandValue) {
			OperandValue opVal = (OperandValue) patternExpression;
			Constructor c = opVal.getConstructor();
			int opIndex = opVal.getIndex();
			combineOperandMask(state, c.getOperand(opIndex), mask);
		}
		else if (patternExpression instanceof TokenField) {
			TokenField tf = (TokenField) patternExpression;
			//System.out.println("token: " + tf.getByteStart() + "," + tf.getByteEnd() + " " + tf.getBitStart() + "," + tf.getBitEnd());

			int size = tf.getByteEnd() + 1;

			int startByteIndex = tf.getByteStart(); // - (tf.getBitStart() / 8);
			int endByteIndex = size - 1; // - (tf.getBitStart() / 8);
			int startBit = tf.getBitStart() % 8;
			int endBit = tf.getBitEnd() % 8;
			boolean bigEndian = buf.isBigEndian();
			for (int i = startByteIndex; i <= endByteIndex; i++) {
				int firstBit = 0;
				int lastBit = 7;
				if (i == endByteIndex) {
					if (bigEndian) {
						firstBit = startBit;
					}
					else {
						lastBit = endBit;
					}
				}
				if (i == startByteIndex) {
					if (bigEndian) {
						lastBit = endBit;
					}
					else {
						firstBit = startBit;
					}
				}
				byte byteMask = (byte) ((0xff >> (7 - lastBit + firstBit)) << firstBit);
				mask[i + patternOffset] |= byteMask;
			}
		}
	}

	private void combineSymbolMask(ConstructState constructState, byte[] mask) {
		Constructor c = constructState.getConstructor();
		for (String piece : c.getPrintPieces()) {
			if (!piece.startsWith("\n")) {
				continue;
			}
			int opIndex = piece.charAt(1) - 'A';
			combineOperandMask(constructState, c.getOperand(opIndex), mask);
		}
	}

	private static class PatternGroup extends ArrayList<Object> {
		private static final long serialVersionUID = 1L;
		private String name;
		private PatternGroup parent;

		PatternGroup(PatternGroup parent, String name) {
			this.parent = parent;
			this.name = name;
		}

		String getName() {
			return name;
		}

		String getPathname() {
			if (parent == null) {
				return "";
			}
			if (name == null) {
				return null;
			}
			String parentPath = parent.getPathname();
			if (parentPath == null) {
				return null;
			}
			if (parentPath.length() != 0) {
				parentPath += ".";
			}
			return parentPath + name;
		}

		PatternGroup getParent() {
			return parent;
		}

		byte[] getMask(int length) {
			byte[] mask = new byte[length];
			for (Object child : this) {
				if (child instanceof PatternGroup) {
					combine((PatternGroup) child, mask);
				}
				else if (child instanceof InstructionBitPattern) {
					combine((InstructionBitPattern) child, mask);
				}
			}
			return mask;
		}

		private void combine(PatternGroup group, byte[] mask) {
			byte[] groupMask = group.getMask(mask.length);
			for (int i = 0; i < mask.length; i++) {
				mask[i] |= groupMask[i];
			}
		}

		private void combine(InstructionBitPattern instructionBitPattern, byte[] mask) {
			byte[] patternMask = instructionBitPattern.getMask(mask.length);
			for (int i = 0; i < mask.length; i++) {
				mask[i] |= patternMask[i];
			}
		}

		@Override
		public String toString() {
			int subGroupCnt = 0;
			int patternCnt = 0;
			for (Object child : this) {
				if (child instanceof PatternGroup) {
					++subGroupCnt;
				}
				else if (child instanceof InstructionBitPattern) {
					++patternCnt;
				}
			}
			return (name != null ? name : "<null>") + ": patterns=" + patternCnt + " symbols=" +
				subGroupCnt;
		}
	}

	private static class InstructionBitPattern {
		private int offset;
		private PatternBlock maskvalue;

		InstructionBitPattern(int offset, PatternBlock maskvalue) {
			this.offset = offset;
			this.maskvalue = maskvalue;
		}

		byte[] getMask(int length) {
			return getBytes(maskvalue.getMaskVector(), length);
		}

		private byte[] getBytes(int[] value, int byteLength) {
			byte[] bytes = new byte[byteLength];
			for (int i = 0; i < value.length; i++) {
				int v = value[i];
				int baseIndex = i * 4;
				for (int n = 3; n >= 0; n--) {
					int index = baseIndex + n + offset;
					if (index < byteLength) {
						bytes[index] = (byte) v;
					}
					v >>>= 8;
				}
			}
			return bytes;
		}
	}

	private static String getPrototypeRepresentation(SleighInstructionPrototype proto,
			InstructionContext instrContext) {
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append(proto.getMnemonic(instrContext));
		int n = proto.getNumOperands();
		for (int i = 0; i < n; i++) {
			stringBuffer.append(i == 0 ? " " : ",");
			stringBuffer.append(getDefaultOperandRepresentation(proto, i, instrContext));
		}
		return stringBuffer.toString();
	}

	private static String getDefaultOperandRepresentation(SleighInstructionPrototype proto,
			int opIndex, InstructionContext instrContext) {

		ArrayList<Object> opList = proto.getOpRepresentationList(opIndex, instrContext);
		if (opList == null) {
			return "<UNSUPPORTED>";
		}
		StringBuffer strBuf = new StringBuffer();
		for (Object opElem : opList) {
			if (opElem instanceof Address) {
				Address opAddr = (Address) opElem;
				strBuf.append("0x");
				strBuf.append(opAddr.toString(false));
			}
			else {
				strBuf.append(opElem.toString());
			}
		}
		return strBuf.toString();
	}

	private static class MyProcessorContextView implements ProcessorContextView {

		private ProgramContext programContext;
		private Address address;
		private ProcessorContextView originalContext;

		MyProcessorContextView(ProgramContext programContext, Address address) {
			this.programContext = programContext;
			this.address = address;
		}

		MyProcessorContextView(ProcessorContextView originalContext) {
			this.originalContext = originalContext;
		}

		@Override
		public Register getBaseContextRegister() {
			return programContext.getBaseContextRegister();
		}

		@Override
		public Register getRegister(String name) {
			if (originalContext != null) {
				return originalContext.getRegister(name);
			}
			return programContext.getRegister(name);
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (originalContext != null) {
				return originalContext.getRegisterValue(register);
			}
			return programContext.getRegisterValue(register, address);
		}

		@Override
		public List<Register> getRegisters() {
			if (originalContext != null) {
				return originalContext.getRegisters();
			}
			return programContext.getRegisters();
		}

		@Override
		public BigInteger getValue(Register register, boolean signed) {
			if (originalContext != null) {
				return originalContext.getValue(register, signed);
			}
			return programContext.getValue(register, address, signed);
		}

		@Override
		public boolean hasValue(Register register) {
			if (originalContext != null) {
				return originalContext.hasValue(register);
			}
			RegisterValue registerValue = programContext.getRegisterValue(register, address);
			return registerValue != null && registerValue.hasValue();
		}

	}

}
