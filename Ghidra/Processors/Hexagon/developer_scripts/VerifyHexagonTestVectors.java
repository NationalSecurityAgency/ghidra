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
//Verify Hexagon test vectors with external .s file
//@category Languages

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class VerifyHexagonTestVectors extends GhidraScript {

	Memory memory;
	Listing listing;
	BookmarkManager bookmarkMgr;

	Map<String, Mismatch> mismatchMap = new HashMap<String, Mismatch>();

	List<Symbol> labels;

	@Override
	protected void run() throws Exception {

		if (currentProgram == null ||
			!"Hexagon".equals(currentProgram.getLanguage().getProcessor().toString())) {
			popup("Current program is not a Hexagon binary!");
			return;
		}

		memory = currentProgram.getMemory();
		listing = currentProgram.getListing();
		bookmarkMgr = currentProgram.getBookmarkManager();

		buildRegisterRenameMap();

		buildLabelList(); // original label use should be replaced by address

		File tvFile = askFile("Choose Hexagon Test Vector .s File", "Open");
		if (tvFile == null) {
			return;
		}

		OrigInstructionEnumeration origInstrEnumeration = new OrigInstructionEnumeration(tvFile);
		GhidraInstructionEnumeration ghidraInstrEnumeration = new GhidraInstructionEnumeration();

		OrigInstruction nextOrigInstr = null;
		GhidraInstruction nextGhidraInstr = null;
		while (true) {

			if (nextOrigInstr == null && origInstrEnumeration.hasMoreElements()) {
				nextOrigInstr = origInstrEnumeration.nextElement();
			}

			if (nextGhidraInstr == null && ghidraInstrEnumeration.hasMoreElements()) {
				nextGhidraInstr = ghidraInstrEnumeration.nextElement();
			}

			if (nextOrigInstr == null) {
				if (nextGhidraInstr == null) {
					break; // done
				}
				markError(nextGhidraInstr.addr, "Sync Error", "Ran out of test vectors early");
				Msg.showError(this, null, "Test Vector Sync Error",
					"Ran out of test vectors early at " + nextGhidraInstr.addr);
				break;
			}

			if (nextGhidraInstr == null) {
				Msg.showError(this, null, "Test Vector Sync Error",
					"Ran out of instruction memory early " + tvFile.getName() + ":" +
						nextOrigInstr.lineNo);
				break;
			}

			if (!"nop".equals(nextOrigInstr.instr)) {
				// skip injected nop
				// NOTE: this may cause endloop's to be lost
				while ("nop".equals(nextGhidraInstr.instr)) {
					if (ghidraInstrEnumeration.hasMoreElements()) {
						nextGhidraInstr = ghidraInstrEnumeration.nextElement();
					}
					else {
						break;
					}
				}
			}

			if (nextOrigInstr.hasAssignment()) {
				if (nextGhidraInstr.mnemonic != null &&
					nextOrigInstr.instr.replace(" ", "").indexOf(nextGhidraInstr.mnemonic) >= 0) {
					nextGhidraInstr.assumeAssignment(nextOrigInstr.isMemStore());
				}
			}

			String origInstr = nextOrigInstr.toString().replace(" ", "").toUpperCase();
			String ghidraInstr = nextGhidraInstr.toString(true).replace(" ", "").toUpperCase();
			if (!origInstr.equals(ghidraInstr)) {
				String key = origInstr + ghidraInstr;
				Mismatch mismatch = mismatchMap.get(key);
				if (mismatch != null) {
					++mismatch.count;
				}
				else {
					mismatch = new Mismatch(nextOrigInstr, nextGhidraInstr);
					mismatchMap.put(key, mismatch);
				}
			}

			nextOrigInstr = null;
			nextGhidraInstr = null;

		}

		ArrayList<Mismatch> list = new ArrayList<Mismatch>();
		list.addAll(mismatchMap.values());
		Collections.sort(list, new Comparator<Mismatch>() {

			@Override
			public int compare(Mismatch arg0, Mismatch arg1) {
				return arg0.origInstr.lineNo - arg1.origInstr.lineNo;
			}
		});

		for (Mismatch mismatch : list) {

			String lineNo =
				StringUtilities.pad(Integer.toString(mismatch.origInstr.lineNo), ' ', 5);
			String instr = StringUtilities.pad(mismatch.origInstr.toString(), ' ', 50);

			String tail = "";
			if (mismatch.count > 1) {
				tail = "  (" + mismatch.count + " occurances)";
			}

			System.out.println(
				lineNo + ": " + instr + "  >?> " + mismatch.ghidraInstr.addr.toString() + ": " +
					mismatch.ghidraInstr.toString(true) + tail);

		}
	}

	private void buildLabelList() {
		labels = new ArrayList<Symbol>();
		for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(false)) {
			if (s.getSymbolType() == SymbolType.LABEL) {
				labels.add(s);
			}
		}
	}

	private class Mismatch {

		int count = 1;
		OrigInstruction origInstr;
		GhidraInstruction ghidraInstr;

		Mismatch(OrigInstruction origInstr, GhidraInstruction ghidraInstr) {
			this.origInstr = origInstr;
			this.ghidraInstr = ghidraInstr;
		}
	}

	private static final long R_REG_BASE_ADDR = 0; // 0-31
	private static final long C_REG_BASE_ADDR = 0x200; // 0-13,24-29
	private static final long G_REG_BASE_ADDR = 0x400; // 0-3, 24-29
	private static final long S_REG_BASE_ADDR = 0x800; // 0-63

	private Map<String, String> regRenameMap = new HashMap<String, String>();

	private void buildRegisterRenameMap() {
		addRegisterRange(R_REG_BASE_ADDR, 0, 31, "R");
		addRegisterRange(C_REG_BASE_ADDR, 0, 13, "C");
		addRegisterRange(C_REG_BASE_ADDR, 24, 29, "C");
		addRegisterRange(G_REG_BASE_ADDR, 0, 3, "G");
		addRegisterRange(G_REG_BASE_ADDR, 24, 29, "G");
		addRegisterRange(S_REG_BASE_ADDR, 0, 63, "S");
	}

	private void addRegisterRange(long baseOffset, int startIndex, int endIndex, String regPrefix) {
		AddressFactory addrFactory = currentProgram.getAddressFactory();
		AddressSpace regSpace = addrFactory.getRegisterSpace();
		Language lang = currentProgram.getLanguage();
		for (int i = startIndex; i < (endIndex + 1); i++) {
			Address regAddr = regSpace.getAddress(baseOffset + ((i - startIndex) * 4));
			Register reg = lang.getRegister(regAddr, 4);
			if (reg == null) {
				throw new AssertException("Register expected at " + regAddr.toString(true));
			}
			String defaultName = regPrefix + i;
			//System.out.println("Reg: " + defaultName);
			if (defaultName.equals(reg.getName())) {
				continue;
			}
			regRenameMap.put(defaultName, reg.getName());
		}
	}

	private void markError(Address addr, String type, String msg) {
		if (bookmarkMgr.getBookmarks(addr).length == 0) {
			bookmarkMgr.setBookmark(addr, BookmarkType.ERROR, type, msg);
		}
	}

	private class OrigInstructionEnumeration implements Enumeration<OrigInstruction> {

		private List<TestVector> testVectors;
		private int nextIndex = 0;
		private OrigInstruction nextElement;
		private OrigInstruction nextNextElement;

		OrigInstructionEnumeration(File tvFile) throws IOException {
			testVectors = readInstructions(tvFile);
		}

		@Override
		public boolean hasMoreElements() {
			if (nextElement == null && nextIndex < testVectors.size()) {
				if (nextNextElement != null) {
					nextElement = nextNextElement;
					nextNextElement = null;
				}
				else {
					getNextElement();
				}
			}
			return nextElement != null;
		}

		private void getNextElement() {

			TestVector testVector = testVectors.get(nextIndex++);
			String origInstrStr = testVector.instr;

			int index = origInstrStr.indexOf(';');
			if (index > 0) {
				String left = origInstrStr.substring(0, index).trim();
				nextElement = new OrigInstruction(testVector.lineNo, left, true, false, false);
				origInstrStr = origInstrStr.substring(index + 1).trim();
			}

			// check for endloop elements
			boolean endloop0 = false;
			boolean endloop1 = false;
			try {
				while (testVectors.get(nextIndex).instr.startsWith(":endloop")) {
					String endloop = testVectors.get(nextIndex++).instr;
					if (endloop.endsWith("0")) {
						endloop0 = true;
					}
					else if (endloop.endsWith("1")) {
						endloop1 = true;
					}
				}
			}
			catch (IndexOutOfBoundsException e) {
				// ignore
			}

			if (nextElement != null) {
				nextNextElement =
					new OrigInstruction(testVector.lineNo, origInstrStr, false, endloop0, endloop1);
			}
			else {
				nextElement =
					new OrigInstruction(testVector.lineNo, origInstrStr, false, endloop0, endloop1);
			}
		}

		@Override
		public OrigInstruction nextElement() {
			hasMoreElements();
			OrigInstruction instr = nextElement;
			nextElement = null;
			return instr;
		}

	}

	private class GhidraInstructionEnumeration implements Enumeration<GhidraInstruction> {

		Address nextInstrAddr;
		GhidraInstruction nextElement;
		GhidraInstruction nextNextElement;
		Register packetOffsetCtxReg;

		GhidraInstructionEnumeration() {
			nextInstrAddr = memory.getMinAddress();
			packetOffsetCtxReg = currentProgram.getLanguage().getRegister("packetOffset");
		}

		@Override
		public boolean hasMoreElements() {
			if (nextElement == null) {
				if (nextNextElement != null) {
					nextElement = nextNextElement;
					nextNextElement = null;
				}
				else {
					getNextElement();
				}
			}
			return nextElement != null;
		}

		private void getNextElement() {
			if (nextInstrAddr == null) {
				return;
			}
			if (!memory.contains(nextInstrAddr)) {
				nextInstrAddr = null;
				return;
			}
			Instruction instr = listing.getInstructionAt(nextInstrAddr);
			if (instr == null) {
				nextElement = new GhidraInstruction(nextInstrAddr, null);
			}
			else if (instr.toString().startsWith("immext")) {
				nextInstrAddr = nextInstrAddr.add(4);
				getNextElement();
				return;
			}
			else {
				String instrStr = instr.toString();

				Address[] flows = instr.getFlows();
				if (flows.length == 1) {

					// Replace absolute flow address with relative offset

					String flowOffsetStr = "0x" + flows[0].toString();

					BigInteger value = instr.getValue(packetOffsetCtxReg, false);
					int packetOffset = (int) (value != null ? value.longValue() : 0);

					Address packetStartAddr = instr.getMinAddress().subtract(packetOffset * 4);
					long relOffset = flows[0].subtract(packetStartAddr);
					if ((relOffset & 0xc0000000L) == 0xc0000000L) {
						relOffset = (relOffset << 32) >> 32; // sign fixup
					}

					boolean isNegative = relOffset < 0;
					String relOffsetStr;
					if (isNegative) {
						relOffsetStr = "#-0x" + Long.toHexString(-relOffset);
					}
					else {
						relOffsetStr = "#0x" + Long.toHexString(relOffset);
					}

					instrStr = instrStr.replace(flowOffsetStr, relOffsetStr);

				}

				int index = instrStr.indexOf(';');
				if (index > 0) {
					String left = instrStr.substring(0, index).trim();
					nextElement = new GhidraInstruction(nextInstrAddr, left);
					instrStr = instrStr.substring(index + 1).trim();
				}

				if (nextElement != null) {
					nextNextElement = new GhidraInstruction(nextInstrAddr, instrStr);
				}
				else {
					nextElement = new GhidraInstruction(nextInstrAddr, instrStr);
				}

			}
			nextInstrAddr = nextInstrAddr.add(4);
		}

		@Override
		public GhidraInstruction nextElement() {
			hasMoreElements();
			GhidraInstruction instr = nextElement;
			nextElement = null;
			return instr;
		}

	}

	private class OrigInstruction {

		private boolean isLeft;
		private int lineNo;
		private String instr;
		private boolean endloop0;
		private boolean endloop1;

		OrigInstruction(int lineNo, String instr, boolean isLeft, boolean endloop0,
				boolean endloop1) {
			this.lineNo = lineNo;
			this.instr = instr;
			this.isLeft = isLeft;
			this.endloop0 = endloop0;
			this.endloop1 = endloop1;
			parse();
		}

		boolean isLeftInstruction() {
			return isLeft;
		}

		boolean hasAssignment() {
			if (isMemStore()) {
				return true;
			}
			int equalIndex = instr.indexOf('=');
			int parenIndex = instr.indexOf('(');
			if (parenIndex > 0 && instr.startsWith("if ")) {
				parenIndex = instr.indexOf('(', parenIndex + 1);
			}
			return equalIndex > 0 && (parenIndex < 0 || parenIndex > equalIndex);
		}

		boolean isMemStore() {
			int memOpIndex = instr.indexOf("mem");
			int equalIndex = instr.indexOf('=');

			return (memOpIndex >= 0 && memOpIndex < equalIndex);
		}

		private void parse() {

			// Add missing conditional parens
			addParens();

			// Rename registers
			for (String oldName : regRenameMap.keySet()) {
				renameRegister(oldName, regRenameMap.get(oldName));
			}

			// ignore ## - treat as #
			instr = instr.replace("##", "#");

			// Convert shift expressions to single constant e.g., (#0x2 << 2)
			fixShiftedConstantExpression();

			// Convert decimal constants to hex
			changeDecimalToHex();

			// ignore << #0x0
			instr = instr.replace("<< #0x0", "");

			replaceLabels();

		}

		private void replaceLabels() {
			for (Symbol s : labels) {
				if (instr.indexOf(s.getName()) >= 0) {
					String addrStr = "0x" + s.getAddress().toString();
					instr = instr.replace(s.getName(), addrStr);
				}
			}
		}

		private void addParens() {
			if (!instr.startsWith("if ")) {
				return;
			}
			// Assumes lower-case mnemonic and upper-case reg name

			int condStartIndex = -1;
			int condEndIndex = -1;

			int index = 2;
			int mode = 0;
			while (index < instr.length() && condEndIndex < 0) {
				char c = instr.charAt(index);
				switch (mode) {
					case 0: // looking for start
						if (c == '(') {
							return;
						}
						if (c == '!') {
							condStartIndex = index;
						}
						else if (c != ' ') {
							if (condStartIndex < 0) {
								condStartIndex = index;
							}
							mode = 1;
						}
						break;
					case 1: // on-reg
						if (c == ' ') {
							mode = 2;
						}
						break;
					case 2: // after reg
						if (c == '.') {
							if (instr.substring(index).startsWith(".new")) {
								index += 3;
							}
							else {
								return; // unexpected
							}
						}
						else if (c != ' ') {
							condEndIndex = index;
						}
						break;
				}
				++index;
			}

			if (condEndIndex > 0) {

				instr = instr.substring(0, condStartIndex) + "( " +
					instr.substring(condStartIndex, condEndIndex) + ") " +
					instr.substring(condEndIndex);
			}
		}

		private void fixShiftedConstantExpression() {
			try {
				for (int index = instr.indexOf("#("); index >= 0 && index < instr.length(); index =
					instr.indexOf("#(", index)) {

					int expEndIndex = instr.indexOf(')', index);
					if (expEndIndex <= 0) {
						return; // unexpected
					}

					long expVal = getShiftedConstantValue(instr.substring(index + 2, expEndIndex));

					boolean isNegative = expVal < 0;
					String prefix = "#0x";
					if (isNegative) {
						prefix = "#-0x";
						expVal = -expVal;
					}
					instr = instr.substring(0, index) + prefix + Long.toHexString(expVal) +
						instr.substring(expEndIndex + 1);

					++index;
				}
			}
			catch (NumberFormatException e) {
				Msg.error(this, e.getMessage());
			}
		}

		private long getShiftedConstantValue(String constantShiftExp) throws NumberFormatException {
			int shiftIndex = constantShiftExp.indexOf("<<");

			String leftConstStr = (shiftIndex < 0) ? constantShiftExp
					: constantShiftExp.substring(0, shiftIndex).trim();

			boolean isNegative = leftConstStr.startsWith("-");
			if (isNegative) {
				leftConstStr = leftConstStr.substring(1);
			}
			long leftConst;
			if (leftConstStr.startsWith("0x")) {
				leftConstStr = leftConstStr.substring(2);
				leftConst = Long.parseLong(leftConstStr, 16);
			}
			else {
				leftConst = Long.parseLong(leftConstStr);
			}
			if (isNegative) {
				leftConst = -leftConst;
			}

			if (shiftIndex < 0) {
				return leftConst;
			}

			String rightConstStr = constantShiftExp.substring(shiftIndex + 2).trim();
			int rightConst = Integer.parseInt(rightConstStr);
			return leftConst << rightConst;
		}

		private void changeDecimalToHex() {
			for (int index = instr.indexOf('#'); index >= 0 && index < (instr.length() - 1); index =
				instr.indexOf('#', index)) {
				if (instr.charAt(++index) == '-') {
					++index;
				}
				if (instr.substring(index).startsWith("0x")) {
					continue; // already hex
				}
				int valStartIndex = index;
				StringBuilder buf = new StringBuilder();
				while (index < instr.length()) {
					char c = instr.charAt(index);
					if (!Character.isDigit(c)) {
						break;
					}
					buf.append(c);
					++index;
				}
				if (buf.length() == 0) {
					continue;
				}
				int val = Integer.parseInt(buf.toString());
				String hexStr = "0x" + Integer.toHexString(val);
				instr = instr.substring(0, valStartIndex) + hexStr +
					instr.substring(valStartIndex + buf.length());
			}
		}

		private void renameRegister(String oldName, String newName) {
			// Assume only 32-bit regs
			int nameLen = oldName.length();
			int newNameLen = newName.length();
			for (int index = instr.indexOf(oldName); index >= 0 && index < instr.length(); index =
				instr.indexOf(oldName, index)) {
				int indexAfterName = index + nameLen;
				if ((index == 0 || instr.charAt(index - 1) != ':') &&
					(indexAfterName == instr.length() || (instr.charAt(indexAfterName) != ':') &&
						!Character.isDigit(instr.charAt(indexAfterName)))) {
					instr = instr.substring(0, index) + newName + instr.substring(indexAfterName);
					index += newNameLen;
				}
				else {
					index = indexAfterName;
				}
			}
		}

		@Override
		public String toString() {
			StringBuilder buf = new StringBuilder(instr);
			if (endloop0) {
				buf.append(" :endloop0");
			}
			if (endloop1) {
				buf.append(" :endloop1");
			}
			return buf.toString();
		}

	}

	private class GhidraOperand {

		String str;

		GhidraOperand(String str) {
			this.str = str.replace("##", "#"); // ignore ## - treat as #
			this.str = this.str.replace("#0)", "#0x0)");
			removeZeroPadding();
			fixDoubleRegs();
		}

		private void removeZeroPadding() {
			for (int index = str.indexOf("#0x0"); index >= 0 && index < str.length(); index =
				str.indexOf("#0x0", index)) {

				index += 3;
				int startIndex = -1;

				while (index < (str.length() - 1) && str.charAt(index) == '0') {
					char nextChar = str.charAt(index + 1);
					if (!Character.isDigit(nextChar)) {
						break;
					}
					if (startIndex < 0) {
						startIndex = index;
					}
					++index;
				}

				if (startIndex > 0) {
					str = str.substring(0, startIndex) + str.substring(index);
				}
			}
		}

		private void fixDoubleRegs() {
			for (int index = 0; index <= str.length() - 4; ++index) {
				char c = str.charAt(index);
				if (c != 'R' && c != 'S' && c != 'C' && c != 'G') {
					continue;
				}
				int numLen = getRegNumberLength(index + 1);
				if (numLen < 0) {
					continue;
				}
				index += numLen;
				if (c == str.charAt(index + 1)) {
					str = str.substring(0, index + 1) + ":" + str.substring(index + 2);
				}
			}
		}

		private int getRegNumberLength(int startIndex) {
			if (startIndex >= str.length() - 2) {
				return -1;
			}
			if (!Character.isDigit(str.charAt(startIndex++))) {
				return -1;
			}
			if (!Character.isDigit(str.charAt(startIndex))) {
				return 1;
			}
			return 2;
		}

		@Override
		public String toString() {
			return str;
		}

	}

	private class GhidraInstruction {

		private Address addr;
		private String instr;
		private boolean endloop0;
		private boolean endloop1;

		private GhidraOperand conditional;
		private String mnemonic;
		private String assignmentOperator; // = += -= etc.
		private GhidraOperand outArg;
		private List<String> modifiers; // :sat :<<1 etc.
		private List<GhidraOperand> inArgs = new ArrayList<GhidraOperand>();
		private boolean storeMemOp;

		GhidraInstruction(Address addr, String instr) {
			this.addr = addr;
			this.instr = instr;
			parse();
		}

		boolean isMissing() {
			return instr == null;
		}

		@Override
		public String toString() {
			return toString(false);
		}

		public String toString(boolean buildIt) {
			if (instr == null) {
				return "!MISSING!";
			}
			StringBuilder buf = new StringBuilder();
			if (buildIt) {
				if (conditional != null) {
					buf.append("if (");
					buf.append(conditional.toString());
					buf.append(") ");
				}
				boolean isFlow = false;
				if (outArg != null) {
					boolean addParens = false;
					if (mnemonic != null && inArgs.size() == 1 && storeMemOp) {
						buf.append(mnemonic);
						if (!outArg.str.startsWith("(")) {
							buf.append('(');
							addParens = true;
						}
					}
					buf.append(outArg.toString());
					if (addParens) {
						buf.append(')');
					}
					buf.append(' ');
					buf.append(assignmentOperator);
					buf.append(' ');
				}
				if (mnemonic != null) {
					if (!storeMemOp) {
						buf.append(mnemonic);
					}
				}
				else if (assignmentOperator == null) {
					buf.append("!BAD-PARSE!");
				}
				if (inArgs.size() == 1 && assignmentOperator != null &&
					(mnemonic == null || mnemonic.startsWith("mem"))) {
					// omit parens
					buf.append(' ');
					buf.append(inArgs.get(0).toString());
				}
				else if (inArgs.size() == 1 && mnemonic != null &&
					(mnemonic.startsWith("jump") || mnemonic.startsWith("call"))) {

					if (modifiers != null) {
						for (String modifier : modifiers) {
							buf.append(" :");
							buf.append(modifier);
						}
					}

					// omit parens
					isFlow = true;
					buf.append(' ');
					buf.append(inArgs.get(0).toString());
				}
				else if (inArgs.size() == 1 && inArgs.get(0).str.startsWith("(")) {
					buf.append(inArgs.get(0).toString());
				}
				else if (inArgs.size() != 0) {
					buf.append('(');
					for (int i = 0; i < inArgs.size(); i++) {
						if (i != 0) {
							buf.append(", ");
						}
						buf.append(inArgs.get(i).toString());
					}
					buf.append(')');
				}

				if (!isFlow && modifiers != null) {
					for (String modifier : modifiers) {
						buf.append(" :");
						buf.append(modifier);
					}
				}
			}
			else {
				buf.append(instr);
			}

			if (endloop0) {
				buf.append(" :endloop0");
			}
			if (endloop1) {
				buf.append(" :endloop1");
			}
			return buf.toString();
		}

		boolean assumeAssignment(boolean storeMemOp) {
			this.storeMemOp = storeMemOp;
			if (assignmentOperator != null || outArg != null) {
				return true; // already handled
			}
			if (inArgs.size() != 0) {
				outArg = inArgs.remove(0);
				assignmentOperator = "=";
				return true;
			}
			return false;
		}

		private void parse() {
			if (instr == null) {
				return;
			}
			String instrStr = instr;
			int index = instrStr.indexOf(":endloop0");
			if (index > 0) {
				instrStr = instrStr.replace(":endloop0", "").trim();
				endloop0 = true;
			}
			index = instrStr.indexOf(":endloop1");
			if (index > 0) {
				instrStr = instrStr.replace(":endloop1", "").trim();
				endloop0 = true;
			}

			instr = instrStr.trim();

			index = instr.indexOf(' ');
			if (index < 0) {
				mnemonic = instr;
			}
			else {
				mnemonic = instr.substring(0, index);
			}

			if (mnemonic.startsWith("mem")) {
				// normalize low halfword memory load/store
				instr = instr.replace(".L", "");
			}

			if (index > 0) {
				parseOperands(instr.substring(index).trim());
			}

//			if (instr.startsWith("assign")) {
//				if (inArgs.size() == 2) {
//					outArg = inArgs.remove(0);
//					assignmentOperator = "=";
//				}
//				mnemonic = null;
//				return;
//			}

			index = indexOfSpecial(mnemonic);
			if (index > 0) {

				String addOns = mnemonic.substring(index);
				mnemonic = mnemonic.substring(0, index);

				// handle conditional
				if (mnemonic != null && addOns.startsWith(".if")) {
					if (addOns.charAt(3) == '(') {
						index = addOns.indexOf(')');
						if (index > 0) {
							conditional = new GhidraOperand(addOns.substring(4, index));
							addOns = addOns.substring(index + 1);
						}
						else {
							mnemonic = null; // Bad mnemonic
						}
					}
					else {
						// assume conditional flow - use first argument
						if (inArgs.size() >= 2) {
							conditional = inArgs.remove(0);
							addOns = addOns.substring(3);
						}
						else {
							mnemonic = null; // Bad mnemonic
						}
					}
				}

				// handle cmp modifiers .eq .lt etc.
				if (mnemonic != null && addOns.startsWith(".")) {
					mnemonic += ".";
					index = 1;
					while (index < addOns.length()) {
						char c = addOns.charAt(index);
						if (!Character.isLetter(c)) {
							break;
						}
						mnemonic += c;
						++index;
					}
					addOns = addOns.substring(index);
				}

				// explicit assignment operator - e.g., += -= ^= |= etc.
				index = addOns.indexOf("=");
				if (index >= 0) {
					assignmentOperator = addOns.substring(0, index + 1);
					addOns = addOns.substring(index + 1);
					if (inArgs.size() != 0) {
						outArg = inArgs.remove(0);
						if (assignmentOperator == null) {
							assignmentOperator = "=";
						}
					}
					else {
						mnemonic = null; // Bad mnemonic
					}
				}

				if (mnemonic != null && addOns.length() != 0) {
					char modifierChar = addOns.charAt(0);
					if (modifierChar != '.' && modifierChar != ':') {
						mnemonic = modifierChar + mnemonic;
						addOns = addOns.substring(1);
					}
				}

				// split-up modifiers
				if (mnemonic != null && addOns.startsWith(":")) {
					modifiers = new ArrayList<String>();
// TODO: Verify split
					for (String modifier : addOns.substring(1).split(":")) {
						if (!modifiers.add(modifier)) {
							mnemonic = null; // duplicate
						}
					}
					addOns = ""; // consumed everything
					if (modifiers.isEmpty()) {
						mnemonic = null;
					}
				}

				if (addOns.length() != 0) {
					mnemonic = null;
				}

			}

			if (mnemonic == null) {
				Msg.error(this, "Failed to morph: " + instr);
				return;
			}

			// known assignments which are frequently switched at assembly time
			if (instr.startsWith("assign")) {
				assumeAssignment(false);
				mnemonic = null;
			}
			else if (mnemonic.startsWith("cmp.")) {
				assumeAssignment(false);
			}
			else if (mnemonic.startsWith("mem") && inArgs.size() == 2) {
				assumeAssignment(inArgs.get(0).str.startsWith("("));
			}

//			if (assignmentOperator == null && inArgs.size() > 1) {
//				checkPcodeForAssignment(); // TODO: won't work well for right-side packed instr
//			}

		}

		private void parseOperands(String operands) {

			operands = operands.trim();
			if (operands.startsWith(",")) {
				operands = operands.substring(1).trim();
			}
			else if (operands.length() == 0) {
				return;
			}

			int index = 0;
			int startIndex = 0;
			int parenCnt = 0;
			while (index < operands.length()) {
				int leftParenIndex = operands.indexOf('(', index);
				int rightParenIndex = operands.indexOf(')', index);
				int commaIndex = operands.indexOf(',', index);
				int endIndex = -1;
				if (commaIndex < 0) {
					endIndex = operands.length();
				}
				else if (parenCnt == 0 && (leftParenIndex < 0 || commaIndex < leftParenIndex)) {
					endIndex = commaIndex;
					index = commaIndex;
				}
				else if (parenCnt > 0 || leftParenIndex < commaIndex) {
					// inside group or new group starts before comma
					if (leftParenIndex >= 0 && leftParenIndex < rightParenIndex) {
						// new group starts before next closure
						++parenCnt;
						index = leftParenIndex;
					}
					if (parenCnt > 0 && rightParenIndex >= 0) {
						--parenCnt;
						index = rightParenIndex;
					}
				}

				if (endIndex >= 0) {
					inArgs.add(new GhidraOperand(operands.substring(startIndex, endIndex)));
					startIndex = endIndex + 1;
					index = endIndex;
					endIndex = -1;
				}

				++index;
			}

			if (startIndex < operands.length()) {
				inArgs.add(new GhidraOperand(operands.substring(startIndex)));
			}
//			
//			
//			
//			
//			
//			int parenIndex = operands.indexOf('(');
//			int commaIndex = operands.indexOf(',');
//
////			if (parenIndex < 0) {
//// TODO: Verify split
//			for (String opStr : operands.split(",")) {
//				inArgs.add(new GhidraOperand(opStr));
//			}
//			return;
//			}
//
//			if (commaIndex > 0 && commaIndex < parenIndex) {
//				inArgs.add(new GhidraOperand(operands.substring(0, commaIndex)));
//				parseOperands(operands.substring(commaIndex + 1));
//				return;
//			}
//
//			// assume no nested paren groups
//
//			int rightParenIndex = operands.indexOf(')');
//			if (rightParenIndex > 0) {
//				inArgs.add(new GhidraOperand(operands.substring(0, rightParenIndex + 1)));
//				parseOperands(operands.substring(rightParenIndex + 1));
//				return;
//			}

			// no closing paren found
// TODO: generate error

		}
	}

	/**
	 * Find index of first special character.
	 * @param str
	 * @return index or -1 if whitespace or end-of-string encountered before
	 * matching a non-alpha or numeric character
	 */
	private static int indexOfSpecial(String str) {
		for (int i = 0; i < str.length(); i++) {
			char c = str.charAt(i);
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '_') {
				continue;
			}
			if (c == ' ' || c == '\t') {
				break;
			}
			return i;
		}
		return -1;
	}

	private class TestVector {
		final int lineNo;
		final String instr;

		TestVector(int lineNo, String instr) {
			this.lineNo = lineNo;
			this.instr = instr;
		}
	}

	private List<TestVector> readInstructions(File tvFile) throws IOException {

		int row = 1;
		ArrayList<TestVector> list = new ArrayList<TestVector>();
		BufferedReader r = new BufferedReader(new FileReader(tvFile));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.endsWith(":")) {
					// skip labels
					continue;
				}
				int index = line.indexOf("//");
				if (index >= 0) {
					line = line.substring(0, index).trim();
				}
				boolean addEndLoop0 = false;
				boolean addEndLoop1 = false;
				index = line.indexOf(":endloop0");
				if (index >= 0) {
					line = line.replace(":endloop0", "").trim();
					addEndLoop0 = true;
				}
				index = line.indexOf(":endloop1");
				if (index >= 0) {
					line = line.replace(":endloop1", "").trim();
					addEndLoop1 = true;
				}
				if (line.startsWith("{") || line.startsWith("}")) {
					line = line.substring(1).trim();
				}
				if (line.endsWith("}")) {
					line = line.substring(0, line.length() - 1).trim();
				}
				if (line.endsWith(";")) {
					line = line.substring(0, line.length() - 1).trim();
				}
				if (line.length() != 0 && !line.startsWith(".")) {
					list.add(new TestVector(row, line));
				}
				if (addEndLoop0) {
					list.add(new TestVector(row, ":endloop0"));
				}
				if (addEndLoop1) {
					list.add(new TestVector(row, ":endloop1"));
				}
				++row;
			}
		}
		finally {
			r.close();
		}
		return list;
	}

}
