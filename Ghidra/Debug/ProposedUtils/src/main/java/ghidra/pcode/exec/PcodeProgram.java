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
package ghidra.pcode.exec;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.HTMLUtilities;

public class PcodeProgram {
	protected static String htmlSpan(String cls, String display) {
		return String.format("<span class=\"%s\">%s</span>", cls,
			HTMLUtilities.escapeHTML(display));
	}

	public static String registerToString(Register reg, boolean markup) {
		if (markup) {
			return htmlSpan("register", reg.toString());
		}
		else {
			return reg.toString();
		}
	}

	public static String constToString(Varnode cvn, boolean markup) {
		String display = String.format("%d:%d", cvn.getOffset(), cvn.getSize());
		if (markup) {
			return htmlSpan("constant", display);
		}
		else {
			return display;
		}
	}

	public static String uniqueToString(Varnode uvn, boolean markup) {
		String display = String.format("$U%s:%d",
			uvn.getAddress().getOffsetAsBigInteger().toString(16), uvn.getSize());
		if (markup) {
			return htmlSpan("unique", display);
		}
		else {
			return display;
		}
	}

	public static String addressToString(Varnode avn, boolean markup) {
		String display = String.format("%s:%d", avn.getAddress().toString(true), avn.getSize());
		if (markup) {
			return htmlSpan("address", display);
		}
		else {
			return display;
		}
	}

	public static String vnToString(Language language, Varnode vn, boolean markup) {
		Register reg =
			language.getRegister(vn.getAddress().getAddressSpace(), vn.getOffset(), vn.getSize());
		if (reg != null) {
			return registerToString(reg, markup);
		}
		if (vn.isConstant()) {
			return constToString(vn, markup);
		}
		if (vn.isUnique()) {
			return uniqueToString(vn, markup);
		}
		return addressToString(vn, markup);
	}

	public static String spaceToString(Language language, Varnode vn, boolean markup) {
		if (!vn.isConstant()) {
			throw new IllegalArgumentException("space id must be a constant varnode");
		}
		AddressSpace space = language.getAddressFactory().getAddressSpace((int) vn.getOffset());
		String display = space == null ? "<null>" : space.getName();
		if (markup) {
			return htmlSpan("space", display);
		}
		else {
			return display;
		}
	}

	public static String useropToString(Language language, Varnode vn, boolean markup) {
		if (!vn.isConstant()) {
			throw new IllegalArgumentException("userop index must be a constant varnode");
		}
		String display = "\"" + language.getUserDefinedOpName((int) vn.getOffset()) + "\"";
		if (markup) {
			return htmlSpan("userop", display);
		}
		else {
			return display;
		}
	}

	public static String opCodeToString(Language language, int op, boolean markup) {
		if (markup) {
			return htmlSpan("op", PcodeOp.getMnemonic(op));
		}
		else {
			return PcodeOp.getMnemonic(op);
		}
	}

	public static String opToString(Language language, PcodeOp op, boolean markup) {
		StringBuilder sb = new StringBuilder();
		Varnode output = op.getOutput();
		if (output != null) {
			sb.append(vnToString(language, output, markup));
			sb.append(" = ");
		}
		int opcode = op.getOpcode();
		sb.append(opCodeToString(language, opcode, markup));
		boolean isDeref = opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE;
		boolean isUserop = opcode == PcodeOp.CALLOTHER;
		int i;
		if (isDeref) {
			sb.append(' ');
			sb.append(spaceToString(language, op.getInput(0), markup));
			sb.append('(');
			sb.append(vnToString(language, op.getInput(1), markup));
			sb.append(')');
			i = 2;
		}
		else if (isUserop) {
			sb.append(' ');
			sb.append(useropToString(language, op.getInput(0), markup));
			i = 1;
		}
		else {
			i = 0;
		}
		for (; i < op.getNumInputs(); i++) {
			if (i != 0) {
				sb.append(',');
			}
			sb.append(' ');
			sb.append(vnToString(language, op.getInput(i), markup));
		}
		return sb.toString();
	}

	public static PcodeProgram fromInstruction(Instruction instruction) {
		Language language = instruction.getPrototype().getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Instruction must be parsed using Sleigh");
		}
		PcodeOp[] pcode = instruction.getPcode(false);
		return new PcodeProgram((SleighLanguage) language, List.of(pcode),
			Map.of());
	}

	protected final SleighLanguage language;
	protected final List<PcodeOp> code;
	protected final Map<Integer, String> useropNames = new HashMap<>();

	protected PcodeProgram(SleighLanguage language, List<PcodeOp> code,
			Map<Integer, UserOpSymbol> useropSymbols) {
		this.language = language;
		this.code = code;
		int langOpCount = language.getNumberOfUserDefinedOpNames();
		for (Map.Entry<Integer, UserOpSymbol> ent : useropSymbols.entrySet()) {
			int index = ent.getKey();
			if (index < langOpCount) {
				useropNames.put(index, language.getUserDefinedOpName(index));
			}
			else {
				useropNames.put(index, ent.getValue().getName());
			}
		}
	}

	public SleighLanguage getLanguage() {
		return language;
	}

	public <T> void execute(PcodeExecutor<T> executor, SleighUseropLibrary<T> library) {
		executor.execute(this, library);
	}

	protected String getHead() {
		return getClass().getSimpleName();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("<" + getHead() + ":");
		for (PcodeOp op : code) {
			sb.append("\n  " + op.getSeqnum() + ": " + opToString(language, op, false));
		}
		sb.append("\n>");
		return sb.toString();
	}
}
