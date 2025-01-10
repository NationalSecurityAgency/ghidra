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

import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.util.pcode.AbstractAppender;
import ghidra.app.util.pcode.AbstractPcodeFormatter;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.NotFoundException;

/**
 * A p-code program to be executed by a {@link PcodeExecutor}
 * 
 * <p>
 * This is a list of p-code operations together with a map of expected userops.
 */
public class PcodeProgram {
	protected static class MyAppender extends AbstractAppender<String> {
		protected int opIdx = 0;
		protected final PcodeProgram program;
		protected final boolean numberOps;

		protected final StringBuffer buf = new StringBuffer();

		public MyAppender(PcodeProgram program, Language language, boolean numberOps) {
			super(language, true);
			this.program = program;
			this.numberOps = numberOps;

			buf.append("<" + program.getHead() + ":\n");
		}

		@Override
		protected void appendString(String string) {
			buf.append(string);
		}

		protected void endLine() {
			buf.append("\n");
		}

		@Override
		protected String stringifyUseropUnchecked(Language language, int id) {
			String name = super.stringifyUseropUnchecked(language, id);
			if (name != null) {
				return name;
			}
			return program.useropNames.get(id);
		}

		@Override
		public String finish() {
			buf.append(">");
			return buf.toString();
		}

		@Override
		public void appendIndent() {
			super.appendIndent();
			if (numberOps) {
				PcodeOp op = program.getCode().get(opIdx);
				buf.append(opIdx++);
				buf.append(",");
				buf.append(op.getSeqnum().getTarget());
				buf.append(".");
				buf.append(op.getSeqnum().getTime());
				buf.append(": ");
			}
		}
	}

	protected static class MyFormatter extends AbstractPcodeFormatter<String, MyAppender> {
		protected final PcodeProgram program;
		protected final boolean numberOps;

		public MyFormatter(PcodeProgram program, boolean numberOps) {
			this.program = program;
			this.numberOps = numberOps;
		}

		@Override
		protected MyAppender createAppender(Language language, boolean indent) {
			return new MyAppender(program, language, numberOps);
		}

		@Override
		protected FormatResult formatOpTemplate(MyAppender appender, OpTpl op) {
			FormatResult result = super.formatOpTemplate(appender, op);
			appender.endLine();
			return result;
		}
	}

	/**
	 * Generate a p-code program from the given instruction, without overrides
	 * 
	 * @param instruction the instruction
	 * @return the p-code program
	 */
	public static PcodeProgram fromInstruction(Instruction instruction) {
		return fromInstruction(instruction, false);
	}

	/**
	 * Generate a p-code program from the given instruction
	 * 
	 * @param instruction the instruction
	 * @param includeOverrides as in {@link Instruction#getPcode(boolean)}
	 * @return the p-code program
	 */
	public static PcodeProgram fromInstruction(Instruction instruction, boolean includeOverrides) {
		Language language = instruction.getPrototype().getLanguage();
		if (!(language instanceof SleighLanguage slang)) {
			throw new IllegalArgumentException("Instruction must be parsed using Sleigh");
		}
		PcodeOp[] pcode = instruction.getPcode(includeOverrides);
		return new PcodeProgram(slang, List.of(pcode), Map.of());
	}

	/**
	 * Generate a p-code program from a given program's inject library
	 * 
	 * @param program the program
	 * @param name the name of the snippet
	 * @param type the type of the snippet
	 * @return the p-code program
	 * @throws MemoryAccessException for problems establishing the injection context
	 * @throws IOException for problems while emitting the injection p-code
	 * @throws UnknownInstructionException if there is no underlying instruction being injected
	 * @throws NotFoundException if an expected aspect of the injection is not present in context
	 */
	public static PcodeProgram fromInject(Program program, String name, int type)
			throws MemoryAccessException, UnknownInstructionException, NotFoundException,
			IOException {
		PcodeInjectLibrary library = program.getCompilerSpec().getPcodeInjectLibrary();
		InjectContext ctx = library.buildInjectContext();
		InjectPayload payload = library.getPayload(type, name);
		PcodeOp[] pcode = payload.getPcode(program, ctx);
		return new PcodeProgram((SleighLanguage) program.getLanguage(), List.of(pcode), Map.of());
	}

	protected final SleighLanguage language;
	protected final List<PcodeOp> code;
	protected final Map<Integer, String> useropNames;

	/**
	 * Construct a p-code program with the given bindings
	 * 
	 * @param language the language that generated the p-code
	 * @param code the list of p-code ops
	 * @param useropSymbols a map of expected userop symbols
	 */
	protected PcodeProgram(SleighLanguage language, List<PcodeOp> code,
			Map<Integer, UserOpSymbol> useropSymbols) {
		this.language = language;
		this.code = code;
		this.useropNames = new HashMap<>();
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

	/**
	 * Construct a p-code program from a derivative of the given one
	 * 
	 * @param program the original program
	 * @param code the code portion for this program
	 */
	public PcodeProgram(PcodeProgram program, List<PcodeOp> code) {
		assert !code.isEmpty();
		this.language = program.language;
		this.code = code;
		this.useropNames = program.useropNames;
	}

	/**
	 * Get the language generating this program
	 * 
	 * @return the language
	 */
	public SleighLanguage getLanguage() {
		return language;
	}

	public List<PcodeOp> getCode() {
		return code;
	}

	/**
	 * Execute this program using the given executor and library
	 * 
	 * @param <T> the type of values to be operated on
	 * @param executor the executor
	 * @param library the library
	 */
	public <T> void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library) {
		executor.execute(this, library);
	}

	/**
	 * For display purposes, get the header above the frame, usually the class name
	 * 
	 * @return the frame's display header
	 */
	protected String getHead() {
		return getClass().getSimpleName();
	}

	@Override
	public String toString() {
		return format();
	}

	public String format(boolean numberOps) {
		return new MyFormatter(this, numberOps).formatOps(language, code);
	}

	public String format() {
		return format(false);
	}
}
