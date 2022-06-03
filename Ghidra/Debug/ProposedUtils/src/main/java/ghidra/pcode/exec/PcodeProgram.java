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
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.util.pcode.AbstractAppender;
import ghidra.app.util.pcode.AbstractPcodeFormatter;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A p-code program to be executed by a {@link PcodeExecutor}
 * 
 * <p>
 * This is a list of p-code operations together with a map of expected userops.
 */
public class PcodeProgram {
	protected static class MyAppender extends AbstractAppender<String> {
		protected final PcodeProgram program;
		protected final StringBuffer buf = new StringBuffer();

		public MyAppender(PcodeProgram program, Language language) {
			super(language, true);
			this.program = program;
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
	}

	protected static class MyFormatter extends AbstractPcodeFormatter<String, MyAppender> {
		protected final PcodeProgram program;

		public MyFormatter(PcodeProgram program) {
			this.program = program;
		}

		@Override
		protected MyAppender createAppender(Language language, boolean indent) {
			return new MyAppender(program, language);
		}

		@Override
		protected FormatResult formatOpTemplate(MyAppender appender, OpTpl op) {
			FormatResult result = super.formatOpTemplate(appender, op);
			appender.endLine();
			return result;
		}
	}

	/**
	 * Generate a p-code program from the given instruction
	 * 
	 * @param instruction the instruction
	 * @return the p-code program.
	 */
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
		return new MyFormatter(this).formatOps(language, code);
	}
}
