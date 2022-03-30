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
		return new MyFormatter(this).formatOps(language, code);
	}
}
