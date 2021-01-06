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

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.pcode.PcodeOp;

public class SleighExpression extends PcodeProgram {
	public static final String RESULT_NAME = "___result";
	protected static final SleighUseropLibrary<?> CAPTURING =
		new ValueCapturingSleighUseropLibrary<>();

	protected static class ValueCapturingSleighUseropLibrary<T>
			extends AnnotatedSleighUseropLibrary<T> {
		T result;

		@SleighUserop
		public void ___result(T result) {
			this.result = result;
		}
	}

	protected SleighExpression(SleighLanguage language, List<PcodeOp> code,
			Map<Integer, UserOpSymbol> useropSymbols) {
		super(language, code, useropSymbols);
	}

	// TODO: One that can take a library, and compose the result into it

	public <T> T evaluate(PcodeExecutor<T> executor) {
		ValueCapturingSleighUseropLibrary<T> library =
			new ValueCapturingSleighUseropLibrary<>();
		execute(executor, library);
		return library.result;
	}
}
