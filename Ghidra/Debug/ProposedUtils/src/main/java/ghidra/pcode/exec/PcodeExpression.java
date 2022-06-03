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

/**
 * A p-code program derived from, i.e., implementing, a SLEIGH expression
 */
public class PcodeExpression extends PcodeProgram {
	public static final String RESULT_NAME = "___result";
	protected static final PcodeUseropLibrary<?> CAPTURING =
		new ValueCapturingPcodeUseropLibrary<>();

	/**
	 * A clever means of capturing the result of the expression.
	 * 
	 * @implNote The compiled source is actually {@code ___result(<expression>);} which allows us to
	 *           capture the value (and size) of arbitrary expressions. Assigning the value to a
	 *           temp variable instead of a userop does not quite suffice, since it requires a fixed
	 *           size, which cannot be known ahead of time.
	 *
	 * @param <T> no type in particular, except to match the executor
	 */
	protected static class ValueCapturingPcodeUseropLibrary<T>
			extends AnnotatedPcodeUseropLibrary<T> {
		T result;

		@PcodeUserop
		public void ___result(T result) {
			this.result = result;
		}
	}

	/**
	 * Construct a p-code program from source already compiled into p-code ops
	 * 
	 * @param language the language that generated the p-code
	 * @param code the list of p-code ops
	 * @param useropSymbols a map of expected userop symbols
	 */
	protected PcodeExpression(SleighLanguage language, List<PcodeOp> code,
			Map<Integer, UserOpSymbol> useropSymbols) {
		super(language, code, useropSymbols);
	}

	// TODO: One that can take a library, and compose the result into it

	/**
	 * Evaluate the expression using the given executor
	 * 
	 * @param <T> the type of the result
	 * @param executor the executor
	 * @return the result
	 */
	public <T> T evaluate(PcodeExecutor<T> executor) {
		ValueCapturingPcodeUseropLibrary<T> library =
			new ValueCapturingPcodeUseropLibrary<>();
		execute(executor, library);
		return library.result;
	}
}
