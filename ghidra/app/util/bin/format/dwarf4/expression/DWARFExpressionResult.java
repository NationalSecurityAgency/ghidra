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
package ghidra.app.util.bin.format.dwarf4.expression;

import java.util.ArrayDeque;

/**
 * The result of executing a {@link DWARFExpression} with a {@link DWARFExpressionEvaluator}.
 * <p>
 * Currently only holds the stack results, but future improvements should
 * migrate result values (ie. stuff like {@link DWARFExpressionEvaluator#isDeref()})
 * from {@link DWARFExpressionEvaluator} to here.
 */
public class DWARFExpressionResult {
	private ArrayDeque<Long> stack = new ArrayDeque<Long>();

	public DWARFExpressionResult(ArrayDeque<Long> stack) {
		this.stack = stack;
	}

	public long pop() {
		return stack.pop();
	}
}
