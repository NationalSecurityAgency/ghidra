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
package ghidra.app.plugin.assembler.sleigh.expr.match;

import java.util.Map;

import ghidra.app.plugin.processors.sleigh.expression.ConstantValue;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * A matcher for a given constant value
 */
public class ConstantValueMatcher extends AbstractExpressionMatcher<ConstantValue> {
	protected final long value;

	public ConstantValueMatcher(long value) {
		super(ConstantValue.class);
		this.value = value;
	}

	@Override
	protected boolean matchDetails(ConstantValue expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		return expression.getValue() == value;
	}
}
