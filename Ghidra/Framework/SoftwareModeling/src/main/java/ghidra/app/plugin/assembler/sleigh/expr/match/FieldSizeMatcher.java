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
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.expression.*;

/**
 * A matcher for a token or context field, constrained by its size in bits
 */
public class FieldSizeMatcher extends AbstractExpressionMatcher<PatternValue> {
	protected final ExpressionMatcher<?> sizeMatcher;

	public FieldSizeMatcher(ExpressionMatcher<?> sizeMatcher) {
		super(Set.of(ContextField.class, TokenField.class));
		this.sizeMatcher = sizeMatcher;
	}

	@Override
	protected boolean matchDetails(PatternValue expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		if (expression instanceof ContextField) {
			ContextField cf = (ContextField) expression;
			long size = cf.getEndBit() - cf.getStartBit() + 1;
			return sizeMatcher.match(new ConstantValue(size), result);
		}
		if (expression instanceof TokenField) {
			TokenField tf = (TokenField) expression;
			long size = tf.getBitEnd() - tf.getBitStart() + 1;
			return sizeMatcher.match(new ConstantValue(size), result);
		}
		return false;
	}
}
