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

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.UnaryExpression;

/**
 * A matcher for a unnary expression
 * 
 * <p>
 * If the required type matches, the matching descends to the child operand.
 * 
 * @param <T> the type of expression matched
 */
public class UnaryExpressionMatcher<T extends UnaryExpression>
		extends AbstractExpressionMatcher<T> {
	protected final ExpressionMatcher<?> unaryMatcher;

	public UnaryExpressionMatcher(Set<Class<? extends T>> ops, ExpressionMatcher<?> unaryMatcher) {
		super(ops);
		this.unaryMatcher = unaryMatcher;
	}

	public UnaryExpressionMatcher(Class<T> cls, ExpressionMatcher<?> unaryMatcher) {
		super(cls);
		this.unaryMatcher = unaryMatcher;
	}

	@Override
	protected boolean matchDetails(T expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		return unaryMatcher.match(expression.getUnary(), result);
	}
}
