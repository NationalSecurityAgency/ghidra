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

/**
 * A matcher which accept any expression of the required type
 *
 * <p>
 * This requires no further consideration of the expressions operands. If the type matches, the
 * expression matches.
 *
 * @param <T> the type to match
 */
public class AnyMatcher<T extends PatternExpression> extends AbstractExpressionMatcher<T> {
	public static AnyMatcher<PatternExpression> any() {
		return new AnyMatcher<>(PatternExpression.class);
	}

	public AnyMatcher(Set<Class<? extends T>> ops) {
		super(ops);
	}

	public AnyMatcher(Class<T> cls) {
		super(cls);
	}

	@Override
	protected boolean matchDetails(T expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		return true;
	}
}
