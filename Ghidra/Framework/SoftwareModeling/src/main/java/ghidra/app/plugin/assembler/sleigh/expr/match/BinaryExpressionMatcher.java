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

import java.util.*;

import ghidra.app.plugin.processors.sleigh.expression.BinaryExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * A matcher for a binary expression
 * 
 * <p>
 * If the required type matches, the matching descends to the left then right operands.
 * 
 * @param <T> the type of expression matched
 */
public class BinaryExpressionMatcher<T extends BinaryExpression>
		extends AbstractExpressionMatcher<T> {

	/**
	 * A matcher for binary expression allowing commutativity
	 * 
	 * <p>
	 * This behaves the same as {@link BinaryExpressionMatcher}, but if the first attempt fails, the
	 * operand match is re-attempted with the operands swapped.
	 *
	 * @param <T> the type of expression matched
	 */
	public static class Commutative<T extends BinaryExpression> extends BinaryExpressionMatcher<T> {
		public Commutative(Set<Class<? extends T>> ops,
				ExpressionMatcher<?> leftMatcher, ExpressionMatcher<?> rightMatcher) {
			super(ops, leftMatcher, rightMatcher);
		}

		public Commutative(Class<T> cls, ExpressionMatcher<?> leftMatcher,
				ExpressionMatcher<?> rightMatcher) {
			super(cls, leftMatcher, rightMatcher);
		}

		@Override
		protected boolean matchDetails(T expression,
				Map<ExpressionMatcher<?>, PatternExpression> result) {
			Set<ExpressionMatcher<?>> reset = new HashSet<>(result.keySet());
			if (leftMatcher.match(expression.getLeft(), result) &&
				rightMatcher.match(expression.getRight(), result)) {
				return true;
			}
			result.keySet().retainAll(reset);
			return rightMatcher.match(expression.getLeft(), result) &&
				leftMatcher.match(expression.getRight(), result);
		}
	}

	protected final ExpressionMatcher<?> leftMatcher;
	protected final ExpressionMatcher<?> rightMatcher;

	public BinaryExpressionMatcher(Set<Class<? extends T>> ops,
			ExpressionMatcher<?> leftMatcher, ExpressionMatcher<?> rightMatcher) {
		super(ops);
		this.leftMatcher = leftMatcher;
		this.rightMatcher = rightMatcher;
	}

	public BinaryExpressionMatcher(Class<T> cls, ExpressionMatcher<?> leftMatcher,
			ExpressionMatcher<?> rightMatcher) {
		super(cls);
		this.leftMatcher = leftMatcher;
		this.rightMatcher = rightMatcher;
	}

	@Override
	protected boolean matchDetails(T expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		return leftMatcher.match(expression.getLeft(), result) &&
			rightMatcher.match(expression.getRight(), result);
	}
}
