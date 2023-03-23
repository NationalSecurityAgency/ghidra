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
 * Base implementation for expression matchers
 *
 * @param <T> the type of expression matched
 */
public abstract class AbstractExpressionMatcher<T extends PatternExpression>
		implements ExpressionMatcher<T> {
	protected final Set<Class<? extends T>> ops;

	public AbstractExpressionMatcher(Set<Class<? extends T>> ops) {
		this.ops = Set.copyOf(ops);
	}

	public AbstractExpressionMatcher(Class<? extends T> cls) {
		this.ops = Set.of(cls);
	}

	protected T opMatches(PatternExpression expression) {
		return ops.stream()
				.filter(op -> op.isInstance(expression))
				.map(op -> op.cast(expression))
				.findAny()
				.orElse(null);
	}

	protected abstract boolean matchDetails(T expression,
			Map<ExpressionMatcher<?>, PatternExpression> result);

	@Override
	public boolean match(PatternExpression expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		T t = opMatches(expression);
		if (t == null) {
			return false;
		}
		if (!matchDetails(t, result)) {
			return false;
		}
		return recordResult(t, result);
	}

	protected boolean recordResult(PatternExpression expression,
			Map<ExpressionMatcher<?>, PatternExpression> result) {
		PatternExpression already = result.put(this, expression);
		if (already == null) {
			return true;
		}
		return expressionsIdenticallyDefined(already, expression);
	}

	protected static boolean expressionsIdenticallyDefined(PatternExpression a,
			PatternExpression b) {
		if (a.getClass() != b.getClass()) {
			return false;
		}
		if (a instanceof EndInstructionValue) {
			return true;
		}
		if (a instanceof Next2InstructionValue) {
			return true;
		}
		if (a instanceof StartInstructionValue) {
			return true;
		}
		if (a instanceof ConstantValue) {
			ConstantValue ca = (ConstantValue) a;
			ConstantValue cb = (ConstantValue) b;
			return ca.getValue() == cb.getValue();
		}
		if (a instanceof UnaryExpression) {
			UnaryExpression ua = (UnaryExpression) a;
			UnaryExpression ub = (UnaryExpression) b;
			return expressionsIdenticallyDefined(ua.getUnary(), ub.getUnary());
		}
		if (a instanceof BinaryExpression) {
			BinaryExpression ba = (BinaryExpression) a;
			BinaryExpression bb = (BinaryExpression) b;
			return expressionsIdenticallyDefined(ba.getLeft(), bb.getLeft()) &&
				expressionsIdenticallyDefined(ba.getRight(), bb.getRight());
		}
		if (a instanceof TokenField) {
			TokenField ta = (TokenField) a;
			TokenField tb = (TokenField) b;
			return ta.getBitStart() == tb.getBitStart() &&
				ta.getBitEnd() == tb.getBitEnd() &&
				ta.hasSignbit() == tb.hasSignbit();
		}
		if (a instanceof ContextField) {
			ContextField ca = (ContextField) a;
			ContextField cb = (ContextField) b;
			return ca.getStartBit() == cb.getStartBit() &&
				ca.getEndBit() == cb.getEndBit() &&
				ca.hasSignbit() == cb.hasSignbit();
		}
		if (a instanceof OperandValue) {
			OperandValue va = (OperandValue) a;
			OperandValue vb = (OperandValue) b;
			return va.getConstructor() == vb.getConstructor() &&
				va.getIndex() == vb.getIndex();
		}
		throw new AssertionError();
	}
}
