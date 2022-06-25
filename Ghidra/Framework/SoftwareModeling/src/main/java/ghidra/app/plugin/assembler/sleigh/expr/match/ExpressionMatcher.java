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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.expression.*;

/**
 * A matcher for a form of patten expression
 *
 * <p>
 * Some solvers may need to apply sophisticated heuristics to recognize certain forms that commonly
 * occur in pattern expressions. These can certainly be programmed manually, but for many cases, the
 * form recognition can be accomplished by describing the form as an expression matcher. For a
 * shorter syntax to construct such matchers. See {@link Context}.
 *
 * @param <T> the type of expression matched
 */
public interface ExpressionMatcher<T extends PatternExpression> {

	/**
	 * Attempt to match the given expression, recording the substitutions if successful
	 * 
	 * @param expression the expression to match
	 * @return a map of matchers to substituted expressions
	 */
	default Map<ExpressionMatcher<?>, PatternExpression> match(PatternExpression expression) {
		Map<ExpressionMatcher<?>, PatternExpression> result = new HashMap<>();
		if (match(expression, result)) {
			return result;
		}
		return null;
	}

	/**
	 * Retrieve the expression substituted for this matcher from a previous successful match
	 * 
	 * <p>
	 * Calling this on the root matcher is relatively useless, as it would simply return the
	 * expression passed to {@link #match(PatternExpression)}. Instead, sub-matchers should be saved
	 * in a variable, allowing their values to be retrieved. See {@link Context}, for an example.
	 * 
	 * @param results the previous match results
	 * @return the substituted expression
	 */
	@SuppressWarnings("unchecked")
	default T get(Map<ExpressionMatcher<?>, PatternExpression> results) {
		return (T) results.get(this);
	}

	/**
	 * Attempt to match the given expression, recording substitutions in the given map
	 * 
	 * <p>
	 * Even if the match was unsuccessful, the result map may contain attempted substitutions. Thus,
	 * the map should be discarded if unsuccessful.
	 * 
	 * @param expression the expression to match
	 * @param result a map to store matchers to substituted expressions
	 * @return true if successful, false if not
	 */
	boolean match(PatternExpression expression,
			Map<ExpressionMatcher<?>, PatternExpression> result);

	/**
	 * A context for defining expression matcher succinctly
	 * 
	 * <p>
	 * Implementations of this interface have easy access to factory methods for each kind of
	 * {@link PatternExpression}. Additionally, the class itself provide a convenient container for
	 * saving important sub-matchers, so that important sub-expression can be readily retrieved. For
	 * example:
	 * 
	 * <pre>
	 * static class MyMatchers implements ExpressionMatcher.Context {
	 * 	ExpressionMatcher<ConstantValue> shamt = var(ConstantValue.class);
	 * 	ExpressionMatcher<LeftShiftExpression> exp = shl(var(), shamt);
	 * }
	 * 
	 * static final MyMatchers MATCHERS = new MyMatchers();
	 * 
	 * public long getConstantShift(PatternExpression expression) {
	 * 	Map<ExpressionMatcher<?>, PatternExpression> result = MATCHERS.exp.match(expression);
	 * 	if (result == null) {
	 * 		return -1;
	 * 	}
	 * 	return MATCHERS.shamt.get(result).getValue();
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Saving a sub-matcher to a field (as in the example) also permits that sub-matcher to appear
	 * in multiple places. In that case, the sub-matcher must match identical expressions wherever
	 * it appears. For example, if {@code cv} matches any constant value, then {@code plus(cv, cv)}
	 * would match {@code 2 + 2}, but not {@code 2 + 3}.
	 */
	interface Context {

		/**
		 * Match the form {@code L & R} or {@code R & L}
		 * 
		 * @param left the matcher for the left operand
		 * @param right the matcher for the right operand
		 * @return the matcher
		 */
		default ExpressionMatcher<AndExpression> and(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher.Commutative<>(AndExpression.class, left, right);
		}

		/**
		 * Match the form {@code L / R}
		 * 
		 * @param left the matcher for the dividend
		 * @param right the matcher for the divisor
		 * @return the matcher for the quotient
		 */
		default ExpressionMatcher<DivExpression> div(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(DivExpression.class, left, right);
		}

		/**
		 * Match the form {@code L << R}
		 * 
		 * @param left the matcher for the left operand
		 * @param right the matcher for the shift amount
		 * @return the matcher
		 */
		default ExpressionMatcher<LeftShiftExpression> shl(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(LeftShiftExpression.class, left, right);
		}

		/**
		 * Match the form {@code L * R} or {@code R * L}
		 * 
		 * @param left the matcher for the left factor
		 * @param right the matcher for the right factor
		 * @return the matcher for the product
		 */
		default ExpressionMatcher<MultExpression> mul(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher.Commutative<>(MultExpression.class, left, right);
		}

		/**
		 * Match the form {@code L | R} or {@code R | L}
		 * 
		 * @param left the matcher for the left operand
		 * @param right the matcher for the right operand
		 * @return the matcher
		 */
		default ExpressionMatcher<OrExpression> or(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher.Commutative<>(OrExpression.class, left, right);
		}

		/**
		 * Match the form {@code L + R} or {@code R + L}
		 * 
		 * @param left the matcher for the left term
		 * @param right the matcher for the right term
		 * @return the matcher for the sum
		 */
		default ExpressionMatcher<PlusExpression> plus(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(PlusExpression.class, left, right);
		}

		/**
		 * Match the form {@code L >> R}
		 * 
		 * @param left the matcher for the left operand
		 * @param right the matcher for the shift amount
		 * @return the matcher
		 */
		default ExpressionMatcher<RightShiftExpression> shr(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(RightShiftExpression.class, left, right);
		}

		/**
		 * Match the form {@code L - R}
		 * 
		 * @param left the matcher for the left term
		 * @param right the matcher for the right term
		 * @return the matcher for the difference
		 */
		default ExpressionMatcher<SubExpression> sub(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(SubExpression.class, left, right);
		}

		/**
		 * Match the form {@code L $xor R} or {@code R $xor L}
		 * 
		 * @param left the matcher for the left operand
		 * @param right the matcher for the right operand
		 * @return the matcher
		 */
		default ExpressionMatcher<XorExpression> xor(ExpressionMatcher<?> left,
				ExpressionMatcher<?> right) {
			return new BinaryExpressionMatcher<>(XorExpression.class, left, right);
		}

		/**
		 * Match a given constant value
		 * 
		 * <p>
		 * <b>NOTE:</b> To match an unspecified constant value, use {@link #var(Class)} with
		 * {@link ConstantValue}.
		 * 
		 * @param value the value to match
		 * @return the matcher
		 */
		default ExpressionMatcher<ConstantValue> cv(long value) {
			return new ConstantValueMatcher(value);
		}

		/**
		 * Match any expression
		 * 
		 * <p>
		 * This matches any expression without consideration of its operands, except insofar when it
		 * appears in multiple places, it will check that subsequent matches are identical to the
		 * first.
		 * 
		 * @return the matcher
		 */
		default ExpressionMatcher<PatternExpression> var() {
			return AnyMatcher.any();
		}

		/**
		 * Match any expression of the given type
		 * 
		 * @param <T> the type of expression to match
		 * @param cls the class of expression to match
		 * @return the matcher
		 */
		default <T extends PatternExpression> ExpressionMatcher<T> var(Class<T> cls) {
			return new AnyMatcher<>(cls);
		}

		/**
		 * Match an operand value
		 * 
		 * <p>
		 * Typically, this must wrap any use of a field, since that field is considered an operand
		 * from the constructor's perspective.
		 * 
		 * @param def the matcher for the operand's defining expression.
		 * @return the operand matcher
		 */
		default ExpressionMatcher<OperandValue> opnd(ExpressionMatcher<?> def) {
			return new OperandValueMatcher(def);
		}

		/**
		 * Match a field by its size
		 * 
		 * <p>
		 * This matches either a {@link TokenField} or a {@link ContextField}. If matched, it then
		 * passes a {@link ConstantValue} of the field's size (in bits) into the given size matcher.
		 * 
		 * @param size the matcher for the field's size
		 * @return the field matcher
		 */
		default ExpressionMatcher<PatternValue> fldSz(ExpressionMatcher<?> size) {
			return new FieldSizeMatcher(size);
		}

		/**
		 * Match the form {@code -U}
		 * 
		 * @param unary the child matcher
		 * @return the matcher
		 */
		default ExpressionMatcher<MinusExpression> neg(ExpressionMatcher<?> unary) {
			return new UnaryExpressionMatcher<>(MinusExpression.class, unary);
		}

		/**
		 * Match the form {@code ~U}
		 * 
		 * @param unary the child matcher
		 * @return the matcher
		 */
		default ExpressionMatcher<NotExpression> not(ExpressionMatcher<?> unary) {
			return new UnaryExpressionMatcher<>(NotExpression.class, unary);
		}
	}
}
