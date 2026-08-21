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
package generic.expressions;

/**
 * Long operand values. See {@link ExpressionValue}. Defines supported operators and other
 * operands for expression values that are long values.
 */
public class LongExpressionValue implements ExpressionValue {

	private final long value;

	public LongExpressionValue(long value) {
		this.value = value;
	}

	public long getLongValue() {
		return value;
	}

	@Override
	public String toString() {
		return Long.toString(value);
	}

	@Override
	public ExpressionValue applyUnaryOperator(ExpressionOperator operator) throws ExpressionException {
		switch (operator) {
			case BITWISE_NOT:
				return new LongExpressionValue(~value);
			case LOGICAL_NOT:
				return new LongExpressionValue(value == 0 ? 1 : 0);
			case UNARY_MINUS:
				return new LongExpressionValue(-value);
			case UNARY_PLUS:
				return this;
			default:
				throw new ExpressionException(
					"Unary Operator " + operator + " not supported by Long values!");
		}
	}

	@Override
	public ExpressionValue applyBinaryOperator(ExpressionOperator operator, ExpressionValue operand)
			throws ExpressionException {
		if (!(operand instanceof LongExpressionValue longOperand)) {
			throw new ExpressionException("Unsupported operand type for Long: " + value);
		}
		long otherValue = longOperand.value;

		switch (operator) {
			case BITWISE_AND:
				return new LongExpressionValue(value & otherValue);
			case BITWISE_OR:
				return new LongExpressionValue(value | otherValue);
			case BITWISE_XOR:
				return new LongExpressionValue(value ^ otherValue);
			case DIVIDE:
				return new LongExpressionValue(value / otherValue);
			case EQUALS:
				return new LongExpressionValue(value == otherValue ? 1 : 0);
			case GREATER_THAN:
				return new LongExpressionValue(value > otherValue ? 1 : 0);
			case GREATER_THAN_OR_EQUAL:
				return new LongExpressionValue(value >= otherValue ? 1 : 0);
			case SHIFT_LEFT:
				return new LongExpressionValue(value << otherValue);
			case LESS_THAN:
				return new LongExpressionValue(value < otherValue ? 1 : 0);
			case LESS_THAN_OR_EQUAL:
				return new LongExpressionValue(value <= otherValue ? 1 : 0);
			case LOGICAL_AND:
				int b1 = value == 0 ? 0 : 1;
				int b2 = otherValue == 0 ? 0 : 1;
				return new LongExpressionValue(b1 & b2);
			case LOGICAL_OR:
				b1 = value == 0 ? 0 : 1;
				b2 = otherValue == 0 ? 0 : 1;
				return new LongExpressionValue(b1 | b2);
			case SUBTRACT:
				return new LongExpressionValue(value - otherValue);
			case NOT_EQUALS:
				return new LongExpressionValue(value == otherValue ? 0 : 1);
			case ADD:
				return new LongExpressionValue(value + otherValue);
			case SHIFT_RIGHT:
				return new LongExpressionValue(value >> otherValue);
			case MULTIPLY:
				return new LongExpressionValue(value * otherValue);
			default:
				throw new ExpressionException(
					"Binary Operator \"" + operator + "\" not supported by Long values!");
		}

	}

}
