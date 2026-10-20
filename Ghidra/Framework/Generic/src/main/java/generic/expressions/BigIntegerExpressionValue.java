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

import java.math.BigInteger;

/**
 * Long operand values. See {@link ExpressionValue}. Defines supported operators and other
 * operands for expression values that are long values.
 */
public class BigIntegerExpressionValue implements ExpressionValue {

	private final BigInteger value;

	public BigIntegerExpressionValue(BigInteger value) {
		this.value = value;
	}

	public BigIntegerExpressionValue(long longValue) {
		this.value = BigInteger.valueOf(longValue);
	}

	public BigInteger getValue() {
		return value;
	}

	@Override
	public String toString() {
		return value.toString();
	}

	public String toHexString() {
		String valueString = value.toString(16);
		if (valueString.startsWith("-")) {
			return "-0x" + valueString.substring(1);
		}
		return "0x" + valueString;
	}

	@Override
	public ExpressionValue applyUnaryOperator(ExpressionOperator operator)
			throws ExpressionException {
		switch (operator) {
			case BITWISE_NOT:
				return new BigIntegerExpressionValue(value.not());
			case LOGICAL_NOT:
				boolean b = value.equals(BigInteger.ZERO);
				return new BigIntegerExpressionValue(b ? BigInteger.ONE : BigInteger.ZERO);
			case UNARY_MINUS:
				return new BigIntegerExpressionValue(value.negate());
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
		if (!(operand instanceof BigIntegerExpressionValue bigIntegerOperand)) {
			throw new ExpressionException("Unsupported operand type for BigInteger: " + value);
		}
		BigInteger otherValue = bigIntegerOperand.getValue();

		switch (operator) {
			case BITWISE_AND:
				return new BigIntegerExpressionValue(value.and(otherValue));
			case BITWISE_OR:
				return new BigIntegerExpressionValue(value.or(otherValue));
			case BITWISE_XOR:
				return new BigIntegerExpressionValue(value.xor(otherValue));
			case DIVIDE:
				return new BigIntegerExpressionValue(value.divide(otherValue));
			case EQUALS:
				return new BigIntegerExpressionValue(
					value.equals(otherValue) ? BigInteger.ONE : BigInteger.ZERO);
			case GREATER_THAN:
				return new BigIntegerExpressionValue(
					value.compareTo(otherValue) > 0 ? BigInteger.ONE : BigInteger.ZERO);
			case GREATER_THAN_OR_EQUAL:
				return new BigIntegerExpressionValue(
					value.compareTo(otherValue) >= 0 ? BigInteger.ONE : BigInteger.ZERO);
			case SHIFT_LEFT:
				return new BigIntegerExpressionValue(value.shiftLeft(otherValue.intValue()));
			case LESS_THAN:
				return new BigIntegerExpressionValue(
					value.compareTo(otherValue) < 0 ? BigInteger.ONE : BigInteger.ZERO);
			case LESS_THAN_OR_EQUAL:
				return new BigIntegerExpressionValue(
					value.compareTo(otherValue) <= 0 ? BigInteger.ONE : BigInteger.ZERO);
			case LOGICAL_AND:
				boolean b1 = !value.equals(BigInteger.ZERO);
				boolean b2 = !otherValue.equals(BigInteger.ZERO);
				boolean result = b1 && b2;
				return new BigIntegerExpressionValue(result ? BigInteger.ONE : BigInteger.ZERO);
			case LOGICAL_OR:
				b1 = !value.equals(BigInteger.ZERO);
				b2 = !otherValue.equals(BigInteger.ZERO);
				result = b1 || b2;
				return new BigIntegerExpressionValue(result ? BigInteger.ONE : BigInteger.ZERO);
			case SUBTRACT:
				return new BigIntegerExpressionValue(value.subtract(otherValue));
			case NOT_EQUALS:
				return new BigIntegerExpressionValue(
					value.equals(otherValue) ? BigInteger.ONE : BigInteger.ZERO);
			case ADD:
				return new BigIntegerExpressionValue(value.add(otherValue));
			case SHIFT_RIGHT:
				return new BigIntegerExpressionValue(value.shiftRight(otherValue.intValue()));
			case MULTIPLY:
				return new BigIntegerExpressionValue(value.multiply(otherValue));
			default:
				throw new ExpressionException(
					"Binary Operator \"" + operator + "\" not supported by Long values!");
		}

	}

}
