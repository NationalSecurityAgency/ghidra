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
package ghidra.program.util;

import generic.expressions.*;
import ghidra.program.model.address.Address;

/**
 * Address operand values. See {@link ExpressionValue}. Defines supported operators and other
 * operands for expression values that are addresses.
 */
public class AddressExpressionValue implements ExpressionValue {
	private Address value;

	public AddressExpressionValue(Address address) {
		this.value = address;
	}

	@Override
	public ExpressionValue applyUnaryOperator(ExpressionOperator operator) throws ExpressionException {
		long offset = value.getOffset();
		switch (operator) {
			case BITWISE_NOT:
				return addressExpressionOf(~offset);
			case UNARY_MINUS:
				return addressExpressionOf(-offset);
			case UNARY_PLUS:
				return this;
			default:
				throw new ExpressionException(
					"Unary Operator " + operator + " not supported by Long values!");
		}
	}

	private AddressExpressionValue addressExpressionOf(long offset) {
		Address address = value.getNewAddress(offset);
		return new AddressExpressionValue(addressOf(offset));
	}

	private AddressExpressionValue addressExpressionOf(Address address) {
		return new AddressExpressionValue(address);
	}

	private Address addressOf(long offset) {
		return value.getNewAddress(offset);
	}

	@Override
	public ExpressionValue applyBinaryOperator(ExpressionOperator operator, ExpressionValue operand)
			throws ExpressionException {

		if (operand instanceof LongExpressionValue longOperand) {
			return applyBinaryOperator(operator, longOperand);
		}

		if (operand instanceof AddressExpressionValue addressOperand) {
			return applyBinaryOperator(operator, addressOperand);
		}
		throw new ExpressionException("Unsupported operand type for Long: " + value);

	}

	private ExpressionValue applyBinaryOperator(ExpressionOperator operator,
			LongExpressionValue expressionValue) throws ExpressionException {
		long otherValue = expressionValue.getLongValue();
		long offset = value.getOffset();
		int compareResult = Long.compareUnsigned(offset, otherValue);

		switch (operator) {
			case BITWISE_AND:
				return addressExpressionOf(offset & otherValue);
			case BITWISE_OR:
				return addressExpressionOf(offset | otherValue);
			case BITWISE_XOR:
				return addressExpressionOf(offset ^ otherValue);
			case DIVIDE:
				return addressExpressionOf(offset / otherValue);
			case SUBTRACT:
				return addressExpressionOf(value.subtract(otherValue));
			case ADD:
				return addressExpressionOf(value.add(otherValue));
			case MULTIPLY:
				return addressExpressionOf(offset * otherValue);
			case SHIFT_LEFT:
				return addressExpressionOf(offset << otherValue);
			case SHIFT_RIGHT:
				return addressExpressionOf(offset >> otherValue);
			case EQUALS:
				return booleanExpression(compareResult == 0);
			case GREATER_THAN:
				return booleanExpression(compareResult > 0);
			case LESS_THAN:
				return booleanExpression(compareResult < 0);
			case GREATER_THAN_OR_EQUAL:
				return booleanExpression(compareResult >= 0);
			case LESS_THAN_OR_EQUAL:
				return booleanExpression(compareResult <= 0);

			default:
				throw new ExpressionException(
					"Binary Operator \"" + operator +
						"\" with Long operands not supported by Address values!");
		}
	}

	private ExpressionValue booleanExpression(boolean b) {
		return new LongExpressionValue(b ? 1 : 0);
	}

	private ExpressionValue applyBinaryOperator(ExpressionOperator operator,
			AddressExpressionValue expressionValue) throws ExpressionException {
		Address otherValue = expressionValue.getAddress();
		long otherValueOffset = otherValue.getOffset();
		long offset = value.getOffset();
		int compareResult = value.compareTo(otherValue);

		switch (operator) {
			case BITWISE_AND:
				return new LongExpressionValue(offset & otherValueOffset);
			case BITWISE_OR:
				return new LongExpressionValue(offset | otherValueOffset);
			case BITWISE_XOR:
				return new LongExpressionValue(offset ^ otherValueOffset);
			case SUBTRACT:
				return new LongExpressionValue(value.subtract(otherValue));
			case ADD:
				return new LongExpressionValue(offset + otherValueOffset);
			case EQUALS:
				return booleanExpression(compareResult == 0);
			case GREATER_THAN:
				return booleanExpression(compareResult > 0);
			case LESS_THAN:
				return booleanExpression(compareResult < 0);
			case GREATER_THAN_OR_EQUAL:
				return booleanExpression(compareResult >= 0);
			case LESS_THAN_OR_EQUAL:
				return booleanExpression(compareResult <= 0);
			default:
				throw new ExpressionException(
					"Binary Operator \"" + operator +
						"\" with Long operands not supported by Address values!");
		}
	}

	public Address getAddress() {
		return value;
	}

	@Override
	public String toString() {
		return value.toString();
	}

}
