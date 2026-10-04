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

import java.math.BigInteger;

import generic.expressions.BigIntegerExpressionValue;
import generic.expressions.ExpressionException;
import generic.expressions.ExpressionOperator;
import generic.expressions.ExpressionValue;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;

/**
 * Address operand values. See {@link ExpressionValue}. Defines supported operators and other
 * operands for expression values that are addresses.
 */
public class AddressExpressionValue implements ExpressionValue {
	private Address value;

	public AddressExpressionValue(Address address) {
		this.value = address;
	}

	public AddressExpressionValue(AddressSpace space, BigInteger value) throws ExpressionException {
		this.value = toAddress(space, value);
	}

	@Override
	public ExpressionValue applyUnaryOperator(ExpressionOperator operator)
			throws ExpressionException {
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
		return new AddressExpressionValue(addressOf(offset));
	}

	private AddressExpressionValue addressExpressionOf(BigInteger bigIntValue)
			throws ExpressionException {
		Address address = toAddress(value.getAddressSpace(), bigIntValue);
		return new AddressExpressionValue(address);
	}

	private Address toAddress(AddressSpace space, BigInteger value) throws ExpressionException {
		if (value.signum() < 0) {
			// a negative value is less than than min address
			throw new AddressOutOfBoundsException(
				"Address out of bounds. Expression evaluated to a negative value: " + value);
		}

		if (isBiggerThanMaxAddress(space, value)) {
			throw new AddressOutOfBoundsException(
				"Address out of bounds. Expression evaluated to a value larger than max address: " +
					value);
		}

		return toAddress(value.longValue(), space);
	}

	private Address toAddress(long value, AddressSpace space) throws ExpressionException {
		try {
			return space.getAddressInThisSpaceOnly(value);
		}
		catch (AddressOutOfBoundsException e) {
			throw new ExpressionException(e.getMessage());
		}
	}

	private boolean isBiggerThanMaxAddress(AddressSpace space, BigInteger value) {
		BigInteger byteOffset = computeByteOffset(space, value);
		Address maxAddress = space.getMaxAddress();
		long unsignedOffset = maxAddress.getOffset();
		BigInteger max = new BigInteger(Long.toUnsignedString(unsignedOffset));
		return byteOffset.compareTo(max) > 0;
	}

	private BigInteger computeByteOffset(AddressSpace space, BigInteger value) {
		int bytesPerAddress = space.getAddressableUnitSize();	// this is 1 for most programs
		return value.multiply(BigInteger.valueOf(bytesPerAddress));
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

		if (operand instanceof BigIntegerExpressionValue bigIntValue) {
			return applyBinaryOperator(operator, bigIntValue);
		}

		if (operand instanceof AddressExpressionValue addressOperand) {
			return applyBinaryOperator(operator, addressOperand);
		}
		throw new ExpressionException("Unsupported operand type for Long: " + value);

	}

	private ExpressionValue applyBinaryOperator(ExpressionOperator operator,
			BigIntegerExpressionValue expressionValue) throws ExpressionException {
		BigInteger otherValue = expressionValue.getValue();
		BigInteger myValue = new BigInteger(Long.toUnsignedString(value.getOffset()));
		int compareResult = myValue.compareTo(otherValue);

		switch (operator) {
			case BITWISE_AND:
				return addressExpressionOf(myValue.and(otherValue));
			case BITWISE_OR:
				return addressExpressionOf(myValue.or(otherValue));
			case BITWISE_XOR:
				return addressExpressionOf(myValue.xor(otherValue));
			case DIVIDE:
				return addressExpressionOf(myValue.divide(otherValue));
			case SUBTRACT:
				return addressExpressionOf(value.subtract(otherValue.longValueExact()));
			case ADD:
				return addressExpressionOf(value.add(otherValue.longValueExact()));
			case MULTIPLY:
				return addressExpressionOf(myValue.multiply(otherValue));
			case SHIFT_LEFT:
				return addressExpressionOf(myValue.shiftLeft(otherValue.intValueExact()));
			case SHIFT_RIGHT:
				return addressExpressionOf(myValue.shiftRight(otherValue.intValueExact()));
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
		return new BigIntegerExpressionValue(b ? 1 : 0);
	}

	private ExpressionValue unsignedValue(long unsignedLong) {
		BigInteger value = new BigInteger(Long.toUnsignedString(unsignedLong));
		return new BigIntegerExpressionValue(value);
	}

	private ExpressionValue applyBinaryOperator(ExpressionOperator operator,
			AddressExpressionValue expressionValue) throws ExpressionException {
		Address otherValue = expressionValue.getAddress();
		long otherValueOffset = otherValue.getOffset();
		long offset = value.getOffset();
		int compareResult = value.compareTo(otherValue);

		switch (operator) {
			case BITWISE_AND:
				return unsignedValue(offset & otherValueOffset);
			case BITWISE_OR:
				return unsignedValue(offset | otherValueOffset);
			case BITWISE_XOR:
				return unsignedValue(offset ^ otherValueOffset);
			case SUBTRACT:
				return new BigIntegerExpressionValue(value.subtract(otherValue));
			case ADD:
				return new BigIntegerExpressionValue(offset + otherValueOffset);
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
