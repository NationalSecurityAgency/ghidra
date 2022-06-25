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
package ghidra.pcode.exec;

import java.math.BigInteger;

import ghidra.pcode.opbehavior.*;
import ghidra.program.model.pcode.PcodeOp;

/**
 * An interface that defines arithmetic p-code operations on values of type {@code T}.
 *
 * @param <T> the type of values operated on
 */
public interface PcodeArithmetic<T> {
	BinaryOpBehavior INT_ADD =
		(BinaryOpBehavior) OpBehaviorFactory.getOpBehavior(PcodeOp.INT_ADD);
	UnaryOpBehavior INT_ZEXT =
		(UnaryOpBehavior) OpBehaviorFactory.getOpBehavior(PcodeOp.INT_ZEXT);

	/**
	 * The number of bytes needed to encode the size (in bytes) of any value
	 */
	int SIZEOF_SIZEOF = 8;

	/**
	 * The arithmetic for operating on bytes in big-endian
	 */
	PcodeArithmetic<byte[]> BYTES_BE = BytesPcodeArithmetic.BIG_ENDIAN;
	/**
	 * The arithmetic for operating on bytes in little-endian
	 */
	PcodeArithmetic<byte[]> BYTES_LE = BytesPcodeArithmetic.LITTLE_ENDIAN;
	/**
	 * The arithmetic for operating on {@link BigInteger}s.
	 */
	@Deprecated(forRemoval = true) // TODO: Not getting used
	PcodeArithmetic<BigInteger> BIGINT = BigIntegerPcodeArithmetic.INSTANCE;

	/**
	 * Apply a unary operator to the given input
	 * 
	 * <p>
	 * Note the sizes of variables are given, because values don't necessarily have an intrinsic
	 * size. For example, a {@link BigInteger} may have a minimum encoding size, but that does not
	 * necessarily reflect the size of the variable from which is was read.
	 * 
	 * @param op the behavior of the operator
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizein1 the size (in bytes) of the input variable
	 * @param in1 the input value
	 * @return the output value
	 */
	T unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, T in1);

	/**
	 * Apply a binary operator to the given inputs
	 * 
	 * <p>
	 * Note the sizes of variables are given, because values don't necessarily have an intrinsic
	 * size. For example, a {@link BigInteger} may have a minimum encoding size, but that does not
	 * necessarily reflect the size of the variable from which is was read.
	 * 
	 * @param op the behavior of the operator
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizein1 the size (in bytes) of the first (left) input variable
	 * @param in1 the first (left) input value
	 * @param sizein2 the size (in bytes) of the second (right) input variable
	 * @param in2 the second (right) input value
	 * @return the output value
	 */
	T binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, T in1, int sizein2, T in2);

	/**
	 * Convert the given constant concrete value to type {@code T} having the given size.
	 * 
	 * <p>
	 * Note that the size may not be applicable to {@code T}. It is given to ensure the value can be
	 * held in a variable of that size when passed to downstream operators or stored in the executor
	 * state.
	 * 
	 * @param value the constant value
	 * @param size the size (in bytes) of the variable into which the value is to be stored
	 * @return the value as a {@code T}
	 */
	T fromConst(long value, int size);

	/**
	 * Convert the given constant concrete value to type {@code T} having the given size.
	 * 
	 * <p>
	 * Note that the size may not be applicable to {@code T}. It is given to ensure the value can be
	 * held in a variable of that size when passed to downstream operators or stored in the executor
	 * state.
	 * 
	 * @param value the constant value
	 * @param size the size (in bytes) of the variable into which the value is to be stored
	 * @param isContextreg true to indicate the value is from the disassembly context register. If
	 *            {@code T} represents bytes, and the value is the contextreg, then the bytes are in
	 *            big endian, no matter the machine language's endianness.
	 * @return the value as a {@code T}
	 */
	T fromConst(BigInteger value, int size, boolean isContextreg);

	/**
	 * Convert the given constant concrete value to type {@code T} having the given size.
	 * 
	 * <p>
	 * The value is assumed <em>not</em> to be for the disassembly context register.
	 * 
	 * @see #fromConst(BigInteger, int, boolean)
	 */
	default T fromConst(BigInteger value, int size) {
		return fromConst(value, size, false);
	}

	/**
	 * Convert, if possible, the given abstract condition to a concrete boolean value
	 * 
	 * @param cond the abstract condition
	 * @return the boolean value
	 */
	boolean isTrue(T cond);

	/**
	 * Convert, if possible, the given abstract value to a concrete value
	 * 
	 * <p>
	 * If the conversion is not possible, throw an exception. TODO: Decide on conventions of which
	 * exception to throw and/or establish a hierarchy of checked exceptions.
	 * 
	 * @param value the abstract value
	 * @param isContextreg true to indicate the value is from the disassembly context register. If
	 *            {@code T} represents bytes, and the value is the contextreg, then the bytes are in
	 *            big endian, no matter the machine language's endianness.
	 * @return the concrete value
	 */
	BigInteger toConcrete(T value, boolean isContextreg);

	/**
	 * Make concrete, if possible, the given abstract value
	 * 
	 * <p>
	 * If the conversion is not possible, throw an exception. TODO: Decide on conventions of which
	 * exception to throw and/or establish a hierarchy of checked exceptions.
	 * 
	 * @param value the abstract value
	 * @return the concrete value
	 */
	default BigInteger toConcrete(T value) {
		return toConcrete(value, false);
	}

	/**
	 * Get the size in bytes, if possible, of the given abstract value
	 * 
	 * <p>
	 * If the abstract value does not conceptually have a size, throw an exception. Note the
	 * returned size should itself have a size of {@link #SIZEOF_SIZEOF}. TODO: Establish
	 * conventions for exceptions.
	 * 
	 * @param value the abstract value
	 * @return the size in bytes
	 */
	T sizeOf(T value);
}
