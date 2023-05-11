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

import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.opbehavior.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;

/**
 * An interface that defines arithmetic p-code operations on values of type {@code T}.
 *
 * <p>
 * See {@link BytesPcodeArithmetic} for the typical pattern when implementing an arithmetic. There
 * are generally two cases: 1) Where endianness matters, 2) Where endianness does not matter. The
 * first is typical. The implementation should be an {@link Enum} with two constants, one for the
 * big endian implementation, and one for the little endian implementation. The class should also
 * provide static methods: {@code forEndian(boolean isBigEndian)} for getting the correct one based
 * on endianness, and {@code forLanguage(Language language)} for getting the correct one given a
 * language. If endianness does not matter, then the implementation should follow a singleton
 * pattern. See notes on {@link #getEndian()} for the endian-agnostic case.
 *
 * @param <T> the type of values operated on
 */
public interface PcodeArithmetic<T> {

	/**
	 * The number of bytes needed to encode the size (in bytes) of any value
	 */
	int SIZEOF_SIZEOF = 8;

	/**
	 * Reasons for requiring a concrete value
	 */
	enum Purpose {
		/** The value is needed to parse an instruction */
		DECODE(Reason.EXECUTE_DECODE),
		/** The value is needed for disassembly context */
		CONTEXT(Reason.EXECUTE_READ),
		/** The value is needed to decide a conditional branch */
		CONDITION(Reason.EXECUTE_READ),
		/** The value will be used as the address of an indirect branch */
		BRANCH(Reason.EXECUTE_READ),
		/** The value will be used as the address of a value to load */
		LOAD(Reason.EXECUTE_READ),
		/** The value will be used as the address of a value to store */
		STORE(Reason.EXECUTE_READ),
		/** Some other reason, perhaps for userop library use */
		OTHER(Reason.EXECUTE_READ),
		/** The user or a tool is inspecting the value */
		INSPECT(Reason.INSPECT);

		private final Reason reason;

		private Purpose(Reason reason) {
			this.reason = reason;
		}

		public Reason reason() {
			return reason;
		}
	}

	/**
	 * Get the endianness of this arithmetic
	 * 
	 * <p>
	 * Often T is a byte array, or at least represents one abstractly. Ideally, it is an array where
	 * each element is an abstraction of a byte. If that is the case, then the arithmetic likely has
	 * to interpret those bytes as integral values according to an endianness. This should return
	 * that endianness.
	 * 
	 * <p>
	 * If the abstraction has no notion of endianness, return null. In that case, the both
	 * {@link #fromConst(BigInteger, int, boolean)} and {@link #fromConst(long, int)} must be
	 * overridden. Furthermore, unless {@link #toConcrete(Object, Purpose)} is guaranteed to throw
	 * an exception, then {@link #toBigInteger(Object, Purpose)} and
	 * {@link #toLong(Object, Purpose)} must also be overridden.
	 * 
	 * @return the endianness or null
	 */
	Endian getEndian();

	/**
	 * Apply a unary operator to the given input
	 * 
	 * <p>
	 * Note the sizes of variables are given, because values don't necessarily have an intrinsic
	 * size. For example, a {@link BigInteger} may have a minimum encoding size, but that does not
	 * necessarily reflect the size of the variable from which is was read.
	 * 
	 * @implNote {@link OpBehaviorFactory#getOpBehavior(int)} for the given opcode is guaranteed to
	 *           return a derivative of {@link UnaryOpBehavior}.
	 * 
	 * @param opcode the p-code opcode
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizein1 the size (in bytes) of the input variable
	 * @param in1 the input value
	 * @return the output value
	 */
	T unaryOp(int opcode, int sizeout, int sizein1, T in1);

	/**
	 * Apply a unary operator to the given input
	 * 
	 * <p>
	 * This provides the full p-code op, allowing deeper inspection of the code. For example, an
	 * arithmetic may wish to distinguish immediate (constant) values from variables. By default,
	 * this unpacks the details and defers to {@link #unaryOp(int, int, int, Object)}.
	 * 
	 * @implNote {@link OpBehaviorFactory#getOpBehavior(int)} for the given opcode is guaranteed to
	 *           return a derivative of {@link UnaryOpBehavior}.
	 * 
	 * @param op the operation
	 * @param in1 the input value
	 * @return the output value
	 */
	default T unaryOp(PcodeOp op, T in1) {
		return unaryOp(op.getOpcode(), op.getOutput().getSize(), op.getInput(0).getSize(), in1);
	}

	/**
	 * Apply a binary operator to the given inputs
	 * 
	 * <p>
	 * Note the sizes of variables are given, because values don't necessarily have an intrinsic
	 * size. For example, a {@link BigInteger} may have a minimum encoding size, but that does not
	 * necessarily reflect the size of the variable from which is was read.
	 * 
	 * @implNote {@link OpBehaviorFactory#getOpBehavior(int)} for the given opcode is guaranteed to
	 *           return a derivative of {@link BinaryOpBehavior}.
	 * 
	 * @param op the operation
	 * @param b the behavior of the operator
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizein1 the size (in bytes) of the first (left) input variable
	 * @param in1 the first (left) input value
	 * @param sizein2 the size (in bytes) of the second (right) input variable
	 * @param in2 the second (right) input value
	 * @return the output value
	 */
	T binaryOp(int opcode, int sizeout, int sizein1, T in1, int sizein2, T in2);

	/**
	 * Apply a binary operator to the given input
	 * 
	 * <p>
	 * This provides the full p-code op, allowing deeper inspection of the code. For example, an
	 * arithmetic may wish to distinguish immediate (constant) values from variables. By default,
	 * this unpacks the details and defers to {@link #binaryOp(int, int, int, Object, int, Object)}.
	 * 
	 * @implNote {@link OpBehaviorFactory#getOpBehavior(int)} for the given opcode is guaranteed to
	 *           return a derivative of {@link BinaryOpBehavior}.
	 * 
	 * @param op
	 * @param in1
	 * @param in2
	 * @return the output value
	 */
	default T binaryOp(PcodeOp op, T in1, T in2) {
		return binaryOp(op.getOpcode(), op.getOutput().getSize(), op.getInput(0).getSize(), in1,
			op.getInput(1).getSize(), in2);
	}

	/**
	 * Apply the {@link PcodeOp#PTRADD} operator to the given inputs
	 * 
	 * <p>
	 * The "pointer add" op takes three operands: base, index, size; and is used as a more compact
	 * representation of array index address computation. The {@code size} operand must be constant.
	 * Suppose {@code arr} is an array whose elements are {@code size} bytes each, and the address
	 * of its first element is {@code base}. The decompiler would likely render the
	 * {@link PcodeOp#PTRADD} op as {@code &arr[index]}. An equivalent SLEIGH expression is
	 * {@code base + index*size}.
	 * 
	 * <p>
	 * NOTE: This op is always a result of decompiler simplification, not low p-code generation, and
	 * so are not ordinarily used by a {@link PcodeExecutor}.
	 * 
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizeinBase the size (in bytes) of the variable used for the array's base address
	 * @param inBase the value used as the array's base address
	 * @param sizeinIndex the size (in bytes) of the variable used for the index
	 * @param inIndex the value used as the index
	 * @param inSize the size of each array element in bytes
	 * @return the output value
	 */
	default T ptrAdd(int sizeout, int sizeinBase, T inBase, int sizeinIndex, T inIndex,
			int inSize) {
		T indexSized = binaryOp(PcodeOp.INT_MULT, sizeout,
			sizeinIndex, inIndex, 4, fromConst(inSize, 4));
		return binaryOp(PcodeOp.INT_ADD, sizeout,
			sizeinBase, inBase, sizeout, indexSized);
	}

	/**
	 * Apply the {@link PcodeOp#PTRSUB} operator to the given inputs
	 * 
	 * <p>
	 * The "pointer subfield" op takes two operands: base, offset; and is used as a more specific
	 * representation of structure field address computation. Its behavior is exactly equivalent to
	 * {@link PcodeOp#INT_ADD}. Suppose {@code st} is a structure pointer with a field {@code f}
	 * located {@link offset} bytes into the structure, and {@code st} has the value {@code base}.
	 * The decompiler would likely render the {@link PcodeOp#PTRSUB} op as {@code &st->f}. An
	 * equivalent SLEIGH expression is {@code base + offset}.
	 * 
	 * <p>
	 * NOTE: This op is always a result of decompiler simplification, not low p-code generation, and
	 * so are not ordinarily used by a {@link PcodeExecutor}.
	 * 
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizeinBase the size (in bytes) of the variable used for the structure's base address
	 * @param inBase the value used as the structure's base address
	 * @param sizeinOffset the size (in bytes) of the variable used for the offset
	 * @param inOffset the value used as the offset
	 * @return the output value
	 */
	default T ptrSub(int sizeout, int sizeinBase, T inBase, int sizeinOffset, T inOffset) {
		return binaryOp(PcodeOp.INT_ADD, sizeout, sizeinBase, inBase, sizeinOffset, inOffset);
	}

	/**
	 * Apply any modifications before a value is stored
	 * 
	 * <p>
	 * This implements any abstractions associated with {@link PcodeOp#STORE}. This is called on the
	 * address/offset and the value before the value is actually stored into the state.
	 * 
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizeinAddress the size (in bytes) of the variable used for indirection
	 * @param inAddress the value used as the address (or offset)
	 * @param sizeinValue the size (in bytes) of the variable to store
	 * @param inValue the value to store
	 * @return the modified value to store
	 */
	T modBeforeStore(int sizeout, int sizeinAddress, T inAddress, int sizeinValue, T inValue);

	/**
	 * Apply any modifications after a value is loaded
	 * 
	 * <p>
	 * This implements any abstractions associated with {@link PcodeOp#LOAD}. This is called on the
	 * address/offset and the value after the value is actually loaded from the state.
	 * 
	 * @param sizeout the size (in bytes) of the output variable
	 * @param sizeinAddress the size (in bytes) of the variable used for indirection
	 * @param inAddress the value used as the address (or offset)
	 * @param sizeinValue the size (in bytes) of the variable loaded
	 * @param inValue the value loaded
	 * @return the modified value loaded
	 */
	T modAfterLoad(int sizeout, int sizeinAddress, T inAddress, int sizeinValue, T inValue);

	/**
	 * Convert the given constant concrete value to type {@code T} having the same size.
	 * 
	 * @param value the constant value
	 * @return the value as a {@code T}
	 */
	T fromConst(byte[] value);

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
	default T fromConst(long value, int size) {
		return fromConst(Utils.longToBytes(value, size, getEndian().isBigEndian()));
	}

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
	default T fromConst(BigInteger value, int size, boolean isContextreg) {
		return fromConst(
			Utils.bigIntegerToBytes(value, size, isContextreg || getEndian().isBigEndian()));
	}

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
	 * Convert, if possible, the given abstract value to a concrete byte array
	 * 
	 * @param value the abstract value
	 * @param size the expected size (in bytes) of the array
	 * @param the reason why the emulator needs a concrete value
	 * @return the array
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	byte[] toConcrete(T value, Purpose purpose);

	/**
	 * Convert, if possible, the given abstract condition to a concrete boolean value
	 * 
	 * @param cond the abstract condition
	 * @param purpose probably {@link Purpose#CONDITION}
	 * @return the boolean value
	 */
	default boolean isTrue(T cond, Purpose purpose) {
		byte[] concrete = toConcrete(cond, purpose);
		for (byte b : concrete) {
			if (b != 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convert, if possible, the given abstract value to a concrete big integer
	 * 
	 * <p>
	 * If the conversion is not possible, throw an exception.
	 * 
	 * @param value the abstract value
	 * @param purpose the reason why the emulator needs a concrete value
	 * @return the concrete value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default BigInteger toBigInteger(T value, Purpose purpose) {
		byte[] concrete = toConcrete(value, purpose);
		return Utils.bytesToBigInteger(concrete, concrete.length,
			purpose == Purpose.CONTEXT || getEndian().isBigEndian(), false);
	}

	/**
	 * Convert, if possible, the given abstract value to a concrete long
	 * 
	 * <p>
	 * If the conversion is not possible, throw an exception.
	 * 
	 * @param value the abstract value
	 * @param purpose the reason why the emulator needs a concrete value
	 * @return the concrete value
	 * @throws ConcretionError if the value cannot be made concrete
	 */
	default long toLong(T value, Purpose purpose) {
		byte[] concrete = toConcrete(value, purpose);
		return Utils.bytesToLong(concrete, concrete.length,
			purpose == Purpose.CONTEXT || getEndian().isBigEndian());
	}

	/**
	 * Get the size in bytes, if possible, of the given abstract value
	 * 
	 * <p>
	 * If the abstract value does not conceptually have a size, throw an exception.
	 * 
	 * @param value the abstract value
	 * @return the size in bytes
	 */
	long sizeOf(T value);

	/**
	 * Get the size in bytes, if possible, of the given abstract value, as an abstract value
	 * 
	 * <p>
	 * The returned size should itself has a size of {@link #SIZEOF_SIZEOF}.
	 * 
	 * @param value the abstract value
	 * @return the size in bytes, as an abstract value
	 */
	default T sizeOfAbstract(T value) {
		return fromConst(sizeOf(value), SIZEOF_SIZEOF);
	}
}
