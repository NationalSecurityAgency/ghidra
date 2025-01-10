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
package ghidra.pcode.emu.jit.gen.type;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.objectweb.asm.*;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.BinOpGen;
import ghidra.pcode.emu.jit.gen.op.IntSExtOpGen;
import ghidra.pcode.emu.jit.op.JitBinOp;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The generator for various type conversion.
 * 
 * <p>
 * These conversions are no more than bitwise casts. The underlying bits are unchanged, but the
 * interpretation and/or the way the JVM has tagged them does.
 * 
 * <p>
 * Many of the methods (and also many other bits of the code generator) follow a convention where
 * the input type(s) are passed as parameter(s), and the resulting type is returned. In many cases
 * the desired type is also taken as a parameter. Upon success, we'd expect that desired type to be
 * the exact type returned, but this may not always be the case. This convention ensures all pieces
 * of the generator know the p-code type (and thus JVM type) of the variable at the top of the JVM
 * stack.
 * 
 * <p>
 * Type conversions are applicable at a few boundaries:
 * <ul>
 * <li>To ensure use-def values conform to the requirements of the operands where they are used and
 * defined. The {@link JitTypeModel} aims to reduce the number of conversions required by assigning
 * appropriate types to the use-def value nodes, but this will not necessarily eliminate them
 * all.</li>
 * <li>Within the implementation of an operator, type conversions may be necessary to ensure the
 * p-code types of input operands conform with the JVM types required by the emitted bytecodes, and
 * that the output JVM type conforms to the p-code type of the output operand.</li>
 * <li>When loading or storing as bytes from the {@link JitBytesPcodeExecutorState state}. The
 * conversion from and to bytes is done using JVM integral types, and so the value may be converted
 * if the operand requires a floating-point type.</li>
 * </ul>
 */
public interface TypeConversions extends Opcodes {
	/**
	 * Emit an {@link Opcodes#IAND} to reduce the number of bits to those permitted in an int of the
	 * given size.
	 * 
	 * <p>
	 * For example to mask from an {@link IntJitType#I4 int4} to an {@link IntJitType#I2}, this
	 * would emit {@code iand 0xffff}. If the source size is smaller than or equal to that of the
	 * destination, nothing is emitted.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 */
	static void checkGenIntMask(JitType from, IntJitType to, MethodVisitor mv) {
		if (to.size() < from.size() && to.size() < Integer.BYTES) {
			mv.visitLdcInsn(-1 >>> (Integer.SIZE - to.size() * Byte.SIZE));
			mv.visitInsn(IAND);
		}
	}

	/**
	 * Emit bytecode to convert one p-code in (in a JVM int) to another
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static IntJitType generateIntToInt(IntJitType from, IntJitType to, MethodVisitor mv) {
		checkGenIntMask(from, to, mv);
		return to;
	}

	/**
	 * Emit bytecode to convert one p-code int (in a JVM long) to one in a JVM int.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static IntJitType generateLongToInt(LongJitType from, IntJitType to, MethodVisitor mv) {
		mv.visitInsn(L2I);
		checkGenIntMask(from, to, mv);
		return to;
	}

	/**
	 * Emit bytecode to convert a {@link FloatJitType#F4 float4} to an {@link IntJitType#I4 int4}.
	 * 
	 * @param from the source type (must be {@link FloatJitType#F4 float4})
	 * @param to the destination type (must be {@link IntJitType#I4 int4})
	 * @param mv the method visitor
	 * @return the destination type ({@link IntJitType#I4 int4})
	 */
	static IntJitType generateFloatToInt(FloatJitType from, IntJitType to, MethodVisitor mv) {
		if (to.size() != from.size()) {
			throw new AssertionError("Size mismatch");
		}
		mv.visitMethodInsn(INVOKESTATIC, NAME_FLOAT, "floatToRawIntBits",
			MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS, false);
		return to;
	}

	/**
	 * Emit bytecode to convert a mult-precision int to a p-code int that fits in a JVM int.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static IntJitType generateMpIntToInt(MpIntJitType from, IntJitType to, MethodVisitor mv) {
		if (to.size() == from.size()) {
			// We're done. The one leg on the stack becomes the int
			return to;
		}
		// Remove all but the least-significant leg
		for (int i = 1; i < from.legsAlloc(); i++) {
			// [...,legN-1,legN]
			mv.visitInsn(SWAP);
			// [...,legN,legN-1]
			mv.visitInsn(POP);
			// [...,legN]
		}
		checkGenIntMask(from, to, mv);
		return to;
	}

	/**
	 * Emit bytecode to convert any (compatible) type to a p-code int that fits in a JVM int.
	 * 
	 * <p>
	 * The only acceptable floating-point source type is {@link FloatJitType#F4 float4}.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static IntJitType generateToInt(JitType from, IntJitType to, MethodVisitor mv) {
		return switch (from) {
			case IntJitType iFrom -> generateIntToInt(iFrom, to, mv); // in case of mask
			case LongJitType lFrom -> generateLongToInt(lFrom, to, mv);
			case FloatJitType fFrom -> generateFloatToInt(fFrom, to, mv);
			case DoubleJitType dFrom -> throw new AssertionError("Size mismatch");
			case MpIntJitType mpFrom -> generateMpIntToInt(mpFrom, to, mv);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit an {@link Opcodes#LAND} to reduce the number of bits to those permitted in an int of the
	 * given size.
	 * 
	 * <p>
	 * For example to mask from a {@link LongJitType#I8 int8} to a {@link LongJitType#I6}, this
	 * would emit {@code land 0x0ffffffffffffL}. If the source size is smaller than or equal to that
	 * of the destination, nothing is emitted.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 */
	static void checkGenLongMask(JitType from, LongJitType to, MethodVisitor mv) {
		if (to.size() < from.size()) {
			mv.visitLdcInsn(-1L >>> (Long.SIZE - to.size() * Byte.SIZE));
			mv.visitInsn(LAND);
		}
	}

	/**
	 * Emit bytecode to convert one p-code int (in a JVM int) to one in a JVM long.
	 * 
	 * <p>
	 * Care must be taken to ensure conversions to larger types extend with zeros (unsigned).
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static LongJitType generateIntToLong(IntJitType from, LongJitType to, MethodVisitor mv) {
		mv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "toUnsignedLong",
			MDESC_INTEGER__TO_UNSIGNED_LONG, false);
		// In theory, never necessary, unless long is used temporarily with size 1-4.
		checkGenLongMask(from, to, mv);
		return to;
	}

	/**
	 * Emit bytecode to convert one p-code in (in a JVM long) to another
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static LongJitType generateLongToLong(LongJitType from, LongJitType to, MethodVisitor mv) {
		checkGenLongMask(from, to, mv);
		return to;
	}

	/**
	 * Emit bytecode to convert a {@link DoubleJitType#F8 float8} to an {@link LongJitType#I8 int8}.
	 * 
	 * @param from the source type (must be {@link DoubleJitType#F8 float8})
	 * @param to the destination type (must be {@link LongJitType#I8 int8})
	 * @param mv the method visitor
	 * @return the destination type ({@link LongJitType#I8 int8})
	 */
	static LongJitType generateDoubleToLong(DoubleJitType from, LongJitType to, MethodVisitor mv) {
		if (to.size() != from.size()) {
			throw new AssertionError("Size mismatch");
		}
		mv.visitMethodInsn(INVOKESTATIC, NAME_DOUBLE, "doubleToRawLongBits",
			MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS, false);
		return to;
	}

	/**
	 * Emit bytecode to convert a mult-precision int to a p-code int that fits in a JVM long.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static LongJitType generateMpIntToLong(MpIntJitType from, LongJitType to, MethodVisitor mv) {
		if (from.legsAlloc() == 1) {
			generateIntToLong(IntJitType.forSize(from.size()), to, mv);
			return to;
		}
		// Remove all but the 2 least-significant legs
		for (int i = 2; i < from.legsAlloc(); i++) {
			// [...,legN-2,legN-1,legN]
			mv.visitInsn(DUP2_X1);
			// [...,legN-1,legN,legN-2,legN-1,legN]
			mv.visitInsn(POP2);
			// [...,legN-1,legN,legN-2]
			mv.visitInsn(POP);
			// [...,legN-1,legN]
		}
		mv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "conv2IntToLong",
			MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG, false);
		return to;
	}

	/**
	 * Emit bytecode to convert any (compatible) type to a p-code that fits in a JVM long.
	 * 
	 * <p>
	 * The only acceptable floating-point source type is {@link DoubleJitType#F8 float8}.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static LongJitType generateToLong(JitType from, LongJitType to, MethodVisitor mv) {
		return switch (from) {
			case IntJitType iFrom -> generateIntToLong(iFrom, to, mv);
			case LongJitType lFrom -> generateLongToLong(lFrom, to, mv); // in case of mask
			case FloatJitType fFrom -> throw new AssertionError("Size mismatch");
			case DoubleJitType dFrom -> generateDoubleToLong(dFrom, to, mv);
			case MpIntJitType mpFrom -> generateMpIntToLong(mpFrom, to, mv);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to convert an {@link IntJitType#I4 int4} to a {@link FloatJitType#F4 float4}.
	 * 
	 * @param from the source type (must be {@link IntJitType#I4 int4})
	 * @param to the destination type (must be {@link FloatJitType#F4 float4})
	 * @param mv the method visitor
	 * @return the destination type ({@link FloatJitType#F4 float4})
	 */
	static FloatJitType generateIntToFloat(IntJitType from, FloatJitType to, MethodVisitor mv) {
		if (to.size() != from.size()) {
			throw new AssertionError("Size mismatch");
		}
		mv.visitMethodInsn(INVOKESTATIC, NAME_FLOAT, "intBitsToFloat",
			MDESC_FLOAT__INT_BITS_TO_FLOAT, false);
		return to;
	}

	/**
	 * Emit bytecode to convert any (compatible) type to a {@link FloatJitType#F4 float4}.
	 * 
	 * @param from the source type ({@link IntJitType#I4 int4} or {@link FloatJitType#F4 float4})
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type ({@link FloatJitType#F4 float4})
	 */
	static FloatJitType generateToFloat(JitType from, FloatJitType to, MethodVisitor mv) {
		return switch (from) {
			case IntJitType iFrom -> generateIntToFloat(iFrom, to, mv);
			case LongJitType lFrom -> throw new AssertionError("Size mismatch");
			case FloatJitType fFrom -> to;
			case DoubleJitType dFrom -> throw new AssertionError("Size mismatch");
			case MpIntJitType mpFrom -> throw new AssertionError("Size mismatch");
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to convert an {@link LongJitType#I8 int8} to a {@link DoubleJitType#F8 float8}.
	 * 
	 * @param from the source type (must be {@link LongJitType#I8 int8})
	 * @param to the destination type (must be {@link DoubleJitType#F8 float8})
	 * @param mv the method visitor
	 * @return the destination type ({@link DoubleJitType#F8 float8})
	 */
	static DoubleJitType generateLongToDouble(LongJitType from, DoubleJitType to,
			MethodVisitor mv) {
		if (to.size() != from.size()) {
			throw new AssertionError("Size mismatch");
		}
		mv.visitMethodInsn(INVOKESTATIC, NAME_DOUBLE, "longBitsToDouble",
			MDESC_DOUBLE__LONG_BITS_TO_DOUBLE, false);
		return to;
	}

	/**
	 * Emit bytecode to convert any (compatible) type to a {@link DoubleJitType#F8 float8}.
	 * 
	 * @param from the source type ({@link LongJitType#I8 int8} or {@link DoubleJitType#F8 float8})
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type ({@link DoubleJitType#F8 float8})
	 */
	static DoubleJitType generateToDouble(JitType from, DoubleJitType to, MethodVisitor mv) {
		return switch (from) {
			case IntJitType iFrom -> throw new AssertionError("Size mismatch");
			case LongJitType lFrom -> generateLongToDouble(lFrom, to, mv);
			case FloatJitType fFrom -> throw new AssertionError("Size mismatch");
			case DoubleJitType dFrom -> to;
			case MpIntJitType mpFrom -> throw new AssertionError("Size mismatch");
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to convert a p-code int that fits in a JVM int to a multi-precision int.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static MpIntJitType generateIntToMpInt(IntJitType from, MpIntJitType to, MethodVisitor mv) {
		if (to.legsAlloc() == 1) {
			checkGenIntMask(from, IntJitType.forSize(to.size()), mv);
			return to;
		}
		// Insert as many more significant legs as needed
		for (int i = 1; i < to.legsAlloc(); i++) {
			mv.visitLdcInsn(0);
			mv.visitInsn(SWAP);
		}
		return to;
	}

	/**
	 * Emit bytecode to convert a p-code int that its int a JVM long to multi-precision int.
	 * 
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static MpIntJitType generateLongToMpInt(LongJitType from, MpIntJitType to, MethodVisitor mv) {
		if (to.legsAlloc() == 1) {
			mv.visitInsn(L2I);
			checkGenIntMask(from, IntJitType.forSize(to.size()), mv);
			return to;
		}
		if (from.size() <= Integer.BYTES) {
			mv.visitInsn(L2I);
			generateIntToMpInt(IntJitType.forSize(from.size()), to, mv);
			return to;
		}
		// Convert, then insert as many more significant legs as needed

		/** Can't just invoke a static method, because two ints have to result */
		// [val:LONG]
		mv.visitInsn(DUP2);
		// [val:LONG,val:LONG]
		mv.visitLdcInsn(Integer.SIZE);
		mv.visitInsn(LUSHR);
		mv.visitInsn(L2I);
		/** This is the upper leg, which may need masking */
		checkGenIntMask(IntJitType.forSize(from.size() - Integer.BYTES),
			IntJitType.forSize(to.partialSize()), mv);
		// [val:LONG,msl:INT]
		mv.visitInsn(DUP_X2);
		// [msl:INT,val:LONG,msl:INT]
		mv.visitInsn(POP);
		// [msl:INT,val:LONG]
		mv.visitInsn(L2I);
		// [msl:INT,lsl:INT]

		// Now add legs
		if (to.legsAlloc() > 2) {
			mv.visitLdcInsn(0);
			// [msl:INT,lsl:INT,0]
			for (int i = 2; i < to.legsAlloc(); i++) {
				// [msl:INT,lsl:INT,0]
				mv.visitInsn(DUP_X2);
				// [0,msl:INT,lsl:INT,0]
			}
			// [...,0,msl:INT,lsl:INT,0]
			mv.visitInsn(POP);
			// [...,0,msl:INT,lsl:INT]
		}
		return to;
	}

	/**
	 * Emit bytecode to convert a mult-precision int from one size to another
	 * 
	 * @param gen the code generator
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static MpIntJitType generateMpIntToMpInt(JitCodeGenerator gen, MpIntJitType from,
			MpIntJitType to, MethodVisitor mv) {
		if (to.size() == from.size()) {
			// Nothing to convert
			return to;
		}
		// Some special cases to avoid use of local variables:
		if (to.legsAlloc() == 1) {
			generateMpIntToInt(from, IntJitType.forSize(to.size()), mv);
			return to;
		}
		if (from.legsAlloc() == 1) {
			generateIntToMpInt(IntJitType.forSize(from.size()), to, mv);
			return to;
		}

		// Okay, now it's complicated
		int legsIn = from.legsAlloc();
		int legsOut = to.legsAlloc();
		int localsCount = Integer.min(legsIn, legsOut);
		int firstIndex = gen.getAllocationModel().nextFreeLocal();
		Label localsStart = new Label();
		Label localsEnd = new Label();
		mv.visitLabel(localsStart);
		for (int i = 0; i < localsCount; i++) {
			mv.visitLocalVariable("temp" + i, Type.getDescriptor(int.class), null, localsStart,
				localsEnd, firstIndex + i);
			mv.visitVarInsn(ISTORE, firstIndex + i);
		}

		// Add or remove legs
		int toAdd = legsOut - legsIn;
		for (int i = 0; i < toAdd; i++) {
			mv.visitLdcInsn(0);
		}
		int toRemove = legsIn - legsOut;
		for (int i = 0; i < toRemove; i++) {
			mv.visitInsn(POP);
		}

		// Start pushing them back, but the most significant may need masking
		int idx = firstIndex + localsCount;
		idx--;
		mv.visitVarInsn(ILOAD, idx);
		if (to.size() < from.size()) {
			checkGenIntMask(
				from, // already checked size, so anything greater 
				IntJitType.forSize(to.partialSize()), mv);
		}
		// push the rest back
		for (int i = 0; i < localsCount; i++) {
			idx--;
			mv.visitVarInsn(ILOAD, idx);
		}

		mv.visitLabel(localsEnd);
		return to;
	}

	/**
	 * Emit bytecode to convert any (compatible) type to a p-code int that fits in a JVM int.
	 * 
	 * <p>
	 * No floating-point source types are currently acceptable. Support for floats of size other
	 * than 4 and 8 bytes is a work in progress.
	 * 
	 * @param gen the code generator
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the destination type
	 */
	static MpIntJitType generateToMpInt(JitCodeGenerator gen, JitType from, MpIntJitType to,
			MethodVisitor mv) {
		return switch (from) {
			case IntJitType iFrom -> generateIntToMpInt(iFrom, to, mv);
			case LongJitType lFrom -> generateLongToMpInt(lFrom, to, mv);
			case FloatJitType fFrom -> throw new AssertionError("Size mismatch");
			case DoubleJitType dFrom -> throw new AssertionError("Size mismatch");
			case MpIntJitType mpFrom -> generateMpIntToMpInt(gen, mpFrom, to, mv);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to convert the value on top of the JVM stack from one p-code type to another.
	 * 
	 * <p>
	 * If the source and destination are already of the same type, or if conversion between them
	 * does not require any bytecode, then no bytecode is emitted.
	 * 
	 * @param gen the code generator
	 * @param from the source type
	 * @param to the destination type
	 * @param mv the method visitor
	 * @return the resulting (destination) type
	 */
	static JitType generate(JitCodeGenerator gen, JitType from, JitType to, MethodVisitor mv) {
		return switch (to) {
			case IntJitType iTo -> generateToInt(from, iTo, mv);
			case LongJitType lTo -> generateToLong(from, lTo, mv);
			case FloatJitType fTo -> generateToFloat(from, fTo, mv);
			case DoubleJitType dTo -> generateToDouble(from, dTo, mv);
			case MpIntJitType mpTo -> generateToMpInt(gen, from, mpTo, mv);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Collapse an mp-int or long to a single int.
	 * 
	 * <p>
	 * If and only if the input is all zeros will the output also be all zeros. Otherwise, the
	 * output can be any non-zero value.
	 * 
	 * <p>
	 * There is no explicit "{@code boolean}" p-code type. Instead, like C, many of the operators
	 * take an {@link JitTypeBehavior#INTEGER int} type and require "false" to be represented by the
	 * value 0. Any non-zero value is interpreted as "true." That said, conventionally, all p-code
	 * booleans ought to be an {@link IntJitType#I1 int1} where "true" is represented by 1 and
	 * "false" is represented by 0. The p-code operators that output "boolean" values are all
	 * implemented to follow this convention, except that size is determined by the Slaspec author.
	 * 
	 * <p>
	 * This conversion deals with input operands used as booleans that do not conform to these
	 * conventions. If, e.g., a {@link PcodeOp#CBRANCH cbranch} is given a condition operand of type
	 * {@link LongJitType#I8 int8}, we have to ensure that all bits, not just the lower 32, are
	 * considered. This is trivially accomplished by pushing {@code 0L} and emitting an
	 * {@link #LCMP}, which consumes the JVM long and replaces it with a JVM int representing the
	 * same boolean value. For multi-precision ints, we reduce all the legs using {@link #IOR}. If a
	 * float is used as a boolean, it must be converted to an int first.
	 * 
	 * @param from the type of the value currently on the stack
	 * @param mv the method visitor
	 * @see #generateLdcFalse(JitType, MethodVisitor)
	 * @see #generateLdcTrue(JitType, MethodVisitor)
	 */
	static void generateIntToBool(JitType from, MethodVisitor mv) {
		switch (from) {
			case IntJitType iFrom -> {
			}
			case LongJitType lFrom -> {
				mv.visitLdcInsn(0L);
				mv.visitInsn(LCMP);
			}
			case MpIntJitType(int size) -> {
				for (int i = 0; i < size - Integer.BYTES; i += Integer.BYTES) {
					mv.visitInsn(IOR);
				}
			}
			default -> throw new AssertionError();
		}
	}

	/**
	 * Remove a value of the given type from the JVM stack.
	 * 
	 * <p>
	 * Depending on the type, we must emit either {@link #POP} or {@link #POP2}. This is used to
	 * ignore an input or drop an output. For example, the boolean operators may short circuit
	 * examination of the second operand, in which case it must be popped. Also, if a userop returns
	 * a value, but the p-code does not provide an output operand, the return value must be popped.
	 * 
	 * @param type the type
	 * @param mv the method visitor
	 */
	static void generatePop(JitType type, MethodVisitor mv) {
		switch (type) {
			case IntJitType iType -> mv.visitInsn(POP);
			case LongJitType lType -> mv.visitInsn(POP2);
			case FloatJitType fType -> mv.visitInsn(POP);
			case DoubleJitType dType -> mv.visitInsn(POP2);
			case MpIntJitType(int size) -> {
				for (int i = 0; i < size; i += Integer.BYTES) {
					mv.visitInsn(POP);
				}
			}
			case MpFloatJitType(int size) -> Unfinished.TODO("MpFloat");
			default -> throw new AssertionError();
		}
	}

	/**
	 * Generate a "boolean" true value of the given type
	 * 
	 * <p>
	 * This performs the inverse of {@link #generateIntToBool(JitType, MethodVisitor)}, but for the
	 * constant "true." Instead of loading a constant 1 into an {@link IntJitType#I1 int1} and then
	 * converting to the desired type, this can just load the constant 1 directly as the desired
	 * type.
	 * 
	 * <p>
	 * This is often used with conditional jumps to produce a boolean output.
	 * 
	 * @param type an integer type
	 * @param mv the method visitor
	 * @see #generateLdcFalse(JitType, MethodVisitor)
	 * @see #generateIntToBool(JitType, MethodVisitor)
	 */
	static void generateLdcTrue(JitType type, MethodVisitor mv) {
		switch (type) {
			case IntJitType iType -> mv.visitLdcInsn(1);
			case LongJitType lType -> mv.visitLdcInsn(1L);
			case MpIntJitType(int size) -> {
				for (int i = 0; i < size - Integer.BYTES; i += Integer.BYTES) {
					mv.visitLdcInsn(0);
				}
				mv.visitLdcInsn(1);
			}
			default -> throw new AssertionError();
		}
	}

	/**
	 * Generate a "boolean" false value of the given type
	 * 
	 * <p>
	 * This performs the inverse of {@link #generateIntToBool(JitType, MethodVisitor)}, but for the
	 * constant "false." Instead of loading a constant 0 into an {@link IntJitType#I1 int1} and then
	 * converting to the desired type, this can just load the constant 0 directly as the desired
	 * type.
	 * 
	 * <p>
	 * This is often used with conditional jumps to produce a boolean output.
	 * 
	 * @param type an integer type
	 * @param mv the method visitor
	 * @see #generateLdcFalse(JitType, MethodVisitor)
	 * @see #generateIntToBool(JitType, MethodVisitor)
	 */
	static void generateLdcFalse(JitType type, MethodVisitor mv) {
		switch (type) {
			case IntJitType iType -> mv.visitLdcInsn(0);
			case LongJitType lType -> mv.visitLdcInsn(0L);
			case MpIntJitType(int size) -> {
				for (int i = 0; i < size; i += Integer.BYTES) {
					mv.visitLdcInsn(0);
				}
			}
			default -> throw new AssertionError();
		}
	}

	/**
	 * Emit code to extend a signed value of the given type to fill its host JVM type.
	 * 
	 * <p>
	 * This is implemented in the same manner as {@link IntSExtOpGen int_sext}.
	 * 
	 * @param type the p-code type
	 * @param mv the method visitor
	 * @return the p-code type that exactly fits the host JVM type, i.e., the resulting p-code type.
	 */
	static JitType generateSExt(JitType type, MethodVisitor mv) {
		switch (type) {
			case IntJitType(int size) -> {
				int shamt = Integer.SIZE - size * Byte.SIZE;
				if (shamt != 0) {
					mv.visitLdcInsn(shamt);
					mv.visitInsn(ISHL);
					mv.visitLdcInsn(shamt);
					mv.visitInsn(ISHR);
				}
			}
			case LongJitType(int size) -> {
				int shamt = Long.SIZE - size * Byte.SIZE;
				if (shamt != 0) {
					mv.visitLdcInsn(shamt);
					mv.visitInsn(LSHL);
					mv.visitLdcInsn(shamt);
					mv.visitInsn(LSHR);
				}
			}
			default -> throw new AssertionError();
		}
		return type.ext();
	}

	/**
	 * Convert a signed {@link IntJitType#I4 int4} to {@link LongJitType#I8 int8}.
	 * 
	 * <p>
	 * Note that if conversion from a smaller int type is needed, the generator must first call
	 * {@link #generateSExt(JitType, MethodVisitor)}.
	 * 
	 * @param mv the method visitor
	 * @return the resulting type ({@link LongJitType#I8 int8})
	 */
	static LongJitType generateSExtIntToLong(MethodVisitor mv) {
		mv.visitInsn(I2L);
		return LongJitType.I8;
	}

	/**
	 * Select the larger of two types and emit code to convert an unsigned value of the first type
	 * to the host JVM type of the selected type.
	 * 
	 * <p>
	 * JVM bytecodes for binary operators often require that both operands have the same size.
	 * Consider that the JVM provides a {@link #IADD} and a {@link #LADD}, but no "{@code ILADD}".
	 * Both operands must be JVM ints, or both must be JVM longs. This method provides an idiom for
	 * converting both operands to the same type. Ideally, we choose the smallest type possible (as
	 * opposed to just converting everything to long always), but we must choose a type large enough
	 * to accommodate the larger of the two p-code operands.
	 * 
	 * <p>
	 * For a binary operator requiring type uniformity, we must apply this method immediately after
	 * loading each operand onto the stack. That operand's type is passed as {@code myType} and the
	 * type of the other operand as {@code otherType}. Consider the left operand. We must override
	 * {@link BinOpGen#afterLeft(JitCodeGenerator, JitBinOp, JitType, JitType, MethodVisitor)
	 * afterLeft} if we're using {@link BinOpGen}. If the left type is the larger, then we select it
	 * and we need only extend the left operand to fill its host JVM type. (We'll deal with the
	 * right operand in a moment.) If the right type is larger, then we select it and we extend the
	 * left to fill <em>the right's</em> host JVM type. We then return the resulting left type so
	 * that we'll know what it was when emitting the actual operator bytecodes. Things work
	 * similarly for the right operand, which we handle within
	 * {@link BinOpGen#generateBinOpRunCode(JitCodeGenerator, JitBinOp, JitBlock, JitType, JitType, MethodVisitor)
	 * generateBinOpRunCode} if we're using it. The two resulting types should now be equal, and we
	 * can examine them and emit the correct bytecodes.
	 * 
	 * @param myType the type of an operand, probably in a binary operator
	 * @param otherType the type of the other operand of a binary operator
	 * @param mv the method visitor
	 * @return the new type of the operand
	 */
	static JitType forceUniformZExt(JitType myType, JitType otherType, MethodVisitor mv) {
		return switch (myType.ext()) {
			case IntJitType mt -> switch (otherType.ext()) {
				case IntJitType ot -> mt;
				case LongJitType ot -> generateIntToLong(mt, ot, mv);
				case MpIntJitType ot -> generateIntToMpInt(mt, MpIntJitType.forSize(mt.size()),
					mv);
				default -> throw new AssertionError();
			};
			case LongJitType mt -> switch (otherType) {
				case IntJitType ot -> mt; // Other operand needs up-conversion
				case LongJitType ot -> mt;
				case MpIntJitType ot -> generateLongToMpInt(mt, MpIntJitType.forSize(mt.size()),
					mv);
				default -> throw new AssertionError();
			};
			case MpIntJitType mt -> mt; // Other may need up-conversion
			default -> throw new AssertionError();
		};
	}

	/**
	 * Do the same as {@link #forceUniformZExt(JitType, JitType, MethodVisitor)}, but with signed
	 * values.
	 * 
	 * @param myType the type of an operand, probably in a binary operator
	 * @param otherType the type of the other operand of a binary operator
	 * @param mv the method visitor
	 * @return the new type of the operand
	 */
	static JitType forceUniformSExt(JitType myType, JitType otherType, MethodVisitor mv) {
		JitType myExtType = generateSExt(myType, mv);
		return switch (myExtType) {
			case IntJitType mt -> switch (otherType.ext()) { // Don't extend other, yet
				case IntJitType ot -> mt;
				case LongJitType ot -> generateSExtIntToLong(mv);
				case MpIntJitType ot -> generateIntToMpInt(mt, MpIntJitType.forSize(mt.size()),
					mv);
				default -> throw new AssertionError();
			};
			case LongJitType mt -> switch (otherType.ext()) {
				case IntJitType ot -> mt; // Other operand needs up-conversion
				case LongJitType ot -> mt;
				case MpIntJitType ot -> generateLongToMpInt(mt, MpIntJitType.forSize(mt.size()),
					mv);
				default -> throw new AssertionError();
			};
			case MpIntJitType mt -> mt; // Other may need up-conversion
			default -> throw new AssertionError();
		};
	}
}
