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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitLoadOp;
import ghidra.pcode.emu.jit.op.JitStoreOp;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator to emit code that accesses variables of various size in a
 * {@link JitBytesPcodeExecutorState state}, for a specific type, byte order, and access.
 * 
 * <p>
 * This is used by variable birthing and retirement as well as direct memory accesses. Dynamic
 * memory accesses, i.e., {@link JitLoadOp load} and {@link JitStoreOp store} op do not use this,
 * though they may borrow some portions.
 */
public interface TypedAccessGen {

	/**
	 * Lookup the generator for reading variables for the given type
	 * 
	 * @param endian the byte order
	 * @param type the variable's type
	 * @return the access generator
	 */
	public static TypedAccessGen lookupReader(Endian endian, JitType type) {
		return switch (endian) {
			case BIG -> switch (type) {
				case IntJitType t -> IntReadGen.BE;
				case LongJitType t -> LongReadGen.BE;
				case FloatJitType t -> FloatReadGen.BE;
				case DoubleJitType t -> DoubleReadGen.BE;
				case MpIntJitType t -> MpIntReadGen.BE;
				default -> throw new AssertionError();
			};
			case LITTLE -> switch (type) {
				case IntJitType t -> IntReadGen.LE;
				case LongJitType t -> LongReadGen.LE;
				case FloatJitType t -> FloatReadGen.LE;
				case DoubleJitType t -> DoubleReadGen.LE;
				case MpIntJitType t -> MpIntReadGen.LE;
				default -> throw new AssertionError();
			};
		};
	}

	/**
	 * Lookup the generator for writing variables for the given type
	 * 
	 * @param endian the byte order
	 * @param type the variable's type
	 * @return the access generator
	 */
	public static TypedAccessGen lookupWriter(Endian endian, JitType type) {
		return switch (endian) {
			case BIG -> switch (type) {
				case IntJitType t -> IntWriteGen.BE;
				case LongJitType t -> LongWriteGen.BE;
				case FloatJitType t -> FloatWriteGen.BE;
				case DoubleJitType t -> DoubleWriteGen.BE;
				case MpIntJitType t -> MpIntWriteGen.BE;
				default -> throw new AssertionError();
			};
			case LITTLE -> switch (type) {
				case IntJitType t -> IntWriteGen.LE;
				case LongJitType t -> LongWriteGen.LE;
				case FloatJitType t -> FloatWriteGen.LE;
				case DoubleJitType t -> DoubleWriteGen.LE;
				case MpIntJitType t -> MpIntWriteGen.LE;
				default -> throw new AssertionError();
			};
		};
	}

	/**
	 * Emit code to access a varnode.
	 * 
	 * <p>
	 * If reading, the result is placed on the JVM stack. If writing, the value is popped from the
	 * JVM stack.
	 * 
	 * <p>
	 * If the varnode fits completely in the block (the common case), then this accesses the bytes
	 * from the one block, using the method chosen by size. If the varnode extends into the next
	 * block, then this will split the varnode into two portions according to machine byte order.
	 * Each portion is accessed using the method for the size of that portion. If reading, the
	 * results are reassembled into a single value and pushed onto the JVM stack.
	 * 
	 * @param gen the code generator
	 * @param vn the varnode
	 * @param rv the method visitor
	 */
	void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv);
}
