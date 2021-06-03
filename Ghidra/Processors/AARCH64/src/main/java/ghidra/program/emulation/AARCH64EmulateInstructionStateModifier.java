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
package ghidra.program.emulation;

import java.math.BigInteger;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.pcode.Varnode;
//import ghidra.pcode.emulate.callother.SignalingNaNOpBehavior;

public class AARCH64EmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	public AARCH64EmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		// The following SIMD and MP versions of SLEIGH
		// primitives are implemented in java for AARCH64

		// BLANK:
		// COPY:
//			registerPcodeOpBehavior("SIMD_COPY", new SIMD_COPY());
		// LOAD:
		// STORE:
		// BRANCH:
		// CBRANCH:
		// BRANCHIND:
		// CALL:
		// CALLIND:
		// CALLOTHER:
		// RETURN:
		// INT_EQUAL:
			// registerPcodeOpBehavior("MP_INT_EQUAL", new MP_INT_EQUAL());
		// INT_NOTEQUAL:
		// INT_SLESS:
		// INT_SLESSEQUAL:
		// INT_LESS:
		// INT_LESSEQUAL:
		// INT_ZEXT:
//			registerPcodeOpBehavior("SIMD_INT_ZEXT", new SIMD_INT_ZEXT());
		// INT_SEXT:
//			registerPcodeOpBehavior("SIMD_INT_SEXT", new SIMD_INT_SEXT());
		// INT_ABS (no equivalent SLEIGH primitive):
			registerPcodeOpBehavior("MP_INT_ABS", new MP_INT_ABS());
//			registerPcodeOpBehavior("SIMD_INT_ABS", new SIMD_INT_ABS());
		// INT_ADD:
			// registerPcodeOpBehavior("SIMD_INT_ADD", new SIMD_INT_ADD());
			// registerPcodeOpBehavior("SIPD_INT_ADD", new SIPD_INT_ADD());
		// INT_SUB:
//			registerPcodeOpBehavior("SIMD_INT_SUB", new SIMD_INT_SUB());
		// INT_CARRY:
		// INT_SCARRY:
		// INT_SBORROW:
		// INT_2COMP:
//			registerPcodeOpBehavior("SIMD_INT_2COMP", new SIMD_INT_2COMP());
		// INT_NEGATE:
			// registerPcodeOpBehavior("MP_INT_NEGATE", new MP_INT_NEGATE());
//			registerPcodeOpBehavior("SIMD_INT_NEGATE", new SIMD_INT_NEGATE());
		// INT_XOR:
//			registerPcodeOpBehavior("SIMD_INT_XOR", new SIMD_INT_XOR());
		// INT_AND:
			// registerPcodeOpBehavior("MP_INT_AND", new MP_INT_AND());
//			registerPcodeOpBehavior("SIMD_INT_AND", new SIMD_INT_AND());
		// INT_OR:
//			registerPcodeOpBehavior("SIMD_INT_OR", new SIMD_INT_OR());
		// INT_LEFT:
//			registerPcodeOpBehavior("SIMD_INT_LEFT", new SIMD_INT_LEFT());
		// INT_RIGHT:
//			registerPcodeOpBehavior("SIMD_INT_RIGHT", new SIMD_INT_RIGHT());
			registerPcodeOpBehavior("MP_INT_RIGHT", new MP_INT_RIGHT());
		// INT_SRIGHT:
//			registerPcodeOpBehavior("SIMD_INT_SRIGHT", new SIMD_INT_SRIGHT());
		// INT_MULT:
//			registerPcodeOpBehavior("SIMD_INT_MULT", new SIMD_INT_MULT());
			registerPcodeOpBehavior("MP_INT_MULT", new MP_INT_MULT());
			registerPcodeOpBehavior("MP_INT_UMULT", new MP_INT_UMULT());
		// INT_DIV:
		// INT_SDIV:
		// INT_REM:
		// INT_SREM:
		// BOOL_NEGATE:
		// BOOL_XOR:
		// BOOL_AND:
		// BOOL_OR:
		// FLOAT_EQUAL:
		// FLOAT_NOTEQUAL:
		// FLOAT_LESS:
		// FLOAT_LESSEQUAL:
		// UNUSED1:
		// FLOAT_NAN:
		// FLOAT_ADD:
//			registerPcodeOpBehavior("SIMD_FLOAT_ADD", new SIMD_FLOAT_ADD());
			// registerPcodeOpBehavior("SIPD_FLOAT_ADD", new SIPD_FLOAT_ADD());
		// FLOAT_DIV:
//			registerPcodeOpBehavior("SIMD_FLOAT_DIV", new SIMD_FLOAT_DIV());
		// FLOAT_MULT:
//			registerPcodeOpBehavior("SIMD_FLOAT_MULT", new SIMD_FLOAT_MULT());
		// FLOAT_SUB:
//			registerPcodeOpBehavior("SIMD_FLOAT_SUB", new SIMD_FLOAT_SUB());
		// FLOAT_NEG:
//			registerPcodeOpBehavior("SIMD_FLOAT_NEG", new SIMD_FLOAT_NEG());
		// FLOAT_ABS:
//			registerPcodeOpBehavior("SIMD_FLOAT_ABS", new SIMD_FLOAT_ABS());
		// FLOAT_SQRT:
		// INT2FLOAT:
		// FLOAT2FLOAT:
//			registerPcodeOpBehavior("SIMD_FLOAT2FLOAT", new SIMD_FLOAT2FLOAT());
		// TRUNC:
//			registerPcodeOpBehavior("SIMD_TRUNC", new SIMD_TRUNC());
		// CEIL:
		// FLOOR:
		// ROUND:
			// registerPcodeOpBehavior("SIMD_FLOAT_ROUND", new SIMD_FLOAT_ROUND());
		// BUILD:
		// DELAY_SLOT:
		// PIECE:
			registerPcodeOpBehavior("SIMD_PIECE", new SIMD_PIECE());
		// SUBPIECE:
		// CAST:
		// LABEL:
		// CROSSBUILD:
		// SEGMENTOP:
		// CPOOLREF:
		// NEW:

		// CONCAT: no sleigh equivalent
			// registerPcodeOpBehavior("a64_CONCAT", new a64_CONCAT());

		// The following AARCH64 instructions are implemented
		// in java as a pcodeop

		// TBL/TBX:
			registerPcodeOpBehavior("a64_TBL", new a64_TBL());
	}

	// Helper functions

	private long getmask(long esize) {
		long mask = -1;
		if (esize < 8) {
			mask = mask >>> ((8 - esize) * 8);
		}
		return mask;
	}

	// Simple versions of half precision
	// This is for demonstration purposes only,
	// NaN, rounding, normalization is ignored.

	private float shortBitsToFloat(long x) {
		long sign = (x >>> 15) & 0x1;
		long exp = (x >>> 10) & 0x1f - 15 + 127;
		long mant = (x & 0x3ff) << 13;
		return Float.intBitsToFloat((int) (sign << 31 | exp << 23 | mant));
	}

	private long floatToShortBits(float x) {
		long fbits = Float.floatToIntBits(x);
		long sign = (fbits >>> 31) & 0x1;
		long exp = (fbits >>> 23) & 0xff - 127 + 15;
		long mant = (fbits & 0x7fffff) >>> 13;
		return (long) (sign << 15 | exp << 10 | mant);
	}

	// Convert a byte array to a long
	// assume that lsb is the least significant byte
	// and there are at most esize bytes.
	// the byte array is in big endian order

	protected long bytes_to_long(byte[] bytes, int lsb, int esize) {
		if (lsb <= 0) {
			return 0;
		}

		int i = lsb - esize;
		if (i < 0) {
			i = 0;
		}

		long result = bytes[i];
		i += 1;
		while (i < lsb) {
			result = result << 8;
			result = result | (bytes[i] & 0xff);
			i += 1;
		}
		return result;
	}

	// Insert size bytes from the long value into the byte
	// array.

	protected void insert_long(long value, byte[] outBytes, int lsb, int esize) {
		if (lsb - esize < 0) {
			throw new LowlevelError("insert_long: byte array too small");
		}
		for (int j = 0; j < esize; j++) {
			outBytes[lsb - j - 1] = (byte) (value & 0xff);
			value = value >> 8;
		}
	}

	// Allocate a byte array of the correct size to hold
	// the output initialize to all zeros, and copy any
	// value in the init varnode (with sign extension to a
	// size boundary)

	protected byte[] varnode_to_bytes(Varnode outputVarnode, byte[] initBytes, int esize) {

		byte[] outBytes = new byte[outputVarnode.getSize()];
		if (initBytes == null) {
			return outBytes;
		}

		byte ext = 0;

		for (int i = outBytes.length, j = initBytes.length; i > 0; i--, j--) {
			if (j > 0) {
				outBytes[i - 1] = initBytes[j - 1];
				ext = (byte) ((initBytes[j - 1] >= 0) ? 0 : 0xff);
			} else {
				outBytes[i - 1] = ext;
				if (((i - 1) % esize) == 0) {
					break;
				}
			}
		}

		return outBytes;
	}

	// Abstract classes for unary and binary operations

	// Generic simd unary operation
	//
	// Must be extended with op method
	//
	// Vd = SIMD_OP1(Vm, size);
	//
	// Vd: output variable
	// Vm: value to operate on
	// size: size of lanes to add

	private abstract class SIMD_OP1 implements OpBehaviorOther {

		protected abstract long op1(long x, int esize);

		void check_args(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 1 input

			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError(this.getClass().getName() + ": requires 2 inputs (op, size), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError(this.getClass().getName() + ": missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			// Get the simd variable to output, the value to copy, and the offset

			Varnode simdVarnode = inputs[1];
			int esize = (int) memoryState.getValue(inputs[2]);

			if (outputVarnode.getSize() < simdVarnode.getSize()) {
				throw new LowlevelError(this.getClass().getName() + ": input size (" + simdVarnode.getSize()
						+ ") exceeds output size (" + outputVarnode.getSize() + ")");
			}

			if (esize != 1 && esize != 2 && esize != 4 && esize != 8) {
				throw new LowlevelError(this.getClass().getName() + ": operand must be 1, 2, 4, or 8 bytes: got " + esize);
			}

			if ((outputVarnode.getSize() % esize) != 0) {
				throw new LowlevelError(this.getClass().getName() + ": output size (" + outputVarnode.getSize()
					+ ") must be a multiple of operand size (" + esize + ")");
			}
		}

	}

	// Signed SIMD_OP1

	private abstract class SIMD_SOP1 extends SIMD_OP1 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			int esize = (int) memoryState.getValue(inputs[2]);

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, true).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, esize);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length;
				outLSB > 0;
				outLSB -= esize, simdLSB -= esize) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, esize);

				// Perform the operation

				simdLane = op1(simdLane, esize);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, esize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Unsigned SIMD_OP1

	private abstract class SIMD_UOP1 extends SIMD_OP1 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			int esize = (int) memoryState.getValue(inputs[2]);

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, false).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, esize);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length;
				outLSB > 0;
				outLSB -= esize, simdLSB -= esize) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, esize);

				// Perform the operation

				simdLane = op1(simdLane, esize);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, esize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Generic simd unary operation with extension
	//
	// Vd = SIMD_OP1E(Vm, size);
	//
	// Vd: output variable
	// Vm: value to operate on
	// size: size of lanes to add
	//
	// Output lanes are a multiple of the size of the input lanes,
	// but they can't be larger than 8.
	//
	// For extension,
	//
	// output:16 = SIMD_OP1E(input:8, 2:1)
	//
	// extends the 2-byte lanes in the input to 4-byte lanes in
	// the output.
	//
	// For contraction,
	//
	// output:8 = SIMD_OP1E(input:16, 2:1)
	//
	// contracts the 2-byte lands in the input to 1-byte lanes in
	// the output.
	//
	// The class be extended with an op1e method

	private abstract class SIMD_OP1E implements OpBehaviorOther {

		protected abstract long op1e(long x, int s_size, int d_size);

		void check_args(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 2 input

			int numArgs = inputs.length - 1;
			if (numArgs != 2) throw new LowlevelError(this.getClass().getName() + ": requires 2 inputs (op, size), got " + numArgs);

			if (outputVarnode == null) throw new LowlevelError(this.getClass().getName() + ": missing required output");

			MemoryState memoryState = emu.getMemoryState();

			// Get the simd variable to output, the value to copy, and the offset

			Varnode simdVarnode = inputs[1];
			int s_size = (int) memoryState.getValue(inputs[2]);

			if (outputVarnode.getSize() != 2 * simdVarnode.getSize())
				throw new LowlevelError(this.getClass().getName() + ": input size (" + simdVarnode.getSize()
						+ ") must be exactly half of the output size (" + outputVarnode.getSize() + ")");

			if (s_size != 1 && s_size != 2 && s_size != 4 && s_size != 8)
				throw new LowlevelError(this.getClass().getName() + ": input elements must be 1, 2, 4, or 8 bytes: got " + s_size);

			int d_size = (s_size * outputVarnode.getSize()) / simdVarnode.getSize();
			if (d_size != 1 && d_size != 2 && d_size != 4 && d_size != 8)
				throw new LowlevelError(this.getClass().getName() + ": the output elements must be 1, 2, 4, or 8 bytes: got " + d_size);

			if ((simdVarnode.getSize() % s_size) != 0)
				throw new LowlevelError(this.getClass().getName() + ": input size (" + simdVarnode.getSize()
					+ ") must be a multiple of input element size (" + s_size + ")");

			if ((outputVarnode.getSize() % d_size) != 0)
				throw new LowlevelError(this.getClass().getName() + ": output size (" + simdVarnode.getSize()
					+ ") must be a multiple of output element size (" + d_size + ")");
		}
	}

	// Signed OP1E

	private abstract class SIMD_SOP1E extends SIMD_OP1E {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			int s_size = (int) memoryState.getValue(inputs[2]);
			int d_size = (s_size * outputVarnode.getSize()) / simdVarnode.getSize();

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, true).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, d_size);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length;
				outLSB > 0;
				outLSB -= d_size, simdLSB -= s_size) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, s_size);

				// Perform the operation

				simdLane = op1e(simdLane, s_size, d_size);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, d_size);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Unsigned OP1E

	private abstract class SIMD_UOP1E extends SIMD_OP1E {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			int s_size = (int) memoryState.getValue(inputs[2]);
			int d_size = (s_size * outputVarnode.getSize()) / simdVarnode.getSize();

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, false).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, d_size);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length;
				outLSB > 0;
				outLSB -= d_size, simdLSB -= s_size) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, s_size);

				// Perform the operation

				simdLane = op1e(simdLane, s_size, d_size);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, d_size);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}


	// Generic simd binary operation
	//
	// Must be extended with op method
	//
	// Vd = SIMD_OP2(Vm, Vn, esize);
	//
	// Vd: output variable
	// Vm, Vn: op1 and op2
	// esize: optional size of lanes to add, of omitted, Vn is a
	//       constant operand to each lane of Vm (of that size)

	private abstract class SIMD_OP2 implements OpBehaviorOther {

		protected abstract long op2(long x, long y, int esize);

		void check_args(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 2 or 3 inputs

			int numArgs = inputs.length - 1;
			if (numArgs != 2 && numArgs != 3) {
				throw new LowlevelError(this.getClass().getName() + ": requires 3 inputs (simd, op, esize), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError(this.getClass().getName() + ": missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			// Get the simd variable to output, the value to copy, and the offset

			Varnode simdVarnode = inputs[1];
			Varnode opVarnode = inputs[2];

			int esize = opVarnode.getSize();
			boolean opConstant = (numArgs == 2);
			if (! opConstant) {
				esize = (int) memoryState.getValue(inputs[3]);
			}

			if (outputVarnode.getSize() < simdVarnode.getSize()) {
				throw new LowlevelError(this.getClass().getName() + ": input size (" + simdVarnode.getSize()
						+ ") exceeds output size (" + outputVarnode.getSize() + ")");
			}

			if (esize != 1 && esize != 2 && esize != 4 && esize != 8) {
				throw new LowlevelError(this.getClass().getName() + ": operand must be 1, 2, 4, or 8 bytes: got " + esize);
			}

			if ((outputVarnode.getSize() % esize) != 0) {
				throw new LowlevelError(this.getClass().getName() + ": output size (" + outputVarnode.getSize()
					+ ") must be a multiple of operand size (" + esize + ")");
			}

			if (! opConstant && simdVarnode.getSize() != opVarnode.getSize()) {
				throw new LowlevelError(this.getClass().getName() + ": simd size (" + outputVarnode.getSize()
					+ ") and operand size (" + esize + ") must be the same for simd operation");
			}

		}
	}

	// Signed SIMD_OP2

	private abstract class SIMD_SOP2 extends SIMD_OP2 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			Varnode opVarnode = inputs[2];
			boolean opConstant = (inputs.length == 3);
			int esize = opVarnode.getSize();
			if (! opConstant) {
				esize = (int) memoryState.getValue(inputs[3]);
			}
			int opstep = (opConstant ? 0 : esize);

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, true).toByteArray();
			byte[] opBytes = memoryState.getBigInteger(opVarnode, true).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, esize);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length, opLSB = opBytes.length;
				outLSB > 0;
				outLSB -= esize, simdLSB -= esize, opLSB -= opstep) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, esize);
				long opLane = bytes_to_long(opBytes, opLSB, esize);

				// Perform the operation

				simdLane = op2(simdLane, opLane, esize);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, esize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Unsigned SIMD_OP2

	private abstract class SIMD_UOP2 extends SIMD_OP2 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			Varnode simdVarnode = inputs[1];
			Varnode opVarnode = inputs[2];
			boolean opConstant = (inputs.length == 3);
			int esize = opVarnode.getSize();
			if (! opConstant) {
				esize = (int) memoryState.getValue(inputs[3]);
			}
			int opstep = (opConstant ? 0 : esize);

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, false).toByteArray();
			byte[] opBytes = memoryState.getBigInteger(opVarnode, false).toByteArray();
			byte[] outBytes = varnode_to_bytes(outputVarnode, null, esize);

			for (int outLSB = outBytes.length, simdLSB = simdBytes.length, opLSB = opBytes.length;
				outLSB > 0;
				outLSB -= esize, simdLSB -= esize, opLSB -= opstep) {

				long simdLane = bytes_to_long(simdBytes, simdLSB, esize);
				long opLane = bytes_to_long(opBytes, opLSB, esize);

				// Perform the operation

				simdLane = op2(simdLane, opLane, esize);

				// Put the result back into the output

				insert_long(simdLane, outBytes, outLSB, esize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Generic sipd (paired data) binary operation
	//
	// Must be extended with op method
	//
	// Vd = SIPD_OP2(Vn, esize);
	//
	// Vd: output variable
	// Vn1, Vn2: op (optional Vn2 to concatenate)
	// iesize: size of input lanes to add

	private abstract class SIPD_OP2 implements OpBehaviorOther {

		protected abstract long op2(long x, long y, int iesize, int oesize);

		void check_args(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 2 inputs

			int numArgs = inputs.length - 1;
			if (numArgs != 2 && numArgs != 3) {
				throw new LowlevelError(this.getClass().getName() + ": requires 2 or 3 inputs (pairData*, esize), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError(this.getClass().getName() + ": missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			// Get the paired variables and the offset

			Varnode p1Varnode = inputs[1];
			int isize = p1Varnode.getSize();
			Varnode p2Varnode = null;
			if (numArgs == 3) {
				p2Varnode = inputs[2];
				isize += p2Varnode.getSize();
			}

			int iesize = (int) memoryState.getValue(inputs[numArgs]);
			int osize = outputVarnode.getSize();
			int oesize = (iesize * osize) / isize;

			if (iesize != 1 && iesize != 2 && iesize != 4 && iesize != 8) {
				throw new LowlevelError(this.getClass().getName() + ": operand lanes must be 1, 2, 4, or 8 bytes: got " + iesize);
			}

			if (oesize != 1 && oesize != 2 && oesize != 4 && oesize != 8) {
				throw new LowlevelError(this.getClass().getName() + ": output lanes must be 1, 2, 4, or 8 bytes: got " + oesize);
			}
		}

	}

	// Signed SIPD_OP2

	private abstract class SIPD_SOP2 extends SIPD_OP2 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			int numArgs = inputs.length - 1;
			Varnode p1Varnode = inputs[1];
			int isize = p1Varnode.getSize();
			Varnode p2Varnode = null;
			if (numArgs == 3) {
				p2Varnode = inputs[2];
				isize += p2Varnode.getSize();
			}

			int iesize = (int) memoryState.getValue(inputs[numArgs]);
			int osize = outputVarnode.getSize();
			int oesize = (iesize * osize) / isize;

			// create pairBytes, concatenating if
			// necessary. If there were 2 arguments, the
			// second one is least significant

			byte[] pairBytes = new byte[isize];

			if (p2Varnode != null) {
				byte[] p2Bytes = memoryState.getBigInteger(p2Varnode, true).toByteArray();
				for (int i = p2Bytes.length, pi = pairBytes.length;
					i > 0 && pi > 0;
					i -= 1, pi -= 1) {

					pairBytes[pi - 1] = p2Bytes[i - 1];
				}
			}
			byte[] p1Bytes = memoryState.getBigInteger(p1Varnode, true).toByteArray();
			for (int i = p1Bytes.length, pi = p1Varnode.getSize();
				i > 0 && pi > 0;
				i -= 1, pi -= 1) {

				pairBytes[pi - 1] = p1Bytes[i - 1];
			}

			byte[] outBytes = varnode_to_bytes(outputVarnode, null, osize);

			for (int outLSB = outBytes.length, opLSB = pairBytes.length;
				outLSB > 0 && opLSB > 0;
				outLSB -= oesize, opLSB -= iesize) {

				long arg1Lane = bytes_to_long(pairBytes, opLSB, iesize);
				long arg2Lane = bytes_to_long(pairBytes, opLSB - iesize, iesize);

				// Perform the operation

				arg1Lane = op2(arg1Lane, arg2Lane, iesize, oesize);

				// Put the result back into the output

				insert_long(arg1Lane, outBytes, outLSB, oesize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Unigned SIPD_OP2

	private abstract class SIPD_UOP2 extends SIPD_OP2 {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			check_args(emu, outputVarnode, inputs);

			MemoryState memoryState = emu.getMemoryState();

			int numArgs = inputs.length - 1;
			Varnode p1Varnode = inputs[1];
			int isize = p1Varnode.getSize();
			Varnode p2Varnode = null;
			if (numArgs == 3) {
				p2Varnode = inputs[2];
				isize += p2Varnode.getSize();
			}

			int iesize = (int) memoryState.getValue(inputs[numArgs]);
			int osize = outputVarnode.getSize();
			int oesize = (iesize * osize) / isize;

			// create pairBytes, concatenating if
			// necessary. If there were 2 arguments, the
			// second one is least significant

			byte[] pairBytes = new byte[isize];

			if (p2Varnode != null) {
				byte[] p2Bytes = memoryState.getBigInteger(p2Varnode, false).toByteArray();
				for (int i = p2Bytes.length, pi = pairBytes.length;
					i > 0 && pi > 0;
					i -= 1, pi -= 1) {

					pairBytes[pi - 1] = p2Bytes[i - 1];
				}
			}
			byte[] p1Bytes = memoryState.getBigInteger(p1Varnode, false).toByteArray();
			for (int i = p1Bytes.length, pi = p1Varnode.getSize();
				i > 0 && pi > 0;
				i -= 1, pi -= 1) {

				pairBytes[pi - 1] = p1Bytes[i - 1];
			}

			byte[] outBytes = varnode_to_bytes(outputVarnode, null, osize);

			for (int outLSB = outBytes.length, opLSB = pairBytes.length;
				outLSB > 0 && opLSB > 0;
				outLSB -= oesize, opLSB -= iesize) {

				long arg1Lane = bytes_to_long(pairBytes, opLSB, iesize);
				long arg2Lane = bytes_to_long(pairBytes, opLSB - iesize, iesize);

				// Perform the operation

				arg1Lane = op2(arg1Lane, arg2Lane, iesize, oesize);

				// Put the result back into the output

				insert_long(arg1Lane, outBytes, outLSB, oesize);
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Implementations of pcodeops

	// Copy a the input value to the given output lane
	//
	// Vd = SIMD_COPY(Vinit, Vn, offset);
	//
	// Vd = destination varnode
	// Vinit = default values for non-affected lanes, usually just Vd
	// Vn = value to copy
	// offset = optional integer to specify the lane (0 = least significant)
	//          to copy the value. if not specified, then all lanes are copied

	private class SIMD_COPY implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 2 inputs

			int numArgs = inputs.length - 1;
			if (numArgs != 2 && numArgs != 3) throw new LowlevelError("SIMD_COPY: requires 2 or 3 inputs, got " + numArgs);

			if (outputVarnode == null) throw new LowlevelError("SIMD_COPY: missing required output");

			MemoryState memoryState = emu.getMemoryState();

			// Get the init variable to output, the value to copy, and the offset

			Varnode initVarnode = inputs[1];
			Varnode valueVarnode = inputs[2];
			int offset = -1;
			if (numArgs == 3) offset = (int) memoryState.getValue(inputs[3]);

			if (outputVarnode.getSize() < initVarnode.getSize())
				throw new LowlevelError("SIMD_COPY: output size (" + outputVarnode.getSize()
					+ ") is smaller than the init size (" + initVarnode.getSize() + ")");

			if (offset >= 0) {
				if (outputVarnode.getSize() < offset + valueVarnode.getSize())
					throw new LowlevelError("SIMD_COPY: output size (" + outputVarnode.getSize()
						+ ") too small to copy input size (" + valueVarnode.getSize() + ") to offset (" + offset + ")");
			} else {
				if (outputVarnode.getSize() < valueVarnode.getSize() || (outputVarnode.getSize() % valueVarnode.getSize()) != 0)
					throw new LowlevelError("SIMD_COPY: output size (" + outputVarnode.getSize()
						+ ") must be multiple of input size (" + valueVarnode.getSize() + ")");
			}

			// Allocate a byte array of the correct size to hold the output
			// initialized to all zeros

			int outSize = outputVarnode.getSize();
			byte[] outBytes = new byte[outSize];
			byte[] initBytes = memoryState.getBigInteger(initVarnode, false).toByteArray();
			for (int i = 0; i < initBytes.length && i < outSize; i++)
				outBytes[outSize - 1 - i] = initBytes[initBytes.length - 1 - i];

			// Get the bytes to copy (treat them as unsigned)
			// The byte arrays are always in big endian order, and may be truncated.
			// and if it's a negative value, then it needs to be sign extended.

			int valueSize = valueVarnode.getSize();
			byte[] copyBytes = new byte[valueSize];
			{
				byte[] valueBytes = memoryState.getBigInteger(valueVarnode, false).toByteArray();
				byte ext = 0;
				for (int i = valueSize - 1, j = valueBytes.length - 1; i >= 0; i--, j--) {
					if (j >= 0) {
						copyBytes[i] = valueBytes[j];
						ext = (byte) ((valueBytes[j] < 0) ? -1 : 0);
					} else {
						copyBytes[i] = ext;
					}
				}
			}

			for (int i = 0; i < valueSize; i++) {
				if (offset >= 0) {
					outBytes[outSize - offset * valueSize - valueSize + i] = copyBytes[i];
				} else {
					for (int offs = 0; offs * valueSize < outSize; offs += 1)
						outBytes[outSize - offs * valueSize - valueSize + i] = copyBytes[i];
				}
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Multiprecision compare
	//
	// Vd = MP_INT_EQUAL(Vn, Vm);
	//
	// Vd: destination varnode (will be 0 or 1)
	// Vn, Vm: multiplicands

	@SuppressWarnings("unused")
	private class MP_INT_EQUAL implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("MP_INT_EQUAL: requires 2 (Vm, Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_EQUAL: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			BigInteger cmp1 = memoryState.getBigInteger(inputs[1], false);
			BigInteger cmp2 = memoryState.getBigInteger(inputs[2], false);

			BigInteger result = (cmp1.compareTo(cmp2) == 0) ? BigInteger.ONE : BigInteger.ZERO;

			memoryState.setValue(outputVarnode, result);
		}
	}

	// Convert element from s_size to d_size by truncation
	// The input may be longer than s_size, e.g. if it was sign
	// extended, so truncate to the smaller of s_size and d_size

	private class SIMD_INT_ZEXT extends SIMD_UOP1E {
		protected long op1e(long x, int s_size, int d_size) { return x & getmask(s_size) & getmask(d_size); }
	}

	// Convert element from s_size to d_size with sign extend
	// the input is, or should be, sign extended, so it can simply
	// be truncated to the output size

	private class SIMD_INT_SEXT extends SIMD_SOP1E {
		protected long op1e(long x, int s_size, int d_size) { return x & getmask(d_size); }
	}

	private class MP_INT_ABS implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 1) {
				throw new LowlevelError("MP_INT_ABS: requires 1 (Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_ABS: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			BigInteger op = memoryState.getBigInteger(inputs[1], true);

			BigInteger result = op.abs();
			// System.out.print(String.format("MP_INT_ABS %s to %s (%x)\n", op.toString(), result.toString(), result.longValue()));

			memoryState.setValue(outputVarnode, result);
		}
	}

	private class SIMD_INT_ABS extends SIMD_SOP1 {
		protected long op1(long x, int esize) { return (x < 0) ? -x : x; }
	}

	@SuppressWarnings("unused")
	private class SIMD_INT_ADD extends SIMD_SOP2 {
		protected long op2(long x, long y, int esize) { return x + y; }
	}

	@SuppressWarnings("unused")
	private class SIPD_INT_ADD extends SIPD_SOP2 {
		@Override
		protected long op2(long x, long y, int iesize, int oesize) { return x + y; }
	}

	private class SIMD_INT_SUB extends SIMD_SOP2 {
		protected long op2(long x, long y, int esize) { return x - y; }
	}

	private class SIMD_INT_2COMP extends SIMD_SOP1 {
		protected long op1(long x, int esize) { return -x; }
	}

	// Multiprecision NOT
	//
	// Vd = MP_INT_NEGATE(Vn);
	//
	// Vd: destination varnode
	// Vn: value to bitwise negate

	@SuppressWarnings("unused")
	private class MP_INT_NEGATE implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 1) {
				throw new LowlevelError("MP_INT_NEGATE: requires 1 (Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_NEGATE: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			byte[] value = memoryState.getBigInteger(inputs[1], true).toByteArray();

			// Need to perform bitwise negation manually
			// to get the right size

			int outSize = outputVarnode.getSize();
			byte[] result = new byte[outSize];

			for (int i = outSize - 1, j = value.length - 1; i >= 0; i--, j--) {
				if (j >= 0) {
					result[i] = (byte) (~value[j] & 0xff);
				} else {
					result[i] = (byte) 0xff;
				}
			}

			memoryState.setValue(outputVarnode, new BigInteger(result));
		}
	}

	private class SIMD_INT_NEGATE extends SIMD_UOP1 {
		protected long op1(long x, int esize) { return ~x; }
	}

	// Multiprecision AND
	//
	// Vd = MP_INT_AND(Vn, Vm);
	//
	// Vd: destination varnode
	// Vn, Vm: values to bitwise and together

	@SuppressWarnings("unused")
	private class MP_INT_AND implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("MP_INT_AND: requires 2 (Vm, Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_AND: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			BigInteger value = memoryState.getBigInteger(inputs[1], false);
			BigInteger mask = memoryState.getBigInteger(inputs[2], false);

			BigInteger result = value.and(mask);

			memoryState.setValue(outputVarnode, result);
		}
	}

	private class SIMD_INT_XOR extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) { return x ^ y; }
	}

	private class SIMD_INT_AND extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) { return x & y; }
	}

	private class SIMD_INT_OR extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) { return x | y; }
	}

	private class SIMD_INT_LEFT extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) { return x << y; }
	}

	private class SIMD_INT_RIGHT extends SIMD_SOP2 {
		protected long op2(long x, long y, int esize) { return x >>> y; }
	}

	// Multiprecision (logical) right shift
	//
	// Vd = MP_INT_RIGHT(Vn, shift);
	//
	// Vd: destination varnode
	// Vn: value to shift
	// shift: amount to shift

	private class MP_INT_RIGHT implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("MP_INT_RIGHT: requires 2 (Vn, shift), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_RIGHT: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			// By extracting an unsigned value, the right shift is logical and not sign extended

			BigInteger value = memoryState.getBigInteger(inputs[1], false);
			int shift = (int) memoryState.getValue(inputs[2]);

			BigInteger result = value.shiftRight(shift);

			memoryState.setValue(outputVarnode, result);
		}
	}

	private class SIMD_INT_SRIGHT extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) { return x >> y; }
	}

	private class SIMD_INT_MULT extends SIMD_SOP2 {
		protected long op2(long x, long y, int esize) { return x * y; }
	}

	// Multiprecision Multiply.
	//
	// Vd = MP_INT_MULT(Vn, Vm);
	//
	// Vd: destination varnode
	// Vn, Vm: multiplicands

	private class MP_INT_MULT implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("MP_INT_MULT: requires 2 (Vm, Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_MULT: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			BigInteger value = memoryState.getBigInteger(inputs[1], true);
			BigInteger mult = memoryState.getBigInteger(inputs[2], true);

			BigInteger result = value.multiply(mult);

			memoryState.setValue(outputVarnode, result);
		}
	}

	// Multiprecision *Unsigned* Multiply.
	//
	// Vd = MP_INT_UMULT(Vn, Vm);
	//
	// Vd: destination varnode
	// Vn, Vm: multiplicands

	private class MP_INT_UMULT implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("MP_INT_UMULT: requires 2 (Vm, Vn), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("MP_INT_UMULT: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			BigInteger value = memoryState.getBigInteger(inputs[1], false);
			BigInteger mult = memoryState.getBigInteger(inputs[2], false);

			BigInteger result = value.multiply(mult);

			memoryState.setValue(outputVarnode, result);
		}
	}

	private class SIMD_FLOAT_ADD extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fy = shortBitsToFloat(y);
				float fz = fx + fy;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fy = Float.intBitsToFloat((int) y);
				float fz = fx + fy;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fy = Double.longBitsToDouble(y);
				double fz = fx + fy;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	@SuppressWarnings("unused")
	private class SIPD_FLOAT_ADD extends SIPD_UOP2 {
		@Override
		protected long op2(long x, long y, int iesize, int oesize) {
			if (iesize == 2) {
				float fx = shortBitsToFloat(x);
				float fy = shortBitsToFloat(y);
				float fz = fx + fy;
				if (oesize == 2) {
					return floatToShortBits(fz);
				}
				if (oesize == 4) {
					return (long) Float.floatToIntBits(fz);
				}
				if (oesize == 8) {
					return Double.doubleToLongBits((double) fz);
				}
			} else if (iesize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fy = Float.intBitsToFloat((int) y);
				float fz = fx + fy;
				if (oesize == 2) {
					return floatToShortBits(fz);
				}
				if (oesize == 4) {
					return (long) Float.floatToIntBits(fz);
				}
				if (oesize == 8) {
					return Double.doubleToLongBits((double) fz);
				}
			} else if (iesize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fy = Double.longBitsToDouble(y);
				double fz = fx + fy;
				if (oesize == 2) {
					return floatToShortBits((float) fz);
				}
				if (oesize == 4) {
					return (long) Float.floatToIntBits((float) fz);
				}
				if (oesize == 8) {
					return Double.doubleToLongBits(fz);
				}
			}
			return 0;
		}
	}

	private class SIMD_FLOAT_DIV extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fy = shortBitsToFloat(y);
				float fz = fx / fy;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fy = Float.intBitsToFloat((int) y);
				float fz = fx / fy;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fy = Double.longBitsToDouble(y);
				double fz = fx / fy;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	private class SIMD_FLOAT_MULT extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fy = shortBitsToFloat(y);
				float fz = fx * fy;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fy = Float.intBitsToFloat((int) y);
				float fz = fx * fy;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fy = Double.longBitsToDouble(y);
				double fz = fx * fy;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	private class SIMD_FLOAT_SUB extends SIMD_UOP2 {
		protected long op2(long x, long y, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fy = shortBitsToFloat(y);
				float fz = fx - fy;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fy = Float.intBitsToFloat((int) y);
				float fz = fx - fy;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fy = Double.longBitsToDouble(y);
				double fz = fx - fy;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	private class SIMD_FLOAT_NEG extends SIMD_UOP1 {
		protected long op1(long x, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fz = - fx;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fz = - fx;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fz = - fx;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	private class SIMD_FLOAT_ABS extends SIMD_UOP1 {
		protected long op1(long x, int esize) {
			if (esize == 2) {
				float fx = shortBitsToFloat(x);
				float fz = (fx < 0.0F) ? (0.0F - fx) : fx;
				return floatToShortBits(fz);
			} else if (esize == 4) {
				float fx = Float.intBitsToFloat((int) x);
				float fz = (fx < 0.0F) ? (0.0F - fx) : fx;
				return (long) Float.floatToIntBits(fz);
			} else if (esize == 8) {
				double fx = Double.longBitsToDouble(x);
				double fz = (fx < 0.0D) ? (0.0F - fx) : fx;
				return Double.doubleToLongBits(fz);
			}
			return 0;
		}
	}

	private class SIMD_FLOAT2FLOAT extends SIMD_UOP1E {
		protected long op1e(long x, int s_size, int d_size) {
			if (s_size == d_size) return x;
			if (s_size == 2) {
				float fx = shortBitsToFloat(x);
				if (d_size == 4) return (long) Float.floatToIntBits(fx);
				else if (d_size == 8) return Double.doubleToLongBits((double) fx);
			} else if (s_size == 4) {
				float fx = Float.intBitsToFloat((int) x);
				if (d_size == 2) return floatToShortBits(fx);
				else if (d_size == 8) return Double.doubleToLongBits((double) fx);
			} else if (s_size == 8) {
				double fx = Double.longBitsToDouble(x);
				if (d_size == 2) return floatToShortBits((float) fx);
				else if (d_size == 4) return Float.floatToIntBits((float) fx);
			}
			return x;
		}
	}

	private class SIMD_TRUNC extends SIMD_UOP1E {
		protected long op1e(long x, int s_size, int d_size) {
			if (s_size == d_size) return x;
			if (s_size == 2) {
				float fx = shortBitsToFloat(x);
				if (d_size == 4) return (long) ((int) fx);
				else if (d_size == 8) return (long) fx;
			} else if (s_size == 4) {
				float fx = Float.intBitsToFloat((int) x);
				if (d_size == 2) return (long) ((short) fx);
				else if (d_size == 8) return (long) fx;
			} else if (s_size == 8) {
				double fx = Double.longBitsToDouble(x);
				if (d_size == 2) return (long) ((short) fx);
				else if (d_size == 4) return (long) ((int) fx);
			}
			return x;
		}
	}

	@SuppressWarnings("unused")
	private class SIMD_FLOAT_ROUND extends SIMD_UOP1E {
		protected long op1e(long x, int s_size, int d_size) {
			if (s_size == 2) {
				float fx = shortBitsToFloat(x);
				return (long) fx;
			} else if (s_size == 4) {
				float fx = Float.intBitsToFloat((int) x);
				return (long) fx;
			} else if (s_size == 8) {
				double fx = Double.longBitsToDouble(x);
				return (long) fx;
			}
			return 0;
		}
	}

	// Extract a lane from a simd register
	//
	// Vd = SIMD_PIECE(Vn, offset);
	//
	// Vd = destination varnode
	// Vn = simd register
	// offset = the element to extract (0 = least significant)

	private class SIMD_PIECE implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			// Requires 2 inputs

			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError("SIMD_PIECE: requires 2 inputs, got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("SIMD_PIECE: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			// Get the init variable to output, the value to copy, and the offset

			Varnode simdVarnode = inputs[1];
			int offset = (int) memoryState.getValue(inputs[2]);

			if (simdVarnode.getSize() < (offset + 1) * outputVarnode.getSize()) {
				throw new LowlevelError("SIMD_PIECE: input size (" + simdVarnode.getSize()
						+ ") too small to extract output size (" + outputVarnode.getSize() + ") from offset (" + offset + ")");
			}

			// Allocate a byte array of the correct size to hold the output
			// initialized to all zeros

			int outSize = outputVarnode.getSize();
			byte[] outBytes = new byte[outSize];

			// Copy the bytes from the simd, in big endian
			// order, and maybe truncated and need sign
			// extension

			byte[] simdBytes = memoryState.getBigInteger(simdVarnode, false).toByteArray();
			byte ext = 0;

			for (int i = outSize - 1, j = simdBytes.length - 1 - outSize * offset; i >= 0; i--, j--) {
				if (j >= 0) {
					outBytes[i] = simdBytes[j];
					ext = (byte) ((simdBytes[j] < 0) ? -1 : 0);
				} else {
					outBytes[i] = ext;
				}
			}

			memoryState.setValue(outputVarnode, new BigInteger(outBytes));
		}
	}

	// Concatenate varnodes into a larger varnode
	//
	// Vd = a64_CONCAT(Vn, Vm)
	//
	// Vd = destination varnode
	// Vn, Vm = source varnodes

	@SuppressWarnings("unused")
	private class a64_CONCAT implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 2) {
				throw new LowlevelError(this.getClass().getName() + ": requires 2 inputs (Vn, Vm), got " + numArgs);
			}
			if (outputVarnode == null) {
				throw new LowlevelError(this.getClass().getName() + ": missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();

			int outSize = outputVarnode.getSize();

			Varnode VnVarnode = inputs[1];
			Varnode VmVarnode = inputs[2];

			if (outSize != VnVarnode.getSize() + VmVarnode.getSize()) {
				throw new LowlevelError(this.getClass().getName() + ": output size (" + outSize
					+ ") must equal the sum of input sizes (" + VnVarnode.getSize() + "," + VmVarnode.getSize() + ")");
			}

			byte[] outBytes = new byte[outSize];

			byte[] VnBytes = memoryState.getBigInteger(VnVarnode, false).toByteArray();
			byte[] VmBytes = memoryState.getBigInteger(VmVarnode, false).toByteArray();

			for (int i = outSize - 1, j = VnBytes.length - 1; i >= 0 && j >= 0; i--, j--) {
				outBytes[i] = VnBytes[j];
			}
			for (int i = outSize - VnVarnode.getSize() - 1, j = VmBytes.length - 1; i >= 0 && j >= 0; i--, j--) {
				outBytes[i] = VmBytes[j];
			}
		}
	}

	// Implementations of AARCH64 instructions

	// Implement the TBL/TBX instructions
	//
	// Vd = a64_TBL(Vinit, Vn1, [Vn2, Vn3, Vn3,] Vm)
	//
	// Vd: destination varnode (8 or 16 bytes)
	// Vinit: varnode to update (e.g. 0 or Vd)
	// Vn1: table varnode (must be 16 bytes)
	// Vn2, Vn3, Vn4: additional table varnodes
	// Vm: index varnode (8 or 16 bytes, same as Vd)

	private class a64_TBL implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {

			int numArgs = inputs.length - 1;
			if (numArgs < 3 || numArgs > 6) {
				throw new LowlevelError("a64_TBL: requires 3 to 6 inputs (Vinit, Vn-Vn4, Vm), got " + numArgs);
			}

			if (outputVarnode == null) {
				throw new LowlevelError("a64_TBL: missing required output");
			}

			MemoryState memoryState = emu.getMemoryState();
			Varnode updateVarnode = inputs[1];
			Varnode indexVarnode = inputs[numArgs];

			// The index size must match the output size
			if (outputVarnode.getSize() != indexVarnode.getSize()) {
				throw new LowlevelError("a64_TBL: the output size (" + outputVarnode.getSize()
					+ ") must match the index size (" + indexVarnode.getSize() + ")");
			}

			int regs = numArgs - 2;
			int elements = outputVarnode.getSize();

			// The indices are converted to little endian order
			byte[] indices = new byte[elements];
			byte[] vx = memoryState.getBigInteger(indexVarnode, false).toByteArray();
			for (int j = 0; j < vx.length && j < elements; j++) {
				indices[j] = vx[vx.length - j - 1];
			}

			// Create table from registers
			// It consists of 16, 32, 48, or 64 bytes from Vn1-Vn4
			// but these are indexed in little endian order.
			// The varnodes are in big endian order, so
			// they need to be reversed

			byte[] table = new byte[64];
			for (int i = 0; i < regs; i++) {
				byte[] vn = memoryState.getBigInteger(inputs[2 + i], false).toByteArray();
				for (int j = 0; j < vn.length && i * 16 + j < 64; j++) {
					table[i*16 + j] = vn[vn.length - j - 1];
				}
			}

			// The result is pre-initialized to Vi
			// and it is also converted to little endian
			// order just to make it easier to follow

			byte[] result = new byte[elements];
			byte[] vi = memoryState.getBigInteger(updateVarnode, false).toByteArray();
			for (int j = 0; j < vi.length && j < elements; j++) {
				result[j] = vi[vi.length - j - 1];
			}

			// Since the indices, table, and result
			// are all in little endian order
			// and since the byte arrays are all the right
			// size, it's just a simple lookup now

			for (int i = 0; i < elements; i++) {
				int index = (int) (indices[i] & 0xff);
				if (index < 16 * regs) {
					result[i] = table[index];
				}
			}

			// reverse the endianness of the result, in place
			// so the output can be updated

			for (int i = 0; i < elements / 2; i++) {
				byte tmp = result[i];
				result[i] = result[elements - i - 1];
				result[elements - i - 1] = tmp;
			}

			memoryState.setValue(outputVarnode, new BigInteger(result));
		}
	}
}
