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
import java.util.function.Function;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.floatformat.*;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.pcode.Varnode;

@Deprecated(forRemoval = true, since = "12.1")
public class HexagonEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	private static final FloatFormat fp64Format = FloatFormatFactory.getFloatFormat(8);

	private static final int FP64_BIAS = 1023;
	private static final int FP64_MANTISSA_BITS = 52;
	private static final int FP64_INFINITY_EXP = 0x7ff;

	public HexagonEmulateInstructionStateModifier(Emulate emu) {
		super(emu);
		registerPcodeOpBehavior("min", new SignedMinimumOpBehavior());
		registerPcodeOpBehavior("vlslh", new VectorLogicalShiftLeftOpBehavior("vlslh", 16, 7));
		registerPcodeOpBehavior("vlsrh", new VectorLogicalShiftRightOpBehavior("vlsrh", 16, 7));
		registerPcodeOpBehavior("vlslw", new VectorLogicalShiftLeftOpBehavior("vlslw", 32, 7));
		registerPcodeOpBehavior("vlsrw", new VectorLogicalShiftRightOpBehavior("vlsrw", 32, 7));
		registerPcodeOpBehavior("vmux", new VectorMultiplexOpBehavior());
		registerPcodeOpBehavior("vabsh", new VectorAbsoluteValueOpBehavior("vabsh", 16));
		registerPcodeOpBehavior("vabsw", new VectorAbsoluteValueOpBehavior("vabsw", 32));

		registerPcodeOpBehavior("dfmpyfix", new DFMultiplyFixOpBehavior());
		registerPcodeOpBehavior("dfmpyhh", new DFMultiplyHHOpBehavior());
		registerPcodeOpBehavior("dfmpylh", new DFMultiplyLHOpBehavior());
		registerPcodeOpBehavior("dfmpyll", new DFMultiplyLLOpBehavior());

		registerPcodeOpBehavior("isClassifiedFloat", new ClassifyFloatOpBehavior());
	}

	private static final long FP_ZERO_CLASS_MASK = 0x01;
	private static final long FP_NORMAL_CLASS_MASK = 0x02;
	private static final long FP_SUBNORMAL_CLASS_MASK = 0x04;
	private static final long FP_INFINITE_CLASS_MASK = 0x08;
	private static final long FP_NAN_CLASS_MASK = 0x10;

	private class ClassifyFloatOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {

			if (out == null) {
				throw new LowlevelError(
					"isClassifiedFloat: missing required output (predicate-storage)");
			}

			if (inputs.length != 2) {
				throw new LowlevelError(
					"isClassifiedFloat: requires two inputs (float-storage, constant-float-class-mask)");
			}

			MemoryState memoryState = e.getMemoryState();

			Varnode in1 = inputs[0]; // float value
			if (in1.isConstant()) {
				throw new LowlevelError("isClassifiedFloat: first input must not be constant");
			}
			if (in1.getSize() != 4 && in1.getSize() != 8) {
				throw new LowlevelError(
					"isClassifiedFloat: invalid float size of " + in1.getSize());
			}

			Varnode in2 = inputs[1]; // constant float-classification
			if (!in2.isConstant()) {
				throw new LowlevelError("isClassifiedFloat: second input must be constant");
			}

			FloatFormat floatFormat = FloatFormatFactory.getFloatFormat(in1.getSize());
			BigFloat bigFloat = floatFormat.decodeBigFloat(memoryState.getValue(in1));

			int floatClass = (int) in2.getOffset();

			boolean result = false;
			if ((floatClass & FP_ZERO_CLASS_MASK) != 0 && bigFloat.isZero()) {
				result = true;
			}
			if ((floatClass & FP_NORMAL_CLASS_MASK) != 0 && bigFloat.isNormal()) {
				result = true;
			}
			if ((floatClass & FP_SUBNORMAL_CLASS_MASK) != 0 && bigFloat.isDenormal()) {
				result = true;
			}
			if ((floatClass & FP_INFINITE_CLASS_MASK) != 0 && bigFloat.isInfinite()) {
				result = true;
			}
			if ((floatClass & FP_NAN_CLASS_MASK) != 0 && bigFloat.isNaN()) {
				result = true;
			}

			memoryState.setValue(out, result ? 0xff : 0);
		}
	}

	/**
	 * out = min(in1,in2) where in1/in2 may be constant
	 */
	private class SignedMinimumOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {

			if (out == null) {
				throw new LowlevelError("min: missing required output");
			}

			if (inputs.length != 2) {
				throw new LowlevelError("min: requires two inputs");
			}

			MemoryState memoryState = e.getMemoryState();

			Varnode in1 = inputs[0];
			Varnode in2 = inputs[1];

			long value1 = in1.isConstant() ? in1.getOffset() : memoryState.getValue(in1);
			value1 = Utils.sign_extend(value1, in1.getSize(), 8);

			long value2 = in2.isConstant() ? in2.getOffset() : memoryState.getValue(in2);
			value2 = Utils.sign_extend(value2, in2.getSize(), 8);

			// TODO: Unsure if min operation is signed or unsigned

			memoryState.setValue(out, Math.min(value1, value2));
		}

	}

	/**
	 * Rdd = vmux(Pn,Rss,Rtt)
	 */
	private class VectorMultiplexOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {

			if (out == null) {
				throw new LowlevelError("vmux: missing required double-word output (Rdd)");
			}

			if (inputs.length != 3) {
				throw new LowlevelError("vmux: requires three inputs");
			}

			MemoryState memoryState = e.getMemoryState();

			Varnode in1 = inputs[0];
			Varnode in2 = inputs[1];
			Varnode in3 = inputs[2];

			if (out.getSize() != 8 || in2.getSize() != 8 || in3.getSize() != 8) {
				throw new LowlevelError(
					"vmux: multiplexed input and output sizes must be double-word");
			}

			long predicate = in1.isConstant() ? in1.getOffset() : memoryState.getValue(in1);
			long value2 = in2.isConstant() ? in2.getOffset() : memoryState.getValue(in2);
			long value3 = in3.isConstant() ? in3.getOffset() : memoryState.getValue(in3);

			long result = 0;
			for (int i = 0; i < 8; i++) {
				long byteValue = ((predicate & 1) != 0 ? value2 : value3) & 0x0ff;
				result |= byteValue << (i * 8);
				predicate >>= 1;
				value2 >>= 8;
				value3 >>= 8;
			}

			memoryState.setValue(out, result);
		}

	}

	private abstract class VectorOpBehavior implements OpBehaviorOther {

		protected final String opName;
		protected final int slotBitSize;
		protected final long slotMask;

		VectorOpBehavior(String opName, int slotBitSize) {
			this.opName = opName;
			this.slotBitSize = slotBitSize;
			slotMask = ~(-1L << slotBitSize);
		}

		protected void evaluate(MemoryState memoryState, Varnode out, long[] inputs,
				Function<Integer, Long> opFunction) {

			if (out == null) {
				throw new LowlevelError(opName + ": missing required double-word output (Rdd)");
			}
			if (out.getSize() != 8) {
				throw new LowlevelError(opName + ": output size must be double-word");
			}

			long result = 0;
			for (int slot = (64 / slotBitSize) - 1; slot >= 0; slot--) {
				result <<= slotBitSize;
				result |= opFunction.apply(slot) & slotMask;
			}
			memoryState.setValue(out, result);
		}
	}

	private class VectorLogicalShiftRightOpBehavior extends VectorOpBehavior {

		private final int shiftBitSize;

		VectorLogicalShiftRightOpBehavior(String opName, int slotBitSize, int shiftBitSize) {
			super(opName, slotBitSize);
			this.shiftBitSize = shiftBitSize;
		}

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			if (inputs.length != 2) {
				throw new LowlevelError(opName + ": requires two inputs");
			}

			MemoryState memoryState = e.getMemoryState();
			long source = memoryState.getValue(inputs[0]);

			// signed shift value (negative value is left shift)
			long shiftValue =
				inputs[1].isConstant() ? inputs[1].getOffset() : memoryState.getValue(inputs[1]);
			int s = 64 - shiftBitSize;
			shiftValue = (shiftValue << s) >> s; // sign-extend shift value

			final long shift = shiftValue;
			evaluate(memoryState, out, new long[] { source, shift }, slot -> {
				long r = 0;
				if (Math.abs(shift) < 64) {
					int slotShift = slot * slotBitSize;
					r = (source >> slotShift) & slotMask;
					if (shift < 0) {
						r <<= -shift;
					}
					else {
						r >>>= shift;
					}
					r &= slotMask;
				}
				return r;
			});
		}
	}

	private class VectorLogicalShiftLeftOpBehavior extends VectorOpBehavior {

		private final int shiftBitSize;

		VectorLogicalShiftLeftOpBehavior(String opName, int slotBitSize, int shiftBitSize) {
			super(opName, slotBitSize);
			this.shiftBitSize = shiftBitSize;
		}

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			if (inputs.length != 2) {
				throw new LowlevelError(opName + ": requires two inputs");
			}

			MemoryState memoryState = e.getMemoryState();
			long source = memoryState.getValue(inputs[0]);

			// signed shift value (negative value is right shift)
			long shiftValue =
				inputs[1].isConstant() ? inputs[1].getOffset() : memoryState.getValue(inputs[1]);
			int s = 64 - shiftBitSize;
			shiftValue = (shiftValue << s) >> s; // sign-extend shift value

			final long shift = shiftValue;
			evaluate(memoryState, out, new long[] { source, shift }, slot -> {
				long r = 0;
				if (Math.abs(shift) < 64) {
					int slotShift = slot * slotBitSize;
					r = (source >> slotShift) & slotMask;
					if (shift < 0) {
						r >>>= -shift;
					}
					else {
						r <<= shift;
					}
					r &= slotMask;
				}
				return r;
			});
		}
	}

	private class VectorAbsoluteValueOpBehavior extends VectorOpBehavior {

		private final long signBitMask;

		VectorAbsoluteValueOpBehavior(String opName, int slotBitSize) {
			super(opName, slotBitSize);
			signBitMask = 1 << (slotBitSize - 1);
		}

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			if (inputs.length != 1) {
				throw new LowlevelError(opName + ": requires one input");
			}

			MemoryState memoryState = e.getMemoryState();
			long source = memoryState.getValue(inputs[0]);

			evaluate(memoryState, out, new long[] { source }, slot -> {
				int slotShift = slot * slotBitSize;
				long r = (source >> slotShift) & slotMask;
				if ((r & signBitMask) != 0) {
					r = (~r + 1) & slotMask; // negate with 2's complement
				}
				return r;
			});
		}
	}

	private class DFMultiplyFixOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {

			if (out == null || out.getSize() != 8) {
				throw new LowlevelError("dfmpyfix: requires 8-byte output");
			}

			if (inputs.length != 2) {
				throw new LowlevelError("dfmpyfix: requires two inputs");
			}

			for (int i = 0; i < 2; i++) {
				if (inputs[i].getSize() != 8) {
					throw new LowlevelError("dfmpyhh: requires two 8-byte inputs");
				}
			}

			MemoryState memoryState = e.getMemoryState();
			long rss = memoryState.getValue(inputs[0]);
			long rtt = memoryState.getValue(inputs[1]);

			BigFloat rssBf = fp64Format.decodeBigFloat(rss);
			BigFloat rttBf = fp64Format.decodeBigFloat(rtt);

			long result = rss;
			if (!rssBf.isNormal() && (getExponent(rtt, rttBf) >= 512) && rttBf.isNormal()) {
				rssBf.mul(fp64Format.decodeBigFloat(0x4330000000000000L));
				result = fp64Format.getEncoding(rssBf).longValue();
			}
			else if (!rttBf.isNormal() && (getExponent(rss, rssBf) >= 512) && rssBf.isNormal()) {
				rssBf.mul(fp64Format.decodeBigFloat(0x3cb0000000000000L));
				result = fp64Format.getEncoding(rssBf).longValue();
			}
			memoryState.setValue(out, result);
		}

	}

	private class DFMultiplyHHOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			// Multiply high*high and accumulate with L*H value

			if (out == null || out.getSize() != 8) {
				throw new LowlevelError("dfmpyhh: requires 8-byte output");
			}

			if (inputs.length != 3) {
				throw new LowlevelError("dfmpyhh: requires three inputs");
			}

			for (int i = 0; i < 3; i++) {
				if (inputs[i].getSize() != 8) {
					throw new LowlevelError("dfmpyhh: requires three 8-byte inputs");
				}
			}

			MemoryState memoryState = e.getMemoryState();
			long rdd = memoryState.getValue(inputs[0]); // accumulated
			long rss = memoryState.getValue(inputs[1]);
			long rtt = memoryState.getValue(inputs[2]);

			BigFloat rssBf = fp64Format.decodeBigFloat(rss);
			BigFloat rttBf = fp64Format.decodeBigFloat(rtt);

			long result;
			if (rssBf.isZero() || rssBf.isNaN() || rssBf.isInfinite() || rttBf.isZero() ||
				rttBf.isNaN() || rttBf.isInfinite()) {
				result = fp64Format.getEncoding(BigFloat.mul(rssBf, rttBf)).longValue();
			}
			else {
				FPAccumulator x = new FPAccumulator();

				x.sticky = (rdd & 1) != 0;
				x.mant = toUnsignedBigInteger(rdd >> 1);

				long prod = (getMantissa(rss, rssBf) >>> 32) * (getMantissa(rtt, rttBf) >>> 32);
				x.mant = toUnsignedBigInteger(prod).multiply(toUnsignedBigInteger(0x100000000L))
						.add(x.mant);
				x.exp = getExponent(rss, rssBf) + getExponent(rtt, rttBf) - FP64_BIAS - 20;

				if (!rssBf.isNormal() || !rttBf.isNormal()) {
					// crush to inexact zero 
					x.sticky = true;
					x.exp = -4096;
				}

				x.negative = isNegative(rss) ^ isNegative(rtt);

				result = round(x);
			}
			memoryState.setValue(out, result);
		}
	}

	private static class FPAccumulator {
		BigInteger mant = BigInteger.ZERO;
		int exp;
		boolean negative;
		boolean guard;
		boolean round;
		boolean sticky;
	}

	private static BigInteger toUnsignedBigInteger(long ulong) {
		if (ulong >= 0L) {
			return BigInteger.valueOf(ulong);
		}
		int upper = (int) (ulong >>> 32);
		int lower = (int) ulong;
		return (BigInteger.valueOf(Integer.toUnsignedLong(upper))).shiftLeft(32)
				.add(BigInteger.valueOf(Integer.toUnsignedLong(lower)));
	}

	private static boolean isNegative(long f64) {
		return f64 < 0;
	}

	private static int getExponent(long f64, BigFloat f) {
		int exp = (int) (f64 >> FP64_MANTISSA_BITS) & 0x7ff;
		if (f.isNormal()) {
			return exp;
		}
		if (f.isDenormal()) {
			return exp + 1;
		}
		return -1;
	}

	private static long getMantissa(long f64, BigFloat f) {
		int shift = 64 - FP64_MANTISSA_BITS;
		long aMant = (f64 << shift) >>> shift;
		if (f.isNormal()) {
			aMant |= (1L << FP64_MANTISSA_BITS);
		}
		else if (f.isZero()) {
			aMant = 0L;
		}
		else if (!f.isDenormal()) {
			aMant = ~0L;
		}
		return aMant;
	}

	private static long getLo64(BigInteger b) {
		return b.longValue();
	}

	private static long getHi64(BigInteger b) {
		return b.shiftRight(64).longValue();
	}

	/**
	 * Perform normalization and rounding of FP64 accumulator value.
	 * 
	 * @param x accumulator
	 * @return encoded fp64 value
	 */
	private static long round(FPAccumulator x) {

		if ((x.sticky || x.round || x.guard) && x.mant.equals(BigInteger.ZERO)) {
			return fp64Format.getZeroEncoding(false);
		}

		while (getHi64(x.mant) != 0 || (getLo64(x.mant) >>> (FP64_MANTISSA_BITS + 1) != 0)) {
			normalizeRight(x, 1);
		}

		while ((getLo64(x.mant) & (1L << FP64_MANTISSA_BITS)) == 0) {
			normalizeLeft(x);
		}

		while (x.exp <= 0) {
			normalizeRight(x, 1 - x.exp);
//			if (x.sticky || x.round || x.guard) {
//				// raise underflow
//			}
		}

		if (getLo64(x.mant) >> (FP64_MANTISSA_BITS + 1) != 0) {
			normalizeRight(x, 1);
		}

		if (x.exp >= FP64_INFINITY_EXP) {
			return fp64Format.getInfinityEncoding(x.negative);
		}

		long f64 = 0;
		if (x.negative) {
			f64 = Long.MIN_VALUE;
		}
		if ((getLo64(x.mant) & (1L << FP64_MANTISSA_BITS)) != 0) {
			f64 |= ((long) x.exp) << FP64_MANTISSA_BITS;
		}
		f64 |= getLo64(x.mant) & 0xfffffffffffffL;
		return f64;
	}

	private static void normalizeLeft(FPAccumulator x) {
		x.exp--;
		x.mant = x.mant.shiftLeft(1);
		if (x.guard) {
			x.mant = x.mant.or(BigInteger.ONE);
		}
		x.guard = x.round;
		x.round = x.sticky;
	}

	private static void normalizeRight(FPAccumulator a, int n) {
		if (n > 130) {
			a.sticky |= a.round | a.guard | (a.mant.compareTo(BigInteger.ZERO) == 0);
			a.guard = a.round = false;
			a.mant = BigInteger.ZERO;
			a.exp += n;
			return;
		}
		while (n >= 64) {
			a.sticky |= a.round | a.guard | (getLo64(a.mant) != 0);
			a.guard = ((getLo64(a.mant) >> 63) & 1) != 0;
			a.round = ((getLo64(a.mant) >> 62) & 1) != 0;
			a.mant = toUnsignedBigInteger(getHi64(a.mant));
			a.exp += 64;
			n -= 64;
		}
		while (n > 0) {
			a.exp++;
			a.sticky |= a.round;
			a.round = a.guard;
			a.guard = (getLo64(a.mant) & 1) != 0;
			a.mant = a.mant.shiftRight(1);
			n--;
		}
	}

	public static void main(String[] args) {

		long expect = 0x4023b81d7dbf4880L;
		long rdd = 0x00202752200f06f7L; // memoryState.getValue(inputs[1]); // accumulated
		long rss = 0x40091eb851eb851fL;
		long rtt = 0x40091eb851eb851fL;

		BigFloat expBf = fp64Format.decodeBigFloat(expect);

		BigFloat rddBf = fp64Format.decodeBigFloat(rdd);
		BigFloat rssBf = fp64Format.decodeBigFloat(rss);
		BigFloat rttBf = fp64Format.decodeBigFloat(rtt);

		BigFloat expProdBf = BigFloat.sub(expBf, rddBf);

		System.out.println("expectProd=" + fp64Format.round(expProdBf).toString());
		System.out.println("rss=" + fp64Format.round(rssBf).toString());
		System.out.println("rtt=" + fp64Format.round(rttBf).toString());

		FPAccumulator x = new FPAccumulator();

		x.sticky = (rdd & 1) != 0;
		x.mant = toUnsignedBigInteger(rdd >> 1);

		long prod = (getMantissa(rss, rssBf) >>> 32) * (getMantissa(rtt, rttBf) >>> 32);
		x.mant =
			toUnsignedBigInteger(prod).multiply(toUnsignedBigInteger(0x100000000L)).add(x.mant);
		x.exp = getExponent(rss, rssBf) + getExponent(rtt, rttBf) - FP64_BIAS - 20;

		if (!rssBf.isNormal() || !rttBf.isNormal()) {
			// crush to inexact zero 
			x.sticky = true;
			x.exp = -4096;
		}

		x.negative = isNegative(rss) ^ isNegative(rtt);

		long result = round(x);
		BigFloat resultBf = fp64Format.decodeBigFloat(result);

		System.out.println("result=" + fp64Format.round(resultBf).toString());
		System.out.println("expected=" + fp64Format.round(expBf).toString());

		System.out.println(
			"result: 0x" + Long.toHexString(result) + "   Expected: 0x" + Long.toHexString(expect));

	}

	private class DFMultiplyLHOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			// Multiply low*high and accumulate
			// Rdd32 += (Rss.uw[0] * (0x00100000 | zxt 20->64 (Rtt.uw[1]))) << 1;

			if (out == null || out.getSize() != 8) {
				throw new LowlevelError("dfmpylh: requires 8-byte output");
			}

			if (inputs.length != 3) {
				throw new LowlevelError("dfmpylh: requires three inputs");
			}

			for (int i = 0; i < 3; i++) {
				if (inputs[i].getSize() != 8) {
					throw new LowlevelError("dfmpylh: requires three 8-byte inputs");
				}
			}

			MemoryState memoryState = e.getMemoryState();
			long rdd = memoryState.getValue(inputs[0]); // accumulated
			long rssLo = memoryState.getValue(inputs[1]) & 0xffffffffL; // Rss.uw[0]
			long rttHi = memoryState.getValue(inputs[2]) >>> 32; // Rtt.uw[1]

			long prod = (rssLo * (0x00100000L | (rttHi & 0xfffffL))) << 1;
			long result = rdd + prod;

			memoryState.setValue(out, result);
		}

	}

	private class DFMultiplyLLOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate e, Varnode out, Varnode[] inputs) {
			// Multiply low*low and shift off low 32 bits into sticky (in MSB)

			if (out == null || out.getSize() != 8) {
				throw new LowlevelError("dfmpyll: requires 8-byte output");
			}

			if (inputs.length != 2) {
				throw new LowlevelError("dfmpyll: requires two inputs");
			}

			for (int i = 0; i < 2; i++) {
				if (inputs[i].getSize() != 8) {
					throw new LowlevelError("dfmpyll: requires two 8-byte inputs");
				}
			}

			MemoryState memoryState = e.getMemoryState();
			long rssLo = memoryState.getValue(inputs[0]) & 0xffffffffL;
			long rttLo = memoryState.getValue(inputs[1]) & 0xffffffffL;
			long prod = rssLo * rttLo;
			long result = (prod >>> 32) << 1;
			if ((prod & 0xffffffffL) != 0) {
				result |= 1;
			}
			memoryState.setValue(out, result);
		}

	}
}
