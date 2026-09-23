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
package ghidra.pcode.emu.jit.folding;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;

public abstract class AbstractFoldedArithmeticTest {
	abstract Endian getEndian();

	final Endian endian = getEndian();
	final FoldedArithmetic arithmetic = FoldedArithmetic.forEndian(endian);

	MaskedBytes ofFloat(float f) {
		return MaskedBytes.of(Float.floatToRawIntBits(f), -1, 4, endian);
	}

	MaskedBytes ofFloatMasked(float f, int msk) {
		return MaskedBytes.of(Float.floatToRawIntBits(f), msk, 4, endian);
	}

	@Test
	public void testCopy() {
		MaskedBytes mb = MaskedBytes.of(0x1234, -1, 2, endian);
		assertEquals(mb, arithmetic.unaryOp(PcodeOp.COPY, 2, 2, mb));
	}

	@Test
	public void testNegate() {
		assertEquals(MaskedBytes.of(~0x1234, -1, 2, endian),
			arithmetic.unaryOp(PcodeOp.INT_NEGATE, 2, 2,
				MaskedBytes.of(0x1234, -1, 2, endian)));
		assertEquals(MaskedBytes.of(~0x1234, 0x7fff, 2, endian),
			arithmetic.unaryOp(PcodeOp.INT_NEGATE, 2, 2,
				MaskedBytes.of(0x1234, 0x7fff, 2, endian)));
	}

	@Test
	public void testFloatAbs() {
		assertEquals(ofFloat(0.5f), arithmetic.unaryOp(PcodeOp.FLOAT_ABS, 4, 4, ofFloat(0.5f)));
		assertEquals(ofFloat(0.5f), arithmetic.unaryOp(PcodeOp.FLOAT_ABS, 4, 4, ofFloat(-0.5f)));
		assertEquals(ofFloat(0.5f),
			arithmetic.unaryOp(PcodeOp.FLOAT_ABS, 4, 4, ofFloatMasked(0.5f, 0x7fffffff)));
		assertEquals(ofFloatMasked(0.5f, 0xbfffffff),
			arithmetic.unaryOp(PcodeOp.FLOAT_ABS, 4, 4, ofFloatMasked(0.5f, 0x3fffffff)));
	}

	@Test
	public void testFloatNeg() {
		assertEquals(ofFloat(-0.5f), arithmetic.unaryOp(PcodeOp.FLOAT_NEG, 4, 4, ofFloat(0.5f)));
		assertEquals(ofFloat(0.5f), arithmetic.unaryOp(PcodeOp.FLOAT_NEG, 4, 4, ofFloat(-0.5f)));
		assertEquals(ofFloatMasked(0.5f, 0x7fffffff),
			arithmetic.unaryOp(PcodeOp.FLOAT_NEG, 4, 4, ofFloatMasked(0.5f, 0x7fffffff)));
		assertEquals(ofFloatMasked(-0.5f, 0xbfffffff),
			arithmetic.unaryOp(PcodeOp.FLOAT_NEG, 4, 4, ofFloatMasked(0.5f, 0xbfffffff)));
		assertEquals(ofFloatMasked(0.5f, 0xbfffffff),
			arithmetic.unaryOp(PcodeOp.FLOAT_NEG, 4, 4, ofFloatMasked(-0.5f, 0xbfffffff)));
	}

	@Test
	public void testIntSExt() {
		assertEquals(MaskedBytes.of(-1, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_SEXT, 4, 2, MaskedBytes.of(-1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(1, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_SEXT, 4, 2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0xffff8000, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_SEXT, 4, 2, MaskedBytes.of(0x8000, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0, 0, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_SEXT, 4, 2, MaskedBytes.of(0, 0, 2, endian)));
	}

	@Test
	public void testIntZExt() {
		assertEquals(MaskedBytes.of(0xffff, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_ZEXT, 4, 2, MaskedBytes.of(-1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(1, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_ZEXT, 4, 2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0x00008000, -1, 4, endian),
			arithmetic.unaryOp(PcodeOp.INT_ZEXT, 4, 2, MaskedBytes.of(0x8000, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0, 0xffff0000, 4, endian), // Upper bits become known 0s
			arithmetic.unaryOp(PcodeOp.INT_ZEXT, 4, 2, MaskedBytes.of(0, 0, 2, endian)));
	}

	@Test
	public void testUnaryMisc() {
		assertEquals(ofFloat((float) Math.sqrt(0.5f)),
			arithmetic.unaryOp(PcodeOp.FLOAT_SQRT, 4, 4, ofFloat(0.5f)));
		assertEquals(MaskedBytes.ofUnknown(4),
			arithmetic.unaryOp(PcodeOp.FLOAT_SQRT, 4, 4, ofFloatMasked(0.5f, 0xffff7fff)));
	}

	@Test
	public void testIntAnd() {
		//   01x01x01x
		// & 000111xxx
		// -----------
		//   00001x0xx
		assertEquals(MaskedBytes.of(0b000010000, 0b111110100, 4, endian),
			arithmetic.binaryOp(PcodeOp.INT_AND, 4,
				4, MaskedBytes.of(0b010010010, 0b110110110, 4, endian),
				4, MaskedBytes.of(0b000111000, 0b111111000, 4, endian)));
	}

	@Test
	public void testIntOr() {
		//   01x01x01x
		// | 000111xxx
		// -----------
		//   01x111x1x
		assertEquals(MaskedBytes.of(0b010111010, 0b110111010, 4, endian),
			arithmetic.binaryOp(PcodeOp.INT_OR, 4,
				4, MaskedBytes.of(0b010010010, 0b110110110, 4, endian),
				4, MaskedBytes.of(0b000111000, 0b111111000, 4, endian)));
	}

	@Test
	public void testIntXor() {
		//   01x01x01x
		// ^ 000111xxx
		// -----------
		//   01x10xxxx
		assertEquals(MaskedBytes.of(0b010100000, 0b110110000, 4, endian),
			arithmetic.binaryOp(PcodeOp.INT_XOR, 4,
				4, MaskedBytes.of(0b010010010, 0b110110110, 4, endian),
				4, MaskedBytes.of(0b000111000, 0b111111000, 4, endian)));
	}

	@Test
	public void testLeft() {
		// Right is filled with known 0s
		assertEquals(MaskedBytes.of(0x0460, 0x1fe1, 4, endian),
			arithmetic.binaryOp(PcodeOp.INT_LEFT, 4,
				4, MaskedBytes.of(0x0230, 0x0ff0, 4, endian),
				4, MaskedBytes.of(1, -1, 4, endian)));
		assertEquals(MaskedBytes.ofUnknown(4),
			arithmetic.binaryOp(PcodeOp.INT_LEFT, 4,
				4, MaskedBytes.of(0x0230, 0x0ff0, 4, endian),
				4, MaskedBytes.of(1, 0xfffffffb, 4, endian)));

		// What if value is all known 0s? Shift amount wouldn't matter.
	}

	@Test
	public void testRight() {
		// Left is filled with known 0s
		assertEquals(MaskedBytes.of(0x0118, 0x87f8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_RIGHT, 2,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0x0118, 0xfff8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_RIGHT, 2,
				2, MaskedBytes.of(0x0230, 0xfff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0x4118, 0xfff8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_RIGHT, 2,
				2, MaskedBytes.of(0x8230, 0xfff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));

		assertEquals(MaskedBytes.ofUnknown(2),
			arithmetic.binaryOp(PcodeOp.INT_RIGHT, 2,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				2, MaskedBytes.of(1, 0xfffffffb, 2, endian)));

		// What if value is all known 0s? Shift amount wouldn't matter.
	}

	@Test
	public void testSRight() {
		// Left is filled with sign bit
		assertEquals(MaskedBytes.of(0x0118, 0x07f8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_SRIGHT, 2,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0x0118, 0xfff8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_SRIGHT, 2,
				2, MaskedBytes.of(0x0230, 0xfff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));
		assertEquals(MaskedBytes.of(0xc118, 0xfff8, 2, endian),
			arithmetic.binaryOp(PcodeOp.INT_SRIGHT, 2,
				2, MaskedBytes.of(0x8230, 0xfff0, 2, endian),
				2, MaskedBytes.of(1, -1, 2, endian)));

		assertEquals(MaskedBytes.ofUnknown(2),
			arithmetic.binaryOp(PcodeOp.INT_SRIGHT, 2,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				2, MaskedBytes.of(1, 0xfffffffb, 2, endian)));

		// What if value is all known 0s? Shift amount wouldn't matter.
	}

	@Test
	public void testSubPiece() {
		// Left is filled with known 0s, if needed
		// Identity
		assertEquals(MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 2,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(0, -1, 1, endian)));
		// LSB
		assertEquals(MaskedBytes.of(0x30, 0xf0, 1, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 1,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(0, -1, 1, endian)));
		// MSB
		assertEquals(MaskedBytes.of(0x02, 0x0f, 1, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 1,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(1, -1, 1, endian)));
		// OOB
		assertEquals(MaskedBytes.of(0x00, 0xff, 1, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 1,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(2, -1, 1, endian)));
		// ZEXT
		assertEquals(MaskedBytes.of(0x000230, 0xff0ff0, 3, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 3,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(0, -1, 1, endian)));
		// ZEXT(1)
		assertEquals(MaskedBytes.of(0x000002, 0xffff0f, 3, endian),
			arithmetic.binaryOp(PcodeOp.SUBPIECE, 3,
				2, MaskedBytes.of(0x0230, 0x0ff0, 2, endian),
				1, MaskedBytes.of(1, -1, 1, endian)));
	}

	@Test
	public void testBinaryMisc() {
		assertEquals(MaskedBytes.of(6, -1, 4, endian),
			arithmetic.binaryOp(PcodeOp.INT_MULT, 4,
				4, MaskedBytes.of(2, -1, 4, endian),
				4, MaskedBytes.of(3, -1, 4, endian)));
		assertEquals(MaskedBytes.ofUnknown(4),
			arithmetic.binaryOp(PcodeOp.INT_MULT, 4,
				4, MaskedBytes.of(2, -1, 4, endian),
				4, MaskedBytes.of(3, 0xffff7fff, 4, endian)));
		assertEquals(MaskedBytes.ofUnknown(4),
			arithmetic.binaryOp(PcodeOp.INT_MULT, 4,
				4, MaskedBytes.of(2, 0xffff7fff, 4, endian),
				4, MaskedBytes.of(3, -1, 4, endian)));
	}
}
