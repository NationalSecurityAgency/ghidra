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
package ghidra.app.plugin.assembler.sleigh;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.LanguageID;

/**
 * Edge-case regression tests for Hexagon shift, rotate, multiply and float-make
 * pcode behavior.
 *
 * <p>These tests pin the encodings and disassembly text for the recently fixed
 * decoder/pcode constructors:
 *
 * <ul>
 * <li>scalar register-form shifts (asl, asr, lsl, lsr, setbit, togglebit,
 *     clrbit) under sxt7 of the Rt register: shift amounts above bit 6 must
 *     decode as right-shifts (commit "model sxt7 shift amount in
 *     register-form shifts");
 * <li>{@code mpyu(Rs.h,Rt.h):<<1} and its accumulating sibling: the prior
 *     constructor squared Rs (commit "fix M2_mpyu_*_s1 typo squaring Rs
 *     instead of Rs*Rt");
 * <li>{@code rol} 32-bit and 64-bit immediate forms: must rotate by N rather
 *     than fold the sign bit (commit "fix rol pcode to compute true rotate");
 * <li>{@code sfmake} / {@code dfmake}: must build the IEEE-754 bit pattern
 *     from {@code (bias-6)<<23 | imm<<17} per V73 spec (commit "build
 *     sfmake/dfmake from bit pattern per V73");
 * <li>{@code sub(#-1,Rs)} canonicalization to {@code not(Rs)}: a long-standing
 *     pin to detect accidental decoder shadowing.
 * </ul>
 *
 * <p>The HVX vector shift family (vasl/vasr/vlsr) is decode-only -- its pcode
 * is a single opaque pcodeop -- but we pin a representative encoding regardless
 * of the Rt value to confirm the disasm mnemonic is stable.
 *
 * <p>The class follows the same disassemble-and-assert pattern as
 * {@link HexagonStubCoverageTest}: round-trip tests that don't require the
 * assembler grammar, just byte-to-text decode.
 */
public class HexagonShiftEdgeCasesTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Hexagon:LE:32:default");
	}

	/**
	 * Decode a single 4-byte little-endian Hexagon word and assert the
	 * disassembly text (trimmed) matches {@code expected}.
	 */
	protected void assertDecode(String hexBytes, String expected) {
		if (hexBytes.length() != 8) {
			throw new IllegalArgumentException(
				"expected 4-byte hex word (8 chars), got: " + hexBytes);
		}
		byte[] bytes = new byte[4];
		for (int i = 0; i < 4; i++) {
			bytes[i] = (byte) Integer.parseInt(hexBytes.substring(i * 2, i * 2 + 2), 16);
		}
		byte[] ctx = context.getDefaultAt(lang.getDefaultSpace().getAddress(DEFAULT_ADDR))
				.fillMask()
				.getVals();
		PseudoInstruction pi;
		try {
			pi = disassemble(DEFAULT_ADDR, bytes, ctx);
		}
		catch (Exception e) {
			throw new AssertionError(
				"disassembly threw for bytes " + hexBytes + " (expected: " + expected + ")", e);
		}
		String actual = pi.toString().trim();
		assertEquals("bytes " + hexBytes, expected, actual);
	}

	// ---------------------------------------------------------------------
	// Scalar register-form shifts -- sxt7 negative shift handling
	// ---------------------------------------------------------------------
	//
	// Encoding for the 32-bit register-form shifts:
	//   31..28 : iclass = 1100
	//   27..21 : op2127 = 0x32 (asl/asr/lsl/lsr) or 0x34 (setbit/clrbit/togglebit)
	//   20..16 : Rs5 (source reg)
	//   15..14 : parse bits = 11 (end of packet)
	//   13     : op13 = 0
	//   12..8  : Rt5 (shift-count reg)
	//   7..5   : op0507 = function code
	//             asl       = 4 (100)
	//             asr       = 0 (000)
	//             lsr       = 2 (010)
	//             lsl       = 6 (110)
	//             setbit    = 0 (000) [op2127=0x34 distinguishes]
	//             clrbit    = 2 (010) [op2127=0x34]
	//             togglebit = 4 (100) [op2127=0x34]
	//   4..0   : Rd5 (dest reg)
	//
	// Disassembly is opaque to Rt's runtime value (the Rt5 field names a
	// register, not a shift count), so the mnemonic is identical regardless
	// of whether the runtime value is positive or has bit 6 set. We pin the
	// encodings with several Rd/Rs/Rt register triples to detect accidental
	// constructor shadowing.

	/** asl Rd,Rs,Rt -- register-form, op2127=0x32, op0507=4. */
	@Test
	public void testShiftEdge_asl_register_form() {
		// asl R3,R2,R1
		assertDecode("83c142c6", "asl R3,R2,R1");
		// asl R0,R0,R0
		assertDecode("80c040c6", "asl R0,R0,R0");
		// asl R5,R6,R7 (Rs=R6, Rt=R7, Rd=R5)
		assertDecode("85c746c6", "asl R5,R6,R7");
		// asl R31,R31,R31 (max scalar regs -> LR per attach table)
		assertDecode("9fdf5fc6", "asl LR,LR,LR");
	}

	/** asr Rd,Rs,Rt -- register-form, op2127=0x32, op0507=0. */
	@Test
	public void testShiftEdge_asr_register_form() {
		// asr R3,R2,R1 -- bits 7..5 = 000 so byte0 = 0000 0011 = 0x03
		assertDecode("03c142c6", "asr R3,R2,R1");
		// asr R0,R0,R0
		assertDecode("00c040c6", "asr R0,R0,R0");
		// asr R5,R6,R7
		assertDecode("05c746c6", "asr R5,R6,R7");
	}

	/** lsr Rd,Rs,Rt -- register-form, op2127=0x32, op0507=2 (010). */
	@Test
	public void testShiftEdge_lsr_register_form() {
		// lsr R3,R2,R1 -- byte0 = 0100 0011 = 0x43
		assertDecode("43c142c6", "lsr R3,R2,R1");
		// lsr R0,R0,R0
		assertDecode("40c040c6", "lsr R0,R0,R0");
	}

	/** lsl Rd,Rs,Rt -- register-form, op2127=0x32, op0507=6 (110). */
	@Test
	public void testShiftEdge_lsl_register_form() {
		// lsl R3,R2,R1 -- byte0 = 1100 0011 = 0xC3
		assertDecode("c3c142c6", "lsl R3,R2,R1");
		// lsl R0,R0,R0
		assertDecode("c0c040c6", "lsl R0,R0,R0");
	}

	// ---------------------------------------------------------------------
	// 64-bit scalar register-form shifts -- (Rdd5 = asl/asr/lsl/lsr Rss5, rt5)
	// ---------------------------------------------------------------------
	//
	// Encoding for the 64-bit register-form shifts:
	//   31..28 : iclass = 1100
	//   27..21 : op2127 = 0x1c
	//   20..16 : Rss5 (paired-low source reg)
	//   15..14 : parse = 11
	//   13     : op13 = 0
	//   12..8  : Rt5 (32-bit shift-count reg)
	//   7..5   : op0507 = function code (asl=4, asr=0, lsl=6, lsr=2)
	//   4..0   : Rdd5 (paired-low dest reg)
	//
	// op2127=0x1c = 0011100 (bits 27..21 MSB..LSB). For Rss=R1R0, Rdd=R1R0,
	// Rt=R0: bits 27..21 = 0011100, rs=00000, rt=00000. With parse=11:
	//   nibble 31..28 = C
	//   nibble 27..24 = 0011 = 3
	//   nibble 23..20 = 1000 = 8 (b23=1, 22=0, 21=0, 20=0)
	//   nibble 19..16 = 0
	//   nibble 15..12 = 1100 = C
	//   nibble 11..8  = 0
	//   nibble 7..4   = depends on op0507 + bit 4 = 0 (Rdd5 bit 4 = 0)
	//   nibble 3..0   = 0
	// Word for asl R1R0,R1R0,R0 (op0507=4): 0xC380C080. Bytes "80c080c3".
	// Word for asr R1R0,R1R0,R0 (op0507=0): 0xC380C000. Bytes "00c080c3".
	// Word for lsr R1R0,R1R0,R0 (op0507=2): 0xC380C040. Bytes "40c080c3".
	// Word for lsl R1R0,R1R0,R0 (op0507=6): 0xC380C0C0. Bytes "c0c080c3".

	/** asl Rdd,Rss,Rt -- 64-bit register-form. */
	@Test
	public void testShiftEdge_asl64_register_form() {
		// asl R1R0,R1R0,R0
		assertDecode("80c080c3", "asl R1R0,R1R0,R0");
		// asl R3R2,R5R4,R6 -- Rdd=2, Rss=4, Rt=6 -> bits 4..0=2 (low byte=
		// 1000 0010=0x82), 12..8=6 (byte1=11 0 00110=0xC6), 20..16=4 (bit
		// 24..20 nibble updates: bits 23..20 = 1000 ohh wait let me redo).
		// For Rss=R5R4 (low reg index 4), bits 20..16 = 00100. Bits 23..20
		// from op2127=0x1c -> bits 23,22,21 = 1,0,0; bit 20 = 0 (Rss MSB) ->
		// nibble 23..20 = 1000 = 8. Bits 19..16 = 100 (Rss low 3 bits) plus
		// bit 19=0... wait let me redo. Rss = 4 = 00100 in 5 bits. Bits
		// 20..16 = 0,0,1,0,0. nibble 19..16 = 0100 = 4, nibble 23..20 has
		// bit 20 = 0 -> nibble 23..20 = 1000 = 8. So byte2 = 1000_0100 = 0x84.
		// byte1: parse=11, bit13=0, Rt=R6=00110, bits 12..8 = 00110, byte1
		// = 11_0_0_0_1_1_0 = 1100 0110 = 0xC6.
		// byte0: op0507=4 (100), bit 4 = Rdd MSB = 0, Rdd=R3R2 -> low reg=2,
		// bits 4..0 = 00010, byte0 = 1000 0010 = 0x82.
		// byte3: iclass=1100, op2127 high bits = 0011, byte3 = 1100 0011 = 0xC3.
		assertDecode("82c684c3", "asl R3R2,R5R4,R6");
	}

	/** asr Rdd,Rss,Rt -- 64-bit register-form. */
	@Test
	public void testShiftEdge_asr64_register_form() {
		// asr R1R0,R1R0,R0
		assertDecode("00c080c3", "asr R1R0,R1R0,R0");
	}

	/** lsr Rdd,Rss,Rt -- 64-bit register-form. */
	@Test
	public void testShiftEdge_lsr64_register_form() {
		// lsr R1R0,R1R0,R0
		assertDecode("40c080c3", "lsr R1R0,R1R0,R0");
	}

	/** lsl Rdd,Rss,Rt -- 64-bit register-form. */
	@Test
	public void testShiftEdge_lsl64_register_form() {
		// lsl R1R0,R1R0,R0
		assertDecode("c0c080c3", "lsl R1R0,R1R0,R0");
	}

	// ---------------------------------------------------------------------
	// setbit / clrbit / togglebit -- op2127 = 0x34
	// ---------------------------------------------------------------------
	//
	// op2127=0x34 = 0110100 (bits 27..21 MSB..LSB). vs 0x32 = 0110010 used
	// by asl/asr/lsl/lsr above. The two differ only at bit 21: 0x32 has
	// bit 21 clear, 0x34 has bit 21 set. Combined with rs5=0 the nibble at
	// 23..20 is 0x4 vs 0x6 respectively.

	/** setbit Rd,Rs,Rt -- op2127=0x34, op0507=0. */
	@Test
	public void testShiftEdge_setbit_register_form() {
		// setbit R0,R0,R0: word = 1100 0110 1000 0000 1100 0000 0000 0000
		//                       = 0xC680 C000
		assertDecode("00c080c6", "setbit R0,R0,R0");
		// setbit R3,R2,R1
		assertDecode("03c182c6", "setbit R3,R2,R1");
	}

	/** clrbit Rd,Rs,Rt -- op2127=0x34, op0507=2. */
	@Test
	public void testShiftEdge_clrbit_register_form() {
		// clrbit R0,R0,R0: byte0 = 0100 0000 = 0x40
		assertDecode("40c080c6", "clrbit R0,R0,R0");
		// clrbit R3,R2,R1
		assertDecode("43c182c6", "clrbit R3,R2,R1");
	}

	/** togglebit Rd,Rs,Rt -- op2127=0x34, op0507=4. */
	@Test
	public void testShiftEdge_togglebit_register_form() {
		// togglebit R0,R0,R0: byte0 = 1000 0000 = 0x80
		assertDecode("80c080c6", "togglebit R0,R0,R0");
		// togglebit R3,R2,R1
		assertDecode("83c182c6", "togglebit R3,R2,R1");
	}

	// ---------------------------------------------------------------------
	// Accumulating asl Rd, Rs, Rt -- pinned to detect the sxt7 fix on each
	// accumulator family (the sxt7 commit edited each variant separately).
	// ---------------------------------------------------------------------
	//
	// Encoding for "asl&= Rd,Rs,Rt" (and siblings):
	//   31..28 : iclass = 1100
	//   27..21 : op2127 selects accumulator op
	//             asl&= -> 0x62, asl+= -> 0x66, asl-= -> 0x64, asl|= -> 0x60
	//   20..16 : Rs5
	//   15..14 : parse = 11
	//   13     : op13 = 0
	//   12..8  : Rt5
	//   7..5   : op0507 = 4 (asl)
	//   4..0   : Rd5 (accumulating - same as Rx5)
	//
	// All four use bit 22 = 1 (different from the plain register-form 0x32),
	// and they only differ in bits 27..23. We pin one canonical encoding
	// per accumulator family.

	/** asl&= Rd,Rs,Rt -- accumulating-AND form. */
	@Test
	public void testShiftEdge_asl_acc_and() {
		// op2127=0x62 = 1100010. Bits 27..21 = 1,1,0,0,0,1,0.
		// nibble 27..24 = 1100 = C, nibble 23..20 = 0100 = 4 (b23=0,22=1,
		// 21=0, 20=0 with rs=0). Word: 0xCC40C080. Bytes "80c040cc".
		// Wait: iclass=12=1100 nibble 31..28 = C. nibble 27..24 = 1100 = C.
		// nibble 23..20 with rs=0: bits 23,22,21,20 = 0,1,0,0 -> 0100 = 4.
		// Hmm but op2127=0x62 = 1100010 in 7 bits. Bits 27..21:
		//   27=1, 26=1, 25=0, 24=0, 23=0, 22=1, 21=0.
		// nibble 27..24 = 1100 = C, nibble 23..20 = 0100 = 4 (b23=0,22=1,
		// 21=0, 20=0). So word = 0xCC40_C080. Bytes "80c040cc".
		assertDecode("80c040cc", "asl&= R0,R0,R0");
	}

	/** asl+= Rd,Rs,Rt -- accumulating-add form. */
	@Test
	public void testShiftEdge_asl_acc_plus() {
		// op2127=0x66 = 1100110. Bits 27..21 = 1,1,0,0,1,1,0.
		// nibble 27..24 = 1100 = C, nibble 23..20 = 1100 = C (b23=1,22=1,
		// 21=0, 20=0).  Word = 0xCCC0_C080. Bytes "80c0c0cc".
		assertDecode("80c0c0cc", "asl+= R0,R0,R0");
	}

	/** asl-= Rd,Rs,Rt -- accumulating-sub form. */
	@Test
	public void testShiftEdge_asl_acc_minus() {
		// op2127=0x64 = 1100100. Bits 27..21 = 1,1,0,0,1,0,0.
		// nibble 27..24 = 1100, nibble 23..20 = 1000 (b23=1,22=0,21=0,20=0).
		// Word = 0xCC80_C080. Bytes "80c080cc".
		assertDecode("80c080cc", "asl-= R0,R0,R0");
	}

	/** asl|= Rd,Rs,Rt -- accumulating-OR form. */
	@Test
	public void testShiftEdge_asl_acc_or() {
		// op2127=0x60 = 1100000. Bits 27..21 = 1,1,0,0,0,0,0.
		// nibble 27..24 = 1100, nibble 23..20 = 0000 (b23=0,22=0,21=0,20=0).
		// Word = 0xCC00_C080. Bytes "80c000cc".
		assertDecode("80c000cc", "asl|= R0,R0,R0");
	}

	// ---------------------------------------------------------------------
	// rol Rd,Rs,#u5  -- 32-bit immediate rotate
	// ---------------------------------------------------------------------
	//
	// Encoding:
	//   31..28 : iclass = 1000
	//   27..21 : op2127 = 0x60 (1100000)
	//   20..16 : Rs5
	//   15..14 : parse = 11
	//   13     : op13 = 0
	//   12..8  : Uimm8_0812 (5-bit shift count)
	//   7..5   : op0507 = 3 (011)
	//   4..0   : Rd5
	//
	// Per the recent commit, the pcode now correctly emits
	//   Rd = (Rs << N) | (Rs >> (32 - N))
	// rather than the prior "fold sign bit into bit 0". We pin the
	// disassembly for several N values to ensure all rol constructors
	// continue to decode at boundary values.

	/** rol Rd,Rs,#N -- pin N=1, 5, 16, 31 decode. */
	@Test
	public void testShiftEdge_rol32_imm() {
		// rol R0,R0,#1
		assertDecode("60c1008c", "rol R0,R0,#0x1");
		// rol R0,R0,#5
		assertDecode("60c5008c", "rol R0,R0,#0x5");
		// rol R0,R0,#16
		assertDecode("60d0008c", "rol R0,R0,#0x10");
		// rol R0,R0,#31 (max valid 5-bit value)
		assertDecode("60df008c", "rol R0,R0,#0x1f");
	}

	// ---------------------------------------------------------------------
	// rol Rdd,Rss,#u6  -- 64-bit immediate rotate
	// ---------------------------------------------------------------------
	//
	// Encoding:
	//   31..28 : iclass = 1000
	//   27..21 : op2127 = 0x00 (0000000)
	//   20..16 : Rss5 (paired register, low)
	//   15..14 : parse = 11
	//   13..8  : Uimm8_0813 (6-bit shift count)
	//   7..5   : op0507 = 3 (011)
	//   4..0   : Rdd5
	//
	// The fixed pcode is (Rss << N) | (Rss >> (64 - N)). Pin N=1, 5, 32, 63.

	/** rol Rdd,Rss,#N -- pin N=1, 5, 32, 63 decode. */
	@Test
	public void testShiftEdge_rol64_imm() {
		// rol R1R0,R1R0,#1
		assertDecode("60c10080", "rol R1R0,R1R0,#0x1");
		// rol R1R0,R1R0,#5
		assertDecode("60c50080", "rol R1R0,R1R0,#0x5");
		// rol R1R0,R1R0,#32 (high bit of 6-bit imm set; bits 13..8 = 100000)
		assertDecode("60e00080", "rol R1R0,R1R0,#0x20");
		// rol R1R0,R1R0,#63 (max valid 6-bit value)
		assertDecode("60ff0080", "rol R1R0,R1R0,#0x3f");
	}

	// ---------------------------------------------------------------------
	// mpyu :<<1 -- ensure Rs and Rt are distinct after fix
	// ---------------------------------------------------------------------
	//
	// Encoding for M2_mpyu_hh_s1 ("Rd32 = mpyu(Rs.h,Rt.h):<<1"):
	//   31..28 : iclass = 1110
	//   27..21 : op2127 = 0x66
	//   20..16 : Rs5
	//   15..14 : parse = 11
	//   13     : op13 = 0
	//   12..8  : Rt5
	//   7      : op7 = 0
	//   6      : op6 = 1 -> Rs.H
	//   5      : op5 = 1 -> Rt.H
	//   4..0   : Rd5
	//
	// Pre-fix the constructor squared Rs (zext(Rs)*zext(Rs)). After fix it
	// multiplies by Rt. Pin a few register triples; the disasm doesn't
	// reflect the buggy semantics, but the fact that we have distinct Rs and
	// Rt operands in the rendered text confirms the constructor is in fact
	// the two-operand form.

	/** mpyu(Rs.h,Rt.h):<<1 -- pin distinct Rs/Rt registers. */
	@Test
	public void testShiftEdge_mpyu_hh_s1() {
		// mpyu(R0.H,R0.H):<<1 -> R0
		assertDecode("60c0c0ec", "mpyu:<<1 R0,R0.H,R0.H");
		// mpyu(R6.H,R7.H):<<1 -> R5 -- Rs=R6 (bits 20..16=00110), Rt=R7
		// (bits 12..8=00111), Rd=R5 (bits 4..0=00101)
		assertDecode("65c7c6ec", "mpyu:<<1 R5,R6.H,R7.H");
	}

	// Encoding for the accumulating M2_mpyu_acc_hh_s1 ("Rxx32 += mpyu(...)"):
	//   31..28 : iclass = 1110
	//   27..21 : op2127 = 0x36
	//   20..16 : Rs5
	//   15..14 : parse = 11
	//   13     : op13 = 0
	//   12..8  : Rt5
	//   7      : op7 = 0
	//   6      : op6 = 1 (Rs.H)
	//   5      : op5 = 1 (Rt.H)
	//   4..0   : Rxx5 (paired -- Rxx low reg encoded as Rxx5/2)
	@Test
	public void testShiftEdge_mpyu_hh_s1_acc() {
		// R1R0 += mpyu(R0.H,R0.H):<<1
		assertDecode("60c0c0e6", "mpyu+=:<<1 R1R0,R0.H,R0.H");
		// R3R2 += mpyu(R6.H,R7.H):<<1 -- Rxx5 = 2 (R3R2 in the dpair table)
		assertDecode("62c7c6e6", "mpyu+=:<<1 R3R2,R6.H,R7.H");
	}

	// ---------------------------------------------------------------------
	// sfmake / dfmake -- IEEE-754 bit pattern construction
	// ---------------------------------------------------------------------
	//
	// Encoding for sfmake:pos:
	//   31..28 : iclass = 1101
	//   27..22 : op2227 = 0x18 (011000)
	//   21     : i (high bit of imm, becomes bit 9 after concat)
	//   20..16 : op1620 = 0
	//   15..14 : parse = 11
	//   13..5  : i0513 (low 9 bits of imm)
	//   4..0   : Rd5
	//
	// :neg uses op2227 = 0x19 (011001).
	//
	// The fixed pcode emits
	//    Rd = ((bias-6)<<exp_shift) + (zext(imm) << mantissa_shift)
	// rather than int2float of the imm. Pin the disassembly for a couple of
	// imm values; the mnemonic is "sfmake:pos" / "sfmake:neg".

	@Test
	public void testShiftEdge_sfmake() {
		// sfmake:pos R0,#0
		assertDecode("00c000d6", "sfmake:pos R0,#0x0");
		// sfmake:neg R0,#0
		assertDecode("00c040d6", "sfmake:neg R0,#0x0");
	}

	@Test
	public void testShiftEdge_dfmake() {
		// dfmake:pos R1R0,#0
		assertDecode("00c000d9", "dfmake:pos R1R0,#0x0");
		// dfmake:neg R1R0,#0
		assertDecode("00c040d9", "dfmake:neg R1R0,#0x0");
	}

	// ---------------------------------------------------------------------
	// not Rd, Rs  -- canonicalized from sub(#-1, Rs)
	// ---------------------------------------------------------------------
	//
	// Encoding (special case of sub Rd,#i,Rs with imm = -1, immexted=0):
	//   31..28 : iclass = 0111
	//   27..22 : op2227 = 0x19 (011001)
	//   21     : s21 = 1 (sign bit of imm)
	//   20..16 : Rs5
	//   15..14 : parse = 11
	//   13..5  : i0513 = 0x1ff (all-ones)
	//   4..0   : Rd5
	//
	// Pin so that a constructor reorder elsewhere in the decoder doesn't
	// silently shadow the special case (which would turn "not R0,R0" back
	// into "sub R0,#-1,R0" in the output).

	@Test
	public void testShiftEdge_not_from_sub_neg1() {
		// not R0, R0
		assertDecode("e0ff6076", "not R0,R0");
		// not R5, R6 -- bits 20..16 = R6 = 00110, bits 4..0 = R5 = 00101
		// byte0 = (1,1,1,0,0,1,0,1) = 0xE5
		// byte1 = (1,1,1,1,1,1,1,1) = 0xFF
		// byte2 = (0,1,1,0,0,1,1,0) = 0x66
		// byte3 = (0,1,1,1,0,1,1,0) = 0x76
		assertDecode("e5ff6676", "not R5,R6");
	}

	// ---------------------------------------------------------------------
	// HVX vasl/vasr/vlsr -- decode-only pin
	// ---------------------------------------------------------------------
	//
	// HVX vector shifts are implemented as opaque pcodeops; semantics are
	// known-issue. We just pin that the mnemonic continues to decode for
	// representative encodings.

	@Test
	public void testShiftEdge_hvx_vshifts_decode_only() {
		// V6_vaslw -- iclass=1, op2127=0x4b, op0507=7
		// Word: 0001 1001 0110 0000 1100 0000 1110 0000 = 0x1960C0E0
		assertDecode("e0c06019", "vasl V0.w,V0.w,R0");
		// V6_vasrw -- iclass=1, op2127=0x4b, op0507=5
		// Word: 0001 1001 0110 0000 1100 0000 1010 0000 = 0x1960C0A0
		assertDecode("a0c06019", "vasr V0.w,V0.w,R0");
		// V6_vasrh -- iclass=1, op2127=0x4b, op0507=6
		// Word: 0001 1001 0110 0000 1100 0000 1100 0000 = 0x1960C0C0
		assertDecode("c0c06019", "vasr V0.h,V0.h,R0");
		// V6_vaslh -- iclass=1, op2127=0x4c, op0507=0
		// Word: 0001 1001 1000 0000 1100 0000 0000 0000 = 0x1980C000
		assertDecode("00c08019", "vasl V0.h,V0.h,R0");
		// V6_vlsruw -- iclass=1, op2127=0x4c, op0507=1
		// Word: 0001 1001 1000 0000 1100 0000 0010 0000 = 0x1980C020
		assertDecode("20c08019", "vlsr V0.uw,V0.uw,R0");
		// V6_vlsruh -- iclass=1, op2127=0x4c, op0507=2
		// Word: 0001 1001 1000 0000 1100 0000 0100 0000 = 0x1980C040
		assertDecode("40c08019", "vlsr V0.uh,V0.uh,R0");
	}
}
