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
 * Regression-pin coverage test for recently added decoder stubs.
 *
 * <p>Each assertion records, as a baseline, the disassembly text produced by
 * the current Hexagon SLEIGH spec for a representative encoding of one stub
 * family. The intent is purely to detect silent behavioral regressions
 * (e.g. a future edit that accidentally removes or shadows a decoder
 * constructor): if the decoded mnemonic changes for any pinned encoding,
 * the corresponding assertion will fail and force a deliberate review.
 *
 * <p>Encodings are taken from real LLVM-MC sample bytes for V69/V73 HVX and
 * system instructions; the expected text is what the spec currently emits
 * (which for some families is a deliberately simplified or stubbed form).
 *
 * <p>Unlike {@link HexagonAssemblyTest} this class does <em>not</em> exercise
 * the assembler -- many of the stubbed mnemonics use punctuation
 * (e.g. {@code |=}, {@code &=}, {@code ^=}, {@code +=}, {@code :rnd:sat})
 * that does not necessarily round-trip through the assembler grammar.
 * We only assert byte-to-text disassembly via {@link #disassemble}.
 */
public class HexagonStubCoverageTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Hexagon:LE:32:default");
	}

	/**
	 * Decode a single 4-byte little-endian Hexagon word and assert the
	 * disassembly text (trimmed) matches {@code expected}.
	 *
	 * @param hexBytes 8 hex chars representing the 4 bytes in little-endian
	 *                 order as they appear in memory (the same form that the
	 *                 LLVM-MC corpus prints)
	 * @param expected the expected disassembly, without trailing whitespace
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
		// Default context for a single-instruction packet; the parse-bits
		// in the encoding itself mark end-of-packet.
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

	@Test
	public void testStubCoverage_HVX_vmpy_integer() {
		// V6_vmpyhus
		assertDecode("40c0201c", "vmpy V1V0.w,V0.h,V0.uh");
		// V6_vmpyhus_acc
		assertDecode("20e0201c", "vmpy+= V1V0.w,V0.h,V0.uh");
		// V6_vmpyhv
		assertDecode("e0c0001c", "vmpy V1V0.w,V0.h,V0.h");
		// V6_vmpyhv_acc
		assertDecode("e0e0001c", "vmpy+= V1V0.w,V0.h,V0.h");
		// V6_vmpyhvsrs
		assertDecode("20c0201c", "vmpy:<<1:rnd:sat V0.h,V0.h,V0.h");
	}

	@Test
	public void testStubCoverage_HVX_vrmpy_rtt() {
		// V6_vrmpybub_rtt
		assertDecode("a0c0c019", "vrmpy V1V0.w,V0.b,R1R0.ub");
		// V6_vrmpybub_rtt_acc
		assertDecode("00e0a019", "vrmpy+= V1V0.w,V0.b,R1R0.ub");
		// V6_vrmpyub_rtt
		assertDecode("80c0c019", "vrmpy V1V0.uw,V0.ub,R1R0.ub");
		// V6_vrmpyub_rtt_acc
		assertDecode("e0e0a019", "vrmpy+= V1V0.uw,V0.ub,R1R0.ub");
	}

	@Test
	public void testStubCoverage_HVX_hf_sf_arith() {
		// V6_vdmpy_sf_hf_acc
		assertDecode("60e0401c", "vdmpy+= V0.sf,V0.hf,V0.hf");
		// V6_vmpy_hf_hf_acc
		assertDecode("40e0401c", "vmpy+= V0.hf,V0.hf,V0.hf");
		// V6_vmpy_sf_hf_acc
		assertDecode("20e0401c", "vmpy+= V1V0.sf,V0.hf,V0.hf");
		// V6_vfmax_hf
		assertDecode("40e0601c", "vfmax V0.hf,V0.hf,V0.hf");
		// V6_vfmax_sf
		assertDecode("60e0601c", "vfmax V0.sf,V0.sf,V0.sf");
		// V6_vfmin_hf
		assertDecode("00e0601c", "vfmin V0.hf,V0.hf,V0.hf");
		// V6_vfmin_sf
		assertDecode("20e0601c", "vfmin V0.sf,V0.sf,V0.sf");
	}

	@Test
	public void testStubCoverage_HVX_bf_arith() {
		// V6_vadd_sf_bf
		assertDecode("c0e0401d", "vadd V1V0.sf,V0.bf,V0.bf");
		// V6_vsub_sf_bf
		assertDecode("a0e0401d", "vsub V1V0.sf,V0.bf,V0.bf");
		// V6_vmpy_sf_bf
		assertDecode("80e0401d", "vmpy V1V0.sf,V0.bf,V0.bf");
		// V6_vmpy_sf_bf_acc
		assertDecode("00e0001d", "vmpy+= V1V0.sf,V0.bf,V0.bf");
		// V6_vmax_bf
		assertDecode("e0e0401d", "vmax V0.bf,V0.bf,V0.bf");
		// V6_vmin_bf
		assertDecode("00e0401d", "vmin V0.bf,V0.bf,V0.bf");
		// V6_vcvt_bf_sf
		assertDecode("60e0401d", "vcvt V0.bf,V0.sf,V0.sf");
	}

	@Test
	public void testStubCoverage_HVX_bf_compare() {
		// V6_vgtbf
		assertDecode("78e0801c", "vcmp.gt Q0,V0.bf,V0.bf");
		// V6_vgtbf_and
		assertDecode("d0e0801c", "vcmp.gt&= Q0,V0.bf,V0.bf");
		// V6_vgtbf_or
		assertDecode("38e0801c", "vcmp.gt|= Q0,V0.bf,V0.bf");
		// V6_vgtbf_xor
		assertDecode("f0e0801c", "vcmp.gt^= Q0,V0.bf,V0.bf");
	}

	@Test
	public void testStubCoverage_HVX_hf_sf_eq_compare() {
		// V6_veqhf_and
		assertDecode("1ce0801c", "vcmp.eq&= Q0,V0.hf,V0.hf");
		// V6_veqhf_or
		assertDecode("5ce0801c", "vcmp.eq|= Q0,V0.hf,V0.hf");
		// V6_veqhf_xor
		assertDecode("9ce0801c", "vcmp.eq^= Q0,V0.hf,V0.hf");
		// V6_veqsf_and
		assertDecode("0ce0801c", "vcmp.eq&= Q0,V0.sf,V0.sf");
		// V6_veqsf_or
		assertDecode("4ce0801c", "vcmp.eq|= Q0,V0.sf,V0.sf");
		// V6_veqsf_xor
		assertDecode("8ce0801c", "vcmp.eq^= Q0,V0.sf,V0.sf");
	}

	@Test
	public void testStubCoverage_HVX_f8_and_cvt2() {
		// V6_vcvt2_b_hf
		assertDecode("c0e0c01a", "vcvt2 V0.b,V0.hf,V0.hf");
		// V6_vcvt2_ub_hf
		assertDecode("e0e0c01a", "vcvt2 V0.ub,V0.hf,V0.hf");
		// V6_vfmax_f8
		assertDecode("a0e0601c", "vfmax V0.f8,V0.f8,V0.f8");
		// V6_vfmin_f8
		assertDecode("80e0601c", "vfmin V0.f8,V0.f8,V0.f8");
		// V6_vabs_f8 -- previously broken (typo bug), now decoded
		assertDecode("c0e0661c", "vabs V0.f8,V0.f8");
		// V6_vfneg_f8 -- previously broken (typo bug), now decoded
		assertDecode("e0e0661c", "vfneg V0.f8,V0.f8");
	}

	@Test
	public void testStubCoverage_HVX_vhist() {
		// V6_vhist -- previously broken (typo bug), now decoded
		assertDecode("80e0001e", "vhist");
		// V6_vhistq -- previously broken (typo bug), now decoded
		assertDecode("80e0021e", "vhist Q0");
	}

	@Test
	public void testStubCoverage_HVX_qfext_and_align() {
		// V6_get_qfext
		assertDecode("e0c0c019", "vgetqfext V0,V0.x,R0");
		// V6_get_qfext_oracc
		assertDecode("c0c0c019", "vgetqfext|= V0,V0.x,R0");
		// V6_set_qfext
		assertDecode("60c0c019", "vsetqfext V0.x,V0,R0");
		// V6_valign4
		assertDecode("a0c00018", "valign4 V0,V0,V0,R0");
	}

	@Test
	public void testStubCoverage_scalar_and_pair() {
		// A6_vminub_RdP
		assertDecode("00c0e0ea", "vminub R1R0,P0,R1R0,R1R0");
		// L2_loadw_aq
		assertDecode("00c80092", "memw_aq R0,R0");
		// L6_memcpy
		assertDecode("40c00092", "memcpy R0,R0,M0");
		// S6_vtrunehb_ppp -- previously broken (typo bug), now decoded
		assertDecode("60c080c1", "vtrunehb R1R0,R1R0,R1R0");
		// S6_vtrunohb_ppp -- previously broken (typo bug), now decoded
		assertDecode("a0c080c1", "vtrunohb R1R0,R1R0,R1R0");
	}

	@Test
	public void testStubCoverage_system_and_dma() {
		// Y2_icdataw
		assertDecode("00e0c055", "icdataw R0,R0");
		// Y2_tlbpp
		assertDecode("00c0606c", "tlbp R0,R1R0");
		// Y6_dmlink
		assertDecode("40c000a6", "dmlink R0,R0");
		// Y6_dmpause
		assertDecode("60c000a8", "dmpause R0");
		// Y6_dmpoll
		assertDecode("40c000a8", "dmpoll R0");
		// Y6_dmresume
		assertDecode("80c000a6", "dmresume R0");
		// Y6_dmstart
		assertDecode("20c000a6", "dmstart R0");
		// Y6_dmwait
		assertDecode("20c000a8", "dmwait R0");
	}
}
