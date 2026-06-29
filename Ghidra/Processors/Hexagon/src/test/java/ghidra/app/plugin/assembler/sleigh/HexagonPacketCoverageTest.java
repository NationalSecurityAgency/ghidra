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

import java.math.BigInteger;

import org.junit.Test;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;

/**
 * Packet-context regression-pin coverage test for the Hexagon SLEIGH spec.
 *
 * <p>Many Hexagon instruction families (NV-cmp-jumps, NV-stores, HVX
 * V6_vS32b_new_*, dealloc_return:new, ...) only decode in the context of a
 * non-zero packet position with prior-slot register tracking. The mainline
 * canonical-byte oracle test (compare_3way.json) decodes each instruction
 * standalone and so reports these families as DECODE_FAILED -- but that is a
 * methodology artifact, not a real spec gap.
 *
 * <p>This class constructs the required {@code packetOffset} /
 * {@code packetBits} context by hand and disassembles the second-or-later
 * instruction in the packet, asserting the resulting mnemonic and operand
 * text. The pattern follows
 * {@code HexagonAssemblyTest#testAssemble_memw_mSP_n0x4_R0new}, which already
 * exercises packet-context for {@code R0.new} stores.
 *
 * <p>Each assertion pins the current spec output for one representative
 * encoding of one packet-context-dependent family; if the constructor
 * disappears or its rendering changes the assertion fires.
 *
 * <p>The byte encodings below are LLVM canonical primaries (one per
 * {@code def : HInst<>}) modified only to:
 * <ul>
 * <li>set the 3-bit {@code Ns8} / {@code Os8} / {@code Nt8} new-register field
 *     to encoded value {@code 0b010} (= 2). With
 *     {@code nregSlot = packetOffset - xreg - (field >> 1)} and
 *     {@code packetOffset == 1, xreg == 0}, this resolves to
 *     {@code nregSlot = 0} (i.e. the writer was at slot 0);
 * <li>leave parse bits at the canonical {@code 11} (end-of-packet) since the
 *     reader instruction is the last in the packet.
 * </ul>
 *
 * <p>The 3-bit new-value field lives at:
 * <ul>
 * <li>bits 16..18 (Ns8) for NV-cmp-jumps; setting bit 17 of the word lifts
 *     it from {@code 000} to {@code 010};
 * <li>bits 8..10 (Nt8) for NV-stores; setting bit 9;
 * <li>bits 0..2 (Os8) for HVX V6_vS32b_new; setting bit 1.
 * </ul>
 */
public class HexagonPacketCoverageTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Hexagon:LE:32:default");
	}

	/**
	 * Build a context byte string with the given {@code packetOffset} and
	 * {@code packetBits} sub-register values. Mirrors the helper in
	 * {@link HexagonAssemblyTest}.
	 *
	 * @param packetOffset slot index within the packet (0..3)
	 * @param packetBits   raw value of the {@code packetBits} sub-register; the
	 *                     high 2 bits are {@code parse1} (slot-0 parse), the
	 *                     next 2 are {@code parse2} (slot-1 parse), then 5-bit
	 *                     {@code nreg0}, {@code nreg1}, {@code nreg2}, etc.
	 */
	private String makeCtx(int packetOffset, long packetBits) {
		RegisterValue ctxVal = new RegisterValue(lang.getContextBaseRegister());
		ctxVal = ctxVal.assign(lang.getRegister("packetOffset"),
			BigInteger.valueOf(packetOffset));
		ctxVal = ctxVal.assign(lang.getRegister("packetBits"),
			BigInteger.valueOf(packetBits));
		return AssemblyPatternBlock.fromRegisterValue(ctxVal).fillMask().toString();
	}

	/**
	 * Decode a single 4-byte little-endian Hexagon word at packet position
	 * {@code packetOffset} with the given prior-slot {@code packetBits} and
	 * assert the disassembly text.
	 *
	 * @param hexBytes      8 hex chars representing the 4 bytes in
	 *                      little-endian order as they appear in memory
	 * @param packetOffset  slot index within the packet (0..3)
	 * @param packetBits    raw {@code packetBits} sub-register value
	 * @param expected      expected disassembly text, trimmed
	 */
	protected void assertPacketDecode(String hexBytes, int packetOffset, long packetBits,
			String expected) {
		if (hexBytes.length() != 8) {
			throw new IllegalArgumentException(
				"expected 4-byte hex word (8 chars), got: " + hexBytes);
		}
		byte[] bytes = new byte[4];
		for (int i = 0; i < 4; i++) {
			bytes[i] = (byte) Integer.parseInt(hexBytes.substring(i * 2, i * 2 + 2), 16);
		}
		String ctxStr = makeCtx(packetOffset, packetBits);
		byte[] ctx = AssemblyPatternBlock.fromString(ctxStr).fillMask().getVals();
		PseudoInstruction pi;
		try {
			pi = disassemble(DEFAULT_ADDR, bytes, ctx);
		}
		catch (Exception e) {
			throw new AssertionError(
				"disassembly threw for bytes " + hexBytes + " ctx=" + ctxStr +
					" (expected: " + expected + ")",
				e);
		}
		String actual = pi.toString().trim();
		assertEquals("bytes " + hexBytes + " offset=" + packetOffset + " packetBits=" +
			Long.toHexString(packetBits), expected, actual);
	}

	/**
	 * Common context for "slot 1 reads slot 0's writer of R0":
	 * <ul>
	 * <li>parse1 = 01 (slot 0 was a normal middle instruction)
	 * <li>nreg0 = 0 (slot 0 wrote to R0; encoded directly into the 5-bit
	 *               {@code nreg0} sub-field of {@code packetBits})
	 * </ul>
	 * packetBits = parse1 in high 2 bits = 0b01_00_00000_00000_00000_00000_00000_000
	 *            = 0x40000000.
	 */
	private static final long PB_S1_NREG0_R0 = 0x40000000L;

	// ---------------------------------------------------------------------
	// NV cmp-jump families (J4_cmp{eq,gt,gtu}{,i,n1}_{t,f}_jumpnv_{nt,t})
	// ---------------------------------------------------------------------
	//
	// Encoding layout:
	//   31..28 : iclass = 0010
	//   27..22 : opcode bits selecting cmp.{eq,gt,gtu} and t/f
	//   18..16 : Ns8 (3-bit new-value source)
	//   15..14 : parse bits
	//   13     : taken hint (1=jump:t, 0=jump:nt)
	//   12..8  : Rt32 (or U5 immediate)
	//   7..1   : i7 immediate
	//
	// Canonical sets Ns8 = 000; we set bit 17 -> Ns8 = 010. In LE memory
	// order byte2 (bits 16..23) gets bit 1 set: byte2 |= 0x02.
	//
	// Mainline display order:
	//   "jump.if:<t|nt> [!]cmp.<eq|gt|gtu>(R0.new,<rhs>),<target>"
	// Jump target = inst_start - 4*packetOffset + sext(imm)*4. With
	// DEFAULT_ADDR = 0x40000000, packetOffset=1, imm=0: 0x40000000 - 4 = 0x3ffffffc.

	/** Pin the J4_cmpeq*_*_jumpnv_* families. */
	@Test
	public void testPacketCoverage_NVCmpJump_eq() {
		// J4_cmpeq_t_jumpnv_t   (canonical 00e00020)
		assertPacketDecode("00e00220", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.eq(R0.new,R0),0x3ffffffc");
		// J4_cmpeq_t_jumpnv_nt  (canonical 00c00020)
		assertPacketDecode("00c00220", 1, PB_S1_NREG0_R0,
			"jump.if:nt cmp.eq(R0.new,R0),0x3ffffffc");
		// J4_cmpeq_f_jumpnv_t   (canonical 00e04020)
		assertPacketDecode("00e04220", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.eq(R0.new,R0),0x3ffffffc");
		// J4_cmpeqi_t_jumpnv_t  (canonical 00e00024)
		assertPacketDecode("00e00224", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.eq(R0.new,#0x0),0x3ffffffc");
		// J4_cmpeqi_f_jumpnv_t  (canonical 00e04024)
		assertPacketDecode("00e04224", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.eq(R0.new,#0x0),0x3ffffffc");
		// J4_cmpeqn1_t_jumpnv_t (canonical 00e00026) -- #-1 literal renders as "#-1"
		assertPacketDecode("00e00226", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.eq(R0.new,#-1),0x3ffffffc");
		// J4_cmpeqn1_f_jumpnv_t (canonical 00e04026)
		assertPacketDecode("00e04226", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.eq(R0.new,#-1),0x3ffffffc");
	}

	/** Pin the J4_cmpgt*_*_jumpnv_* families. */
	@Test
	public void testPacketCoverage_NVCmpJump_gt() {
		// J4_cmpgt_t_jumpnv_t   (canonical 00e08020)
		assertPacketDecode("00e08220", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.gt(R0.new,R0),0x3ffffffc");
		// J4_cmpgt_t_jumpnv_nt
		assertPacketDecode("00c08220", 1, PB_S1_NREG0_R0,
			"jump.if:nt cmp.gt(R0.new,R0),0x3ffffffc");
		// J4_cmpgt_f_jumpnv_t   (canonical 00e0c020)
		assertPacketDecode("00e0c220", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.gt(R0.new,R0),0x3ffffffc");
		// J4_cmpgti_t_jumpnv_t  (canonical 00e08024)
		assertPacketDecode("00e08224", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.gt(R0.new,#0x0),0x3ffffffc");
		// J4_cmpgtn1_t_jumpnv_t (canonical 00e08026) -- #-1 literal
		assertPacketDecode("00e08226", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.gt(R0.new,#-1),0x3ffffffc");
	}

	/** Pin the J4_cmpgtu*_*_jumpnv_* families. */
	@Test
	public void testPacketCoverage_NVCmpJump_gtu() {
		// J4_cmpgtu_t_jumpnv_t  (canonical 00e00021)
		assertPacketDecode("00e00221", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.gtu(R0.new,R0),0x3ffffffc");
		// J4_cmpgtu_t_jumpnv_nt (canonical 00c00021)
		assertPacketDecode("00c00221", 1, PB_S1_NREG0_R0,
			"jump.if:nt cmp.gtu(R0.new,R0),0x3ffffffc");
		// J4_cmpgtu_f_jumpnv_t  (canonical 00e04021)
		assertPacketDecode("00e04221", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.gtu(R0.new,R0),0x3ffffffc");
		// J4_cmpgtui_t_jumpnv_t (canonical 00e00025)
		assertPacketDecode("00e00225", 1, PB_S1_NREG0_R0,
			"jump.if:t cmp.gtu(R0.new,#0x0),0x3ffffffc");
		// J4_cmpgtui_f_jumpnv_t (canonical 00e04025)
		assertPacketDecode("00e04225", 1, PB_S1_NREG0_R0,
			"jump.if:t !cmp.gtu(R0.new,#0x0),0x3ffffffc");
	}

	// ---------------------------------------------------------------------
	// NV-store families (S2_storer{b,h,i}new_*, S4_storer{b,h,i}new_*)
	// ---------------------------------------------------------------------
	//
	// Encoding layout (S2_storerXnew_io, _pi, _pci, _rr):
	//   31..28 : iclass = 1010 (0xa) for S2_*; 0011_1011 etc. for S4_*
	//   27..22 : subclass selecting size & addressing mode
	//   21..16 : Rs32 (base reg)
	//   15..14 : parse bits
	//   13..11 : 000
	//   10..8  : Nt8 (3-bit new-value source)
	//    7..3  : Ii immediate
	//
	// Canonical Nt8 = 000; we set bit 9 of word -> Nt8 = 010. In LE memory
	// order, byte1 |= 0x02. With imm=0 the rendering omits the offset:
	//   "memb (R0),R0.new"  not "memb (R0+#0x0),R0.new".

	/** Pin S2_storerbnew_io / S2_storerbnew_pi / S4_storerbnew_rr. */
	@Test
	public void testPacketCoverage_NVStore_byte() {
		// S2_storerbnew_io  (canonical 00c0a0a1)  imm=0 -> "(R0)" only
		assertPacketDecode("00c2a0a1", 1, PB_S1_NREG0_R0,
			"memb (R0),R0.new");
		// S2_storerbnew_pi  (canonical 00c0a0ab)
		assertPacketDecode("00c2a0ab", 1, PB_S1_NREG0_R0,
			"memb (R0++#0x0),R0.new");
		// S4_storerbnew_rr  (canonical 00c0a03b)
		// Note: this constructor uses Nreg0002 (Nt8 at bits 0..2), NOT Nreg0810,
		// so we set bit 1 (byte0 |= 0x02) rather than bit 9.
		// With shift = 0 the rendering omits the "<<#0x0" suffix.
		assertPacketDecode("02c0a03b", 1, PB_S1_NREG0_R0,
			"memb (R0+R0),R0.new");
	}

	/** Pin S2_storerhnew_io / S2_storerhnew_pi / S4_storerhnew_rr. */
	@Test
	public void testPacketCoverage_NVStore_half() {
		// S2_storerhnew_io  (canonical 00c8a0a1)
		assertPacketDecode("00caa0a1", 1, PB_S1_NREG0_R0,
			"memh (R0),R0.new");
		// S2_storerhnew_pi  (canonical 00c8a0ab)
		assertPacketDecode("00caa0ab", 1, PB_S1_NREG0_R0,
			"memh (R0++#0x0),R0.new");
		// S4_storerhnew_rr  (canonical 08c0a03b) -- Nreg0002 -> set bit 1
		assertPacketDecode("0ac0a03b", 1, PB_S1_NREG0_R0,
			"memh (R0+R0),R0.new");
	}

	/** Pin S2_storerinew_io / S2_storerinew_pi / S4_storerinew_rr. */
	@Test
	public void testPacketCoverage_NVStore_word() {
		// S2_storerinew_io  (canonical 00d0a0a1)
		assertPacketDecode("00d2a0a1", 1, PB_S1_NREG0_R0,
			"memw (R0),R0.new");
		// S2_storerinew_pi  (canonical 00d0a0ab)
		assertPacketDecode("00d2a0ab", 1, PB_S1_NREG0_R0,
			"memw (R0++#0x0),R0.new");
		// S4_storerinew_rr  (canonical 10c0a03b) -- Nreg0002 -> set bit 1
		assertPacketDecode("12c0a03b", 1, PB_S1_NREG0_R0,
			"memw (R0+R0),R0.new");
	}

	// ---------------------------------------------------------------------
	// HVX V6_vS32b_new_* (vector NV stores)
	// ---------------------------------------------------------------------
	//
	// Encoding for V6_vS32b_new_ai (canonical 20c02028 -> word 0x2820c020):
	//   31..28 : iclass = 0010
	//   27..21 : 1010_000  (vS32b family subclass)
	//   ...
	//   2..0   : Os8 (3-bit new vector reg, via VNreg0002 sub-constructor)
	//
	// Canonical Os8 = 0; we set bit 1 of word -> Os8 = 010.
	// In LE memory order, byte0 |= 0x02.

	// ---------------------------------------------------------------------
	// Predicated NV-store families (S4_pstorer{b,h,i}new{t,f}{,new}_*)
	// ---------------------------------------------------------------------
	//
	// Encoding for S4_pstorerbnewt_io (predicated NV store):
	//   31..28 : iclass = 0100 (0x4)  [for the io form]
	//   ...
	//   10..8  : Nt8 (Nreg0810)
	// We set Nt8 = 010 -> bit 9 of word, byte1 |= 0x02.
	//
	// For S4_pstorerXnewtnew_rr / S4_pstorerXnewfnew_rr (P.new + register
	// indexed) the canonical bytes from JSON include the
	// {@code <<#0x0} shift = 0; we set bit 1 (Nreg0002) on those.

	/** Pin S4 predicated NV-store family. */
	@Test
	public void testPacketCoverage_PStoreNew_pred() {
		// S4_pstorerbnewt_rr  (canonical 00c0a034) -- if (P0) memb(...) = R0.new
		// Uses Nreg0002, set bit 1
		assertPacketDecode("02c0a034", 1, PB_S1_NREG0_R0,
			"memb.if(P0) (R0+R0),R0.new");
		// S4_pstorerbnewf_rr  (canonical 00c0a035) -- if (!P0)
		assertPacketDecode("02c0a035", 1, PB_S1_NREG0_R0,
			"memb.if(!P0) (R0+R0),R0.new");
		// S4_pstorerinewtnew_rr (canonical 10c0a036) -- if (P0.new)
		assertPacketDecode("12c0a036", 1, PB_S1_NREG0_R0,
			"memw.if(P0.new) (R0+R0),R0.new");
		// S4_pstorerhnewfnew_rr (canonical 08c0a037) -- if (!P0.new)
		assertPacketDecode("0ac0a037", 1, PB_S1_NREG0_R0,
			"memh.if(!P0.new) (R0+R0),R0.new");
	}

	// ---------------------------------------------------------------------
	// L4_return_*new_p* (dealloc_return predicated by P.new)
	// ---------------------------------------------------------------------
	//
	// Encoding for "if (Ps4.new) dealloc_return:t" (LLVM L4_return_tnew_pt):
	//   31..28 : 1001          (iclass=9)
	//   27..21 : 0110000        (op2127=0x30)
	//   20..16 : 11110          (op1620=0x1e -- fixed pattern, NOT a register
	//                            field; this distinguishes the form from
	//                            "Rdd32 = dealloc_return(Rs32)" which puts an
	//                            rs5 register here)
	//   15..14 : PP             (parse bits)
	//   13     : 0/1 = jump:t/jump:nt (DRTaken12)
	//   12..11 : 11             (selects "if (..new)" path)
	//   10..9  : 10/01 selecting P.new and/or "!"
	//    7..1  : (zero in our test)
	//    4..0  : 11110          (op0007=0x1e fixed)
	//
	// Note: LLVM canonical encoding sets the 5 bits at op1620 and the low 5
	// bits of op0007 to 0 (these encode placeholder operands like Rs32 and
	// Rdd32 in LLVM's view). Mainline matches the predicated-with-rs5 form
	// (which has rs5 at bits 16..20 and op0007=0x1e fixed), so canonical
	// bytes 00d80096 from compare_3way.json don't decode in mainline:
	// the low-5 bits 0x00 don't match op0007=0x1e. We supply byte0=0x1e.
	//
	// rs5 = 0 (R0) -> byte2 bits 0..4 = 0; byte2 bits 5..7 = 0 (op2127 low).
	// byte3 bits 0..3 = 0110 (op2127 high), bits 4..7 = 1001 (iclass=9) ->
	// byte3 = 0x96. So bytes for "if (P0.new) dealloc_return:t R0":
	//   byte0 = 0x1e, byte1 = 0xd8, byte2 = 0x00, byte3 = 0x96 -> "1ed80096".

	/** Pin L4_return_*new_p* (dealloc_return predicated by P.new) family. */
	@Test
	public void testPacketCoverage_DeallocReturnNew() {
		// L4_return_tnew_pt    -- "if (P0.new) dealloc_return:t" rs5=R0
		// byte1: parse=11, bit13=0, bit12=1, bit11=1, bit10=0, bits9..8=00 = 0xd8
		assertPacketDecode("1ed80096", 1, PB_S1_NREG0_R0,
			"dealloc_return.if(P0.new):t R0");
		// L4_return_tnew_pnt   -- "if (P0.new) dealloc_return:nt"
		// bit12=0 -> byte1 = 11_0_0_1_0_00 = 0xc8
		assertPacketDecode("1ec80096", 1, PB_S1_NREG0_R0,
			"dealloc_return.if(P0.new):nt R0");
		// L4_return_fnew_pt    -- "if (!P0.new) dealloc_return:t"
		// bit13=1 -> byte1 = 11_1_1_1_0_00 = 0xf8
		assertPacketDecode("1ef80096", 1, PB_S1_NREG0_R0,
			"dealloc_return.if(!P0.new):t R0");
		// L4_return_fnew_pnt   -- "if (!P0.new) dealloc_return:nt"
		// bit13=1, bit12=0 -> byte1 = 11_1_0_1_0_00 = 0xe8
		assertPacketDecode("1ee80096", 1, PB_S1_NREG0_R0,
			"dealloc_return.if(!P0.new):nt R0");
	}

	/** Pin HVX V6_vS32b_new_* family. */
	@Test
	public void testPacketCoverage_HVX_VS32bNew() {
		// V6_vS32b_new_ai (canonical 20c02028) -> set bit 1: byte0 = 0x22
		assertPacketDecode("22c02028", 1, PB_S1_NREG0_R0,
			"vmem (R0),V0.new");
		// V6_vS32b_new_pi (canonical 20c02029)
		assertPacketDecode("22c02029", 1, PB_S1_NREG0_R0,
			"vmem (R0++#0x0),V0.new");
		// V6_vS32b_new_pred_ai (canonical 40c0a028) -- mainline renders as
		// "vmem.if(P0)" rather than "if (P0) vmem".
		assertPacketDecode("42c0a028", 1, PB_S1_NREG0_R0,
			"vmem.if(P0) (R0),V0.new");
		// V6_vS32b_new_npred_ai (canonical 68c0a028)
		assertPacketDecode("6ac0a028", 1, PB_S1_NREG0_R0,
			"vmem.if(!P0) (R0),V0.new");
		// V6_vS32b_new_ppu (canonical 20c0202b) -- Mu2 post-increment
		assertPacketDecode("22c0202b", 1, PB_S1_NREG0_R0,
			"vmem (R0++M0),V0.new");
		// V6_vS32b_new_pred_pi (canonical 40c0a029) -- predicated post-inc imm
		assertPacketDecode("42c0a029", 1, PB_S1_NREG0_R0,
			"vmem.if(P0) (R0++#0x0),V0.new");
	}
}
