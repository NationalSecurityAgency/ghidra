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

import org.junit.Test;

import ghidra.program.model.lang.LanguageID;

public class AARCH64BEAssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("AARCH64:BE:64:v8A");
	}

	@Test
	public void testAssemble_ldr_w0_mx1_w0_UXTW_0x2m() {
		assertOneCompatRestExact("ldr w0,[x1, w0, UXTW #0x2]", "20:58:60:b8");
	}

	@Test
	public void testAssemble_ubfiz_w0_w0_0x3_0x5() {
		assertOneCompatRestExact("ubfiz w0,w0,#0x3,#0x5", "00:10:1d:53");
	}

	@Test
	public void testAssemble_mov_w1_0x19() {
		assertOneCompatRestExact("mov w1,#0x19", "21:03:80:52");
	}

	@Test
	public void testAssemble_fmov_d0_0x3ff0000000000000() {
		assertOneCompatRestExact("fmov d0,0x3ff0000000000000", "00:10:6e:1e");
	}

	@Test
	public void testAssemble_str_w0_msp_0x1cm() {
		assertOneCompatRestExact("str w0,[sp, #0x1c]", "e0:1f:00:b9");
	}

	@Test
	public void testAssemble_str_wzr_msp_0xa8m() {
		assertOneCompatRestExact("str wzr,[sp, #0xa8]", "ff:ab:00:b9");
	}

	@Test
	public void testAssemble_eor_w0_w0_0x1() {
		assertOneCompatRestExact("eor w0,w0,#0x1", "00:00:00:52");
	}

	@Test
	public void testAssemble_orr_w4_wzr_0x1010101() {
		assertOneCompatRestExact("orr w4,wzr,#0x1010101", "e4:c3:00:32");
	}

	@Test
	public void testAssemble_and_w0_w0_0xfffffffe() {
		assertOneCompatRestExact("and w0,w0,#0xfffffffe", "00:78:1f:12");
	}

	@Test
	public void testAssemble_orr_x1_xzr_n0x101010101010102() {
		assertOneCompatRestExact("orr x1,xzr,#-0x101010101010102", "e1:db:07:b2");
	}

	@Test
	public void testAssemble_and_x1_x1_0x1ffffffffff00() {
		assertOneCompatRestExact("and x1,x1,#0x1ffffffffff00", "21:a0:78:92");
	}

	@Test
	public void testAssemble_orr_x4_xzr_n0x6666666666666667() {
		assertOneCompatRestExact("orr x4,xzr,#-0x6666666666666667", "e4:e7:01:b2");
	}

	@Test
	public void testAssemble_b_cc_0x0042205c() {
		assertOneCompatRestExact("b.cc 0x0042205c", "43:fe:ff:54", 0x422094);
	}

	@Test
	public void testAssemble_ubfx_x1_x20_0x2_0x2() {
		assertOneCompatRestExact("ubfx x1,x20,#0x2,#0x2", "81:0e:42:d3");
	}

	@Test
	public void testAssemble_mov_x0_0x8() {
		assertOneCompatRestExact("mov x0,#0x8", "00:01:80:d2");
	}

	@Test
	public void testAssemble_sbfiz_x1_x2_0x2_0x20() {
		assertOneCompatRestExact("sbfiz x1,x2,#0x2,#0x20", "41:7c:7e:93");
	}

	@Test
	public void testAssemble_bfm_x19_x0_0x20_0x1f() {
		assertOneCompatRestExact("bfm x19,x0,#0x20,#0x1f", "13:7c:60:b3");
	}

	@Test
	public void testAssemble_mov_w0_n0x0() {
		// This one's really stalling up the solver :(
		assertOneCompatRestExact("mov w0,#0x0", "00:00:80:52");
	}
}
