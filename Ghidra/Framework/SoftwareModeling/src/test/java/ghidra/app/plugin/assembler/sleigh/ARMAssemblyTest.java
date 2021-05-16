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

public class ARMAssemblyTest extends AbstractAssemblyTest {
	public static final String THUMB = "80:00:00:00:00:00:00:00";
	public static final String T_CONDIT_ETT_EQ = "80:24:00:00:00:00:00:00";

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("ARM:LE:32:v7");
	}

	@Test
	public void testAssemble_add_r11_sp_0x4() {
		assertOneCompatRestExact("add r11,sp,#0x4", "04:b0:8d:e2");
	}

	@Test
	public void testAssemble_andeq_r0_r0_r5() {
		assertOneCompatRestExact("andeq r0,r0,r5", "05:00:00:00");
	}

	@Test
	public void testAssemble_moveteq_r11_0xe570() {
		assertOneCompatRestExact("movteq r11,#0xe570", "70:b5:4e:03");
	}

	@Test
	public void testAssemble_stmcsda_r2_lr0r1r2r4r6r7r8lc() {
		assertOneCompatRestExact("stmdacs r2, {r0 r1 r2 r4 r6 r7 r8}^", "d7:01:42:28",
			"stmdacs r2,{r0 r1 r2 r4 r6 r7 r8}^");
	}

	@Test
	public void testAssemble_strh_r3_mr11_n0x86m() {
		assertOneCompatRestExact("strh r3,[r11,#-0x86]", "b6:38:4b:e1");
	}

	@Test
	public void testAssembly_T_add_w_pc_r0_r7_asr_0xf() {
		assertOneCompatRestExact("add.w pc,r0,r7, asr #0xf", "00:eb:e7:3f", THUMB, 0x0000c3b8,
			"add.w pc,r0,r7, asr #0xf");
	}

	@Test
	public void testAssemble_T_and_eq_r0_r5() {
		assertAllSemanticErrors("and.eq r0, r5", THUMB);
	}

	@Test
	public void testAssemble_T_and_r0_r5() {
		assertOneCompatRestExact("ands r0,r5", "28:40", THUMB, 0x00400000, "ands r0,r5");
	}

	@Test
	public void testAssemble_T_bl_0x00008000() {
		// What makes this different from the above test is that it jumps backward
		assertOneCompatRestExact("bl 0x00008000", "ff:f7:be:ff", THUMB, 0x00008080,
			"bl 0x00008000");
	}

	@Test
	public void testAssemble_T_bl_0x0002350c() {
		assertOneCompatRestExact("bl 0x0002350c", "1b:f0:76:fa", THUMB, 0x0000801c,
			"bl 0x0002350c");
	}

	@Test
	public void testAssemble_T_iteq() {
		assertOneCompatRestExact("itett eq", "09:BF", THUMB, 0x00400000, "itett eq");
	}

	@Test
	public void testAssemble_T_ITETT_EQ_and_eq_r0_r5() {
		assertOneCompatRestExact("and.eq r0, r5", "28:40", T_CONDIT_ETT_EQ, 0x00400000,
			"and.eq r0,r5");
	}

	@Test
	public void testAssemble_T_ITETT_EQ_and_r0_r5() {
		assertAllSemanticErrors("and r0, r5", T_CONDIT_ETT_EQ);
	}

	//@Ignore("This is a whitespace problem")
	@Test
	public void testAssemble_T_push_r7_lr() {
		assertOneCompatRestExact("push { r7, lr }", "80:b5", THUMB, 0x00008000, "push { r7, lr }",
			"push { r7, lr  }");
	}

	@Test
	public void testAssemble_T_vmov_i32_d0_simdExpand_0x1_0x0_0xb1() {
		assertOneCompatRestExact("vmov.i32 d0,simdExpand(0x1,0x0,0xb1)", "83:ff:31:00", THUMB,
			0x00010100, "vmov.i32 d0,simdExpand(0x1,0x0,0xb1)");
	}
}
