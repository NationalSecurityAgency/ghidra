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

public class PaRiscAssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("pa-risc:BE:32:default");
	}

	@Test
	public void testAssemble_STW_rp_n0x14_mspm() {
		assertOneCompatRestExact("STW rp,-0x14(sp)", "6b:c2:3f:d9");
	}

	@Test
	public void testAssemble_STW_r26_0x0_mr28m() {
		assertOneCompatRestExact("STW r26,0x0(r28)", "0f:9a:12:80");
	}

	@Test
	public void testAssemble_LDIL_0x73000_r28() {
		assertOneCompatRestExact("LDIL 0x73000,r28", "23:99:60:00");
	}

	@Test
	public void testAssemble_LDW_0x0_mr28m_r28() {
		assertOneCompatRestExact("LDW 0x0(r28),r28", "0f:80:10:9c");
	}

	@Test
	public void testAssemble_BE_L_0x6e0_msr4_rpm_sr0_r31() {
		assertOneCompatRestExact("BE,L 0x6e0(sr4,rp),sr0,r31", "e4:40:2d:c0");
	}

	@Test
	public void testAssemble_B_N_0x00010134() {
		assertOneCompatRestExact("B,N 0x00010134", "e8:00:00:82", 0x000100ec);
	}

	@Test
	public void testAssemble_CMPBF_leftleft_r28_r19_0x000100f0() {
		assertOneCompatRestExact("CMPBF,<< r28,r19,0x000100f0", "8a:7c:9f:5d", 0x0001013c);
	}

	@Test
	public void testAssemble_CMPICLR_leftright_0x0_r28_r0() {
		assertOneCompatRestExact("CMPICLR,<> 0x0,r28,r0", "93:80:30:00");
	}

	@Test
	public void testAssemble_AND_r5_r0_r13() {
		assertOneCompatRestExact("AND r5,r0,r13", "08:05:02:0d");
	}

	@Test
	public void testAssemble_FTEST() {
		assertOneCompatRestExact("FTEST", "30:00:24:20");
	}
}
