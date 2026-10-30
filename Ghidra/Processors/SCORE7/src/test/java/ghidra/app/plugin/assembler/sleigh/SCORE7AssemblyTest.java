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

public class SCORE7AssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("SCORE7:LE:32:default");
	}

	@Test
	public void testAssemble_nopCompactAtUpperHalfword() {
		assertOneCompatRestExact("nop!", "00:00", 0x00000002);
	}

	@Test
	public void testAssemble_ldiuCompactAtUpperHalfword() {
		assertOneCompatRestExact("ldiu! r4,0x2a", "2a:54", 0x00000002);
	}

	@Test
	public void testAssemble_nopFullWidth() {
		assertOneCompatRestExact("nop", "00:80:00:80", 0x00000000);
	}

	@Test
	public void testAssemble_addCompact() {
		assertOneCompatRestExact("add! r4,r5", "50:24", 0x00000000);
	}

	@Test
	public void testAssemble_returnCompact() {
		assertOneCompatRestExact("br! r3", "34:0f", 0x00000000);
	}

	@Test
	public void testAssemble_returnFullWidth() {
		assertOneCompatRestExact("br r3", "08:bc:03:80", 0x00000000);
	}

	@Test
	public void testAssemble_mfsr() {
		assertOneCompatRestExact("mfsr r4,sr1", "50:84:80:80", 0x00000000);
	}

	@Test
	public void testAssemble_mfcel() {
		assertOneCompatRestExact("mfcel r4", "48:84:80:80", 0x00000000);
	}

	@Test
	public void testAssemble_trapAlways() {
		assertOneCompatRestExact("trap 0x7", "04:bc:07:80", 0x00000000);
	}

	@Test
	public void testAssemble_atomicLoadWord() {
		assertOneCompatRestExact("alw r4,[r5]", "0c:80:85:80", 0x00000000);
	}

	@Test
	public void testAssemble_storeTlb() {
		assertOneCompatRestExact("stlb", "04:80:00:98", 0x00000000);
	}

	@Test
	public void testAssemble_sleep() {
		assertOneCompatRestExact("sleep", "c4:80:00:98", 0x00000000);
	}

	@Test
	public void testAssemble_compareTVariants() {
		assertOneCompatRestExact("cmpteq.c r4,r5", "19:94:04:80", 0x00000000);
		assertOneCompatRestExact("cmptmi.c r4,r5", "19:94:24:80", 0x00000000);
		assertOneCompatRestExact("cmp.c r4,r5", "19:94:64:80", 0x00000000);
	}

	@Test
	public void testAssemble_rotateCarryMnemonic() {
		assertOneCompatRestExact("rorc.c r4,r5,r6", "3b:98:85:80", 0x00000000);
	}

	@Test
	public void testAssemble_tsetMnemonic() {
		assertOneCompatRestExact("tset", "54:bc:00:80", 0x00000000);
	}

	@Test
	public void testAssemble_pceLayout() {
		assertOneCompatRestExact("pce 0x0,0x0", "00:00:00:80", 0x00000000);
	}
}
