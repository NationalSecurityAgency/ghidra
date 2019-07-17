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

public class AVR8AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("avr8:LE:16:extended");
	}

	@Test
	public void testAssemble_out_RAMPZ_R16() {
		assertOneCompatRestExact("out RAMPZ,R16", "0b:bf", 0x000007 * 2);
	}

	@Test
	public void testAssemble_ldi_R17_0x25() {
		assertOneCompatRestExact("ldi R17,0x25", "15:e2", 0x000000 * 2);
	}

	@Test
	public void testAssemble_inc_R16() {
		assertOneCompatRestExact("inc R16", "03:95", 0x000006 * 2);
	}

	@Test
	public void testAssemble_SKIP_add_R0_R22() {
		assertOneCompatRestExact("add R0,R22", "06:0e", "80:00:00:00", 0x006f6c * 2, "add R0,R22");
	}

	@Test
	public void testAssemble_brbs_0xc_Cflg() {
		assertOneCompatRestExact("brbs 0xc,Cflg", "c8:f3", 0x0000c * 2);
	}

	@Test
	public void testAssemble_lds_R18_0x019d() {
		assertOneCompatRestExact("lds R18,0x019d", "20:91:9d:01", 0x00012f * 2);
	}

	@Test
	public void testAssemble_call_0x256() {
		assertOneCompatRestExact("call 0x256", "0e:94:2b:01", 0x0001ec * 2);
	}

	@Test
	public void testAssemble_com_Wlo() {
		assertOneCompatRestExact("com Wlo", "80:95", 0x006fba * 2);
	}
}
