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

public class MSP430XAssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("TI_MSP430X:LE:32:default");
	}

	@Test
	public void testAssemble_MOVA_0x8mSPm_R12() {
		assertOneCompatRestExact("MOVA 0x8(SP),R12", "3c:01:08:00", "80:00:00:00", 0x00007658,
			"MOVA 0x8(SP),R12");
	}

	@Test
	public void testAssemble_RPT_0x8_b_RLAX_W_R14() {
		assertOneCompatRestExact("RPT #0x8 { RLAX.W R14", "47:18:0e:5e", "80:00:00:00", 0x00007894,
			"RPT #0x8 { RLAX.W R14");
	}

	@Test
	public void testAssemble_MOV_W_0_0xcmSPm() {
		assertOneCompatRestExact("MOV.W #0,0xc(SP)", "81:43:0c:00", "MOV.W #0,0xc(SP)",
			"MOV.W #0x0,0xc(SP)");
	}
}
