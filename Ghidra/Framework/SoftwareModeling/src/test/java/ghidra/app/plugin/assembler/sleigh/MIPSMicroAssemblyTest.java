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

public class MIPSMicroAssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("MIPS:BE:32:micro");
	}

	@Test
	public void testAssemble_swm16_s0_s2_ra_0x10_mspm() {
		assertOneCompatRestExact("swm16 s0-s2,ra,0x10(sp)", "45:64", "40:00:00:00", 0x00400ed2,
			"swm16 s0-s2,ra,0x10(sp)");
	}

	@Test
	public void testAssemble_movep_a1_a2_s1_s2() {
		assertOneCompatRestExact("movep a1,a2,s1,s2", "84:52", "40:00:00:00", 0x004286a2,
			"movep a1,a2,s1,s2");
	}
}
