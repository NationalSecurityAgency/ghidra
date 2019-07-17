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

public class m68000AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("68000:BE:32:default");
	}

	@Test
	public void testAssemble_move_b_0x7_m0xe_A2m() {
		assertOneCompatRestExact("move.b #0x7,(0xe,A2)", "15:7c:00:07:00:0e");
	}

	@Test
	public void testAssemble_fmove_d_0x4010000000000000_FP1() {
		assertOneCompatRestExact("fmove.d #0x4010000000000000,FP1",
			"f2:3c:54:80:40:10:00:00:00:00:00:00");
	}
}
