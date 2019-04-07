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

public class ARMBEAssemblyTest extends AbstractAssemblyTest {
	public static final String THUMB = "80:00:00:00:00:00:00:00";
	public static final String T_CONDIT_ETT_EQ = "80:24:00:00:00:00:00:00";

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("ARM:BE:32:v7");
	}

	@Test
	public void testAssemble_bl_0x000230b8() {
		assertOneCompatRestExact("bl 0x000230b8", "eb:00:6c:21", 0x0000802c);
	}

	@Test
	public void testAssemble_and_r0_r0_n0xc40000() {
		assertOneCompatRestExact("and r0,r0,#0xc40000", "f4:00:00:44", THUMB, 0x00030464,
			"and r0,r0,#0xc40000");
	}
}
