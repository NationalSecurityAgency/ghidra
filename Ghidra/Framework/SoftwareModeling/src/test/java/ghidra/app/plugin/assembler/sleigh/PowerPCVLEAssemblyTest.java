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

public class PowerPCVLEAssemblyTest extends AbstractAssemblyTest {
	public static final String VLE = "20:00:00:00:00:00:00:00";

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("PowerPC:BE:64:VLEALT-32addr");
	}

	@Test
	public void testAssemble_e_nop() {
		assertOneCompatRestExact("e_nop", "18:00:d0:00", VLE, 0x00400000, "e_nop");
	}
	
	@Test
	public void testAssemble_e_ori_r0_r0_neg0x2() {
		assertOneCompatRestExact("e_ori r0,r0,-0x2", "18:00:d4:fe", VLE, 0x00400000, "e_ori r0,r0,-0x2");
	}
}
