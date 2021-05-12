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

public class SparcAssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("sparc:BE:32:default");
	}

	@Test
	public void testAssemble_rd_Y_g2() {
		assertOneCompatRestExact("rd %Y,g2", "85:40:00:00");
	}

	// Too many reserved/undefined bits: 524288 instructions to test
	// I tested them all once.
	public void testAssemble_restore() {
		assertOneCompatRestExact("restore", "81:e8:00:00");
	}

	@Test
	public void testAssemble_wr_g3_g0() {
		assertOneCompatRestExact("wr g0,g3,%Y", "81:80:00:03");
	}
}
