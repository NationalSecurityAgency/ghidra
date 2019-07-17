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

public class AVR32AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("avr32:BE:32:default");
	}

	@Test
	public void testAssemble_BRls_0x00003dae() {
		assertOneCompatRestExact("BR{ls} 0x00003dae", "fe:98:ff:e5", 0x00003de4);
	}

	@Test
	public void testAssemble_STM_nnSP_R7_LR() {
		assertOneCompatRestExact("STM --SP,R7,LR", "eb:cd:40:80");
	}
}
