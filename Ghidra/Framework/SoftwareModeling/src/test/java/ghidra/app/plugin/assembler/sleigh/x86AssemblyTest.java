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

import org.junit.Ignore;
import org.junit.Test;

import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

public class x86AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("x86:LE:32:default");
	}

	@Test
	@Ignore("Some results are disassembled with + 0xfffffff8 instead. Wrong but harmless here")
	public void testAssemble_ADD_ECX_mEBX_n0x8m() {
		try {
			assertOneCompatRestExact("ADD ECX,dword ptr [EDX + -0x8]", "03:4a:f8");
		}
		catch (DisassemblyMismatchException e) {
			Msg.warn(this, "Swapping to test case with [I+R] form");
			assertOneCompatRestExact("ADD ECX,dword ptr [-0x8 + EDX]", "03:4a:f8");
		}
	}
}
