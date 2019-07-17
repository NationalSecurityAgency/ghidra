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
import ghidra.util.Msg;

public class x86AVX2AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("x86:LE:64:default");
	}

	@Test
	public void testAssemble_VMOVSS_mRBP_n0x4m_XMM0() {
		try {
			assertOneCompatRestExact("VMOVSS dword ptr [RBP + -0x4],XMM0", "c5:fa:11:45:fc");
		}
		catch (DisassemblyMismatchException e) {
			Msg.warn(this, "Swapping to test case with [I+R] form");
			assertOneCompatRestExact("VMOVSS dword ptr [-0x4 + RBP],XMM0", "c5:fa:11:45:fc");
		}
	}
}
