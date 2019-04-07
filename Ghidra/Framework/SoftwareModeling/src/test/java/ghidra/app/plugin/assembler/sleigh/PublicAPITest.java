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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;

public class PublicAPITest extends AbstractGenericTest {
	private Language x86;

	@Before
	public void setUp() throws Exception {
		SleighLanguageProvider provider = new SleighLanguageProvider();
		x86 = provider.getLanguage(new LanguageID("x86:LE:64:default"));
	}

	@Test
	public void testADD0() throws AssemblySyntaxException, AssemblySemanticException {
		Assembler asm = Assemblers.getAssembler(x86);
		byte[] b =
			asm.assembleLine(x86.getDefaultSpace().getAddress(0x40000000), "ADD byte ptr [RBX],BL");
		printArray(b);
	}

	public static void printArray(byte[] arr) {
		for (int i = 0; i < arr.length; i++) {
			System.out.printf("%02x", arr[i]);
		}
		System.out.println();
	}
}
