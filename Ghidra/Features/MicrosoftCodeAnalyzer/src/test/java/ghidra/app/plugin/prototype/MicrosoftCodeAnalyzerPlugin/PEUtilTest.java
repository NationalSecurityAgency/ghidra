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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.cmd.data.AbstractCreateDataTypeModelTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

public class PEUtilTest extends AbstractCreateDataTypeModelTest {

	@Test
	public void testIsVisualStudioOrClangPeGivenVisualStudioPe() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		boolean result = PEUtil.isVisualStudioOrClangPe(program);
		assertTrue(result);
	}

	@Test
	public void testIsVisualStudioOrClangPeGivenClangPe() throws Exception {
		ProgramBuilder builder = build64BitX86Clang();
		ProgramDB program = builder.getProgram();
		boolean result = PEUtil.isVisualStudioOrClangPe(program);
		assertTrue(result);
	}

	@Test
	public void testIsVisualStudioOrClangPeGivenNotVisualStudioOrClangPe() throws Exception {
		ProgramBuilder builder = build64BitX86NonVS();
		ProgramDB program = builder.getProgram();
		boolean result = PEUtil.isVisualStudioOrClangPe(program);
		assertFalse(result);
	}

}
