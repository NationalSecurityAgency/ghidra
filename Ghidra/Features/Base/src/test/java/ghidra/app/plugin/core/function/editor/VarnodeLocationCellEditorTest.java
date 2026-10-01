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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;

public class VarnodeLocationCellEditorTest extends AbstractGenericTest {
	private static final int AARCH64_GENERAL_REGISTER_MAX = 30;

	@Test
	public void testAarch64XRegistersUseNumericOrder() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestProgram", ProgramBuilder._AARCH64);
		ProgramDB p = builder.getProgram();
		builder.dispose();

		ProgramContext context = p.getProgramContext();
		List<Register> registers = VarnodeLocationCellEditor.getSortedVisibleRegisters(context);

		List<String> xRegisters = new ArrayList<>();
		for (Register register : registers) {
			if (register.getName().matches("x\\d+")) {
				xRegisters.add(register.getName());
			}
		}

		List<String> expected = new ArrayList<>();
		for (int i = 0; i <= AARCH64_GENERAL_REGISTER_MAX; i++) {
			expected.add("x" + i);
		}
		assertEquals(expected, xRegisters);
	}
}
