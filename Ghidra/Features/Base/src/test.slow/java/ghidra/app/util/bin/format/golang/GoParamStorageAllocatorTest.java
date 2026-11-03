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
package ghidra.app.util.bin.format.golang;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class GoParamStorageAllocatorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private GoParamStorageAllocator alloc;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("go", ProgramBuilder._X64, "golang", this);
		alloc = new GoParamStorageAllocator(builder.getProgram(), GoVer.parse("1.22"));
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private List<String> regs(DataType dt) {
		List<Register> regs = alloc.getRegistersFor(dt);
		return regs != null ? regs.stream().map(Register::getName).toList() : null;
	}

	@Test
	public void testComplexUsesTwoFloatRegisters() {
		assertEquals(List.of("XMM1_Qa", "XMM0_Qa"), regs(Complex16DataType.dataType));
		assertEquals(List.of("XMM3_Da", "XMM2_Da"), regs(Complex8DataType.dataType));
		assertEquals(List.of("XMM4_Qa"), regs(DoubleDataType.dataType));
	}

	@Test
	public void testComplexNeedsBothRegisters() {
		for (int i = 0; i < 14; i++) {
			regs(DoubleDataType.dataType);
		}
		assertNull(regs(Complex16DataType.dataType));
		assertEquals(List.of("XMM14_Qa"), regs(DoubleDataType.dataType));
	}
}
