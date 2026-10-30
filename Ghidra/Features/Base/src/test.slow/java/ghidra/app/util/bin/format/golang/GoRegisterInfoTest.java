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

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class GoRegisterInfoTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final GoVer GO_VER = GoVer.parse("1.26");

	private static Structure struct(DataType... fields) {
		StructureDataType struct = new StructureDataType("S", 0);
		for (DataType field : fields) {
			struct.add(field);
		}
		return struct;
	}

	private static DataType atomicInt64() {
		return struct(new StructureDataType("sync/atomic.align64", 0), LongLongDataType.dataType);
	}

	private GoRegisterInfo regInfo(String langId) throws Exception {
		Language lang = getLanguageService().getLanguage(new LanguageID(langId));
		return GoRegisterInfoManager.getInstance().getRegisterInfoForLang(lang, GO_VER);
	}

	@Test
	public void testStructAlignment() throws Exception {
		GoRegisterInfo regInfo = regInfo(ProgramBuilder._X64);
		DataType bytes = new ArrayDataType(ByteDataType.dataType, 250, 1);
		assertEquals(1, regInfo.getAlignmentForType(struct(bytes, ByteDataType.dataType)));
		assertEquals(2, regInfo.getAlignmentForType(struct(bytes, UnsignedShortDataType.dataType)));
		assertEquals(8, regInfo.getAlignmentForType(struct(bytes, LongLongDataType.dataType)));
		assertEquals(1, regInfo.getAlignmentForType(struct()));
	}

	@Test
	public void testComplexAlignment() throws Exception {
		GoRegisterInfo regInfo = regInfo(ProgramBuilder._X64);
		DataType named = new TypedefDataType("main.T", Complex8DataType.dataType);
		assertEquals(4, regInfo.getAlignmentForType(named));
		assertEquals(4, regInfo.getAlignmentForType(struct(ByteDataType.dataType, named)));
		assertEquals(4, regInfo.getAlignmentForType(FloatComplexDataType.dataType));
		assertEquals(8, regInfo.getAlignmentForType(Complex16DataType.dataType));
		assertEquals(4, regInfo(ProgramBuilder._X86).getAlignmentForType(Complex16DataType.dataType));
	}

	@Test
	public void testRttiAlignment() throws Exception {
		GoRegisterInfo regInfo = regInfo(ProgramBuilder._X64);
		StructureDataType struct = (StructureDataType) struct(ByteDataType.dataType);	// zero-len fields omitted
		struct.setExplicitMinimumAlignment(2);	// Go struct{ b byte; _ [0]uint16 }
		assertEquals(2, regInfo.getAlignmentForType(struct));
	}

	@Test
	public void testAtomicAlign64() throws Exception {
		GoRegisterInfo regInfo = regInfo(ProgramBuilder._X86);
		assertEquals(8, regInfo.getAlignmentForType(atomicInt64()));
		assertEquals(8, regInfo.getAlignmentForType(struct(ByteDataType.dataType, atomicInt64())));
		assertEquals(4, regInfo.getAlignmentForType(struct(LongLongDataType.dataType)));
	}

	@Test
	public void testStackAlignmentIsRelativeToArgs() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("go386", ProgramBuilder._X86, this);
		try {
			Program program = builder.getProgram();
			GoParamStorageAllocator allocator = new GoParamStorageAllocator(program, GO_VER);
			long base = allocator.getStackAllocation(ByteDataType.dataType);
			assertEquals(base + 8, allocator.getStackAllocation(atomicInt64()));
		}
		finally {
			builder.dispose();
		}
	}
}
