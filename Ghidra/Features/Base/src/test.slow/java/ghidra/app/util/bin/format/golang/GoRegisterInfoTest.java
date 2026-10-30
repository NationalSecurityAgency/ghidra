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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot.GoNameTypePair;
import ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot.GoStructDef;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class GoRegisterInfoTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final GoVer GO_VER = GoVer.parse("1.26");

	private static Structure struct(DataType... fields) {
		StructureDataType struct = new StructureDataType("S", 0);
		for (DataType field : fields) {
			struct.add(field);
		}
		return struct;
	}

	private static GoStructDef snapshotStructDef(String... fields) {
		GoStructDef result = new GoStructDef();
		result.Fields = new ArrayList<>();
		for (String field : fields) {
			GoNameTypePair f = new GoNameTypePair();
			f.Name = "field_" + result.Fields.size();
			f.DataType = field;
			result.Fields.add(f);
		}
		result.TypeParams = List.of();
		return result;
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
	public void testAtomicAlign64FromApiSnapshot_32bitArch() throws Exception {

		// Test the align64 special struct built-into golang that forces 64bit alignment on
		// all archs, when reading struct defs from the api snapshot.

		// slightly different align64 package names in these 2 versions
		List<GoVer> align64FeatureRange = List.of(GoVer.parse("1.19"), GoVer.parse("1.23"));

		ProgramBuilder builder = new ProgramBuilder("go386", ProgramBuilder._X86, "golang", this);
		try {
			Program program = builder.getProgram();
			for (GoVer ver : align64FeatureRange) {
				GoApiSnapshot gas = GoApiSnapshot.get(ver, "386", "linux", TaskMonitor.DUMMY);
				try (GoRttiMapper goBinary =
					new GoRttiMapper(program, null, 4 /*sizeof(32bit_ptr)*/, ver, gas)) {

					Structure i64 = (Structure) goBinary.getGoTypes()
							.getSnapshotDataType(GoSymbolName.parseTypeName("main.PIUS"),
								snapshotStructDef("byte", "int64", "byte", "byte"));

					assertEquals(4, i64.getAlignment());
					assertEquals(16, i64.getLength());
					assertEquals(13, i64.findComponent("field_3").getOffset());

					Structure ai64 = (Structure) goBinary.getGoTypes()
							.getSnapshotDataType(GoSymbolName.parseTypeName("main.AIUS"),
								snapshotStructDef("byte", "sync/atomic.Int64", "byte", "byte"));

					assertEquals(8, ai64.getAlignment());
					assertEquals(24, ai64.getLength());
					assertEquals(17, ai64.findComponent("field_3").getOffset());
				}
			}
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testAtomicAlign64FromApiSnapshot_64bitArch() throws Exception {

		// slightly different align64 package names in these 2 versions
		List<GoVer> align64FeatureRange = List.of(GoVer.parse("1.19"), GoVer.parse("1.23"));

		ProgramBuilder builder = new ProgramBuilder("go", ProgramBuilder._X64, "golang", this);
		try {
			Program program = builder.getProgram();
			for (GoVer ver : align64FeatureRange) {
				GoApiSnapshot gas = GoApiSnapshot.get(ver, "amd64", "linux", TaskMonitor.DUMMY);
				try (GoRttiMapper goBinary =
					new GoRttiMapper(program, null, 8 /*sizeof(64bit_ptr)*/, ver, gas)) {

					Structure i64 = (Structure) goBinary.getGoTypes()
							.getSnapshotDataType(GoSymbolName.parseTypeName("main.PIUS"),
								snapshotStructDef("byte", "int64", "byte", "byte"));

					assertEquals(8, i64.getAlignment());
					assertEquals(24, i64.getLength());
					assertEquals(17, i64.findComponent("field_3").getOffset());

					Structure ai64 = (Structure) goBinary.getGoTypes()
							.getSnapshotDataType(GoSymbolName.parseTypeName("main.AIUS"),
								snapshotStructDef("byte", "sync/atomic.Int64", "byte", "byte"));

					assertEquals(8, ai64.getAlignment());
					assertEquals(24, ai64.getLength());
					assertEquals(17, ai64.findComponent("field_3").getOffset());
				}
			}
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testStackAlignmentIsRelativeToArgs() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("go386", ProgramBuilder._X86, "golang", this);
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
