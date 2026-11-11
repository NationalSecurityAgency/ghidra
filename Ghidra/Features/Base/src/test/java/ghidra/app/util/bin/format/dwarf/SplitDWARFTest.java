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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;
import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.AccessMode;
import java.util.Map;

import org.junit.Assume;
import org.junit.Test;

import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.data.*;

/** Tests Clang DWARF 4 and 5 type units and split objects with signature references. */
public class SplitDWARFTest extends DWARFTestBase {

	@Test
	public void testSplitTypeReference() throws Exception {
		checkDwarf5Split("sample.dwo");
	}

	@Test
	public void testCompressedSplitTypeReference() throws Exception {
		checkDwarf5Split("sample_compressed.dwo");
	}

	private void checkDwarf5Split(String dwoName) throws Exception {
		loadObjectSections(fixture("sample.o"));
		File dwo = fixture(dwoName);

		try (DWARFProgram main = new DWARFProgram(program, new DWARFImportOptions(),
			new BaseSectionProvider(program))) {
			main.init(monitor);
			Map<Long, DWARFCompilationUnit> skeletons =
				main.getDIEContainer().getSkeletonsByDwoId();
			assertEquals(1, skeletons.size());
			try (DWARFProgram split = new DWARFProgram(program, new DWARFImportOptions(),
				new ElfDWOSectionProvider(dwo, main.getSectionProvider()))) {
				split.getDIEContainer().setSkeletonsByDwoId(skeletons);
				split.init(monitor);
				checkTypeReference(split);
				DWARFCompilationUnit splitCU = split.getCompilationUnits()
						.stream()
						.filter(cu -> cu.getUnitType() == DWARFUnitType.DW_UT_split_compile)
						.findFirst()
						.orElseThrow();
				assertEquals(skeletons.get(splitCU.getDwoId()).getAddrTableBase(),
					splitCU.getAddrTableBase());
			}
		}
	}

	@Test
	public void testDwarf4TypeReference() throws Exception {
		loadObjectSections(fixture("type_sample.o"));
		try (DWARFProgram dwarf = new DWARFProgram(program, new DWARFImportOptions(),
			new BaseSectionProvider(program))) {
			dwarf.init(monitor);
			checkTypeReference(dwarf);
		}
	}

	@Test
	public void testDwarf4SplitTypeReference() throws Exception {
		loadObjectSections(fixture("split_v4.o"));
		try (DWARFProgram main = new DWARFProgram(program, new DWARFImportOptions(),
			new BaseSectionProvider(program))) {
			main.init(monitor);
			Map<Long, DWARFCompilationUnit> skeletons =
				main.getDIEContainer().getSkeletonsByDwoId();
			assertEquals(1, skeletons.size());
			try (DWARFProgram split = new DWARFProgram(program, new DWARFImportOptions(),
				new ElfDWOSectionProvider(fixture("split_v4.dwo"), main.getSectionProvider()))) {
				split.getDIEContainer().setSkeletonsByDwoId(skeletons);
				split.init(monitor);
				checkTypeReference(split);
				DWARFCompilationUnit splitCU = split.getCompilationUnits()
						.stream()
						.filter(cu -> !cu.isTypeUnit())
						.findFirst()
						.orElseThrow();
				assertEquals(0, split.getDIEContainer().getAddress(DW_FORM_gnu_addr_index, 0,
					splitCU));
			}
		}
	}

	@Test
	public void testExternalDwarf4TypeUnits() throws Exception {
		String path = System.getenv("GHIDRA_DWARF_INPUT");
		Assume.assumeNotNull(path);
		loadObjectSections(new File(path));
		try (DWARFProgram dwarf = new DWARFProgram(program, new DWARFImportOptions(),
			new BaseSectionProvider(program))) {
			dwarf.init(monitor);
			DWARFCompilationUnit typeUnit = dwarf.getCompilationUnits()
					.stream()
					.filter(DWARFCompilationUnit::isTypeUnit)
					.findFirst()
					.orElseThrow();
			assertNotNull(dwarf.getDIEContainer().getDIE(DW_FORM_ref_sig8,
				typeUnit.getTypeSignature(), typeUnit));
			DIEAggregate type = dwarf.getDIEContainer().getAggregate(
				typeUnit.getTypeDIEOffset());
			dwarf.getDwarfDTM().importAllDataTypes(monitor);
			assertNotNull(dwarf.getDwarfDTM().getDataType(type, null));
		}
	}

	private void loadObjectSections(File object) throws Exception {
		try (FileByteProvider objectBytes = new FileByteProvider(object, null, AccessMode.READ)) {
			ElfHeader elf = new ElfHeader(objectBytes, null);
			elf.parse();
			long address = 0x10000;
			for (ElfSectionHeader section : elf.getSections()) {
				String name = section.getNameAsString();
				if (!name.startsWith(".debug_") || section.getSize() == 0) {
					continue;
				}
				byte[] data = objectBytes.readBytes(section.getOffset(), section.getSize());
				program.getMemory()
						.createInitializedBlock(name, addr(address), new ByteArrayInputStream(data),
							data.length, monitor, false);
				address += data.length + 0x10000;
			}
		}
	}

	private void checkTypeReference(DWARFProgram dwarf) throws Exception {
		DWARFCompilationUnit typeUnit = dwarf.getCompilationUnits()
				.stream()
				.filter(DWARFCompilationUnit::isTypeUnit)
				.findFirst()
				.orElseThrow();
		DebugInfoEntry type = dwarf.getDIEContainer().getDIE(DW_FORM_ref_sig8,
			typeUnit.getTypeSignature(), typeUnit);
		assertNotNull(type);
		assertEquals(typeUnit.getTypeDIEOffset(), type.getOffset());
		assertEquals(DW_TAG_structure_type, type.getTag());

		DWARFCompilationUnit compileUnit = dwarf.getCompilationUnits()
				.stream()
				.filter(cu -> !cu.isTypeUnit())
				.findFirst()
				.orElseThrow();
		DebugInfoEntry subprogram = compileUnit.getCompUnitDIEA()
				.getChildren(DW_TAG_subprogram).get(0);
		DIEAggregate function = dwarf.getDIEContainer().getAggregate(subprogram);
		assertEquals(type.getOffset(), function.getTypeRef().getOffset());

		dwarf.getDwarfDTM().importAllDataTypes(monitor);
		DataType point = dwarf.getDwarfDTM().getDataType(typeUnit.getTypeDIEOffset(), null);
		assertTrue(String.valueOf(point), point instanceof Structure);
		Structure structure = (Structure) point;
		assertEquals(8, structure.getLength());
		assertEquals(2, structure.getNumComponents());
	}

	private File fixture(String name) throws Exception {
		return new File(getClass()
				.getResource("/ghidra/app/util/bin/format/dwarf/split/" + name)
				.toURI());
	}
}
