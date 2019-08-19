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
package ghidra.app.util.bin.format.dwarf4.next;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.jar.ResourceFile;
import generic.test.category.NightlyCategory;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

@Category(NightlyCategory.class)
public class DWARFRegisterMappingsTest extends AbstractGhidraHeadlessIntegrationTest {

	private Language x86Lang;

	@Before
	public void setup() throws Exception {
		x86Lang = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("x86:LE:32:default"));
	}

	/**
	 * Test reading the DWARF register mappings for every language that has a DWARF register
	 * mapping file specified in its LDEF file.
	 * @throws IOException
	 */
	@Test
	public void testReadMappings() throws IOException {
		for (LanguageDescription langDesc : DefaultLanguageService.getLanguageService().getLanguageDescriptions(
			false)) {

			if (!DWARFRegisterMappingsManager.hasDWARFRegisterMapping(langDesc)) {
				continue;
			}

			Language lang =
				DefaultLanguageService.getLanguageService().getLanguage(langDesc.getLanguageID());

			ResourceFile mappingFile =
				DWARFRegisterMappingsManager.getDWARFRegisterMappingFileFor(lang);
			FileResolutionResult dwarfFileFRR;
			if ((dwarfFileFRR = FileUtilities.existsAndIsCaseDependent(mappingFile)) != null &&
				!dwarfFileFRR.isOk()) {
				throw new IOException(
					"DWARF register mapping filename case problem: " + dwarfFileFRR.getMessage());
			}

			DWARFRegisterMappings drm = DWARFRegisterMappingsManager.readMappingForLang(lang);
			assertNotNull("DWARF mapping read failed for " + langDesc.getLanguageID(), drm);
		}
	}

	@Test
	public void testOkMappings() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/></register_mappings><call_frame_cfa value=\"4\"/></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testMissingStackPointerMappings() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\"/></register_mappings><call_frame_cfa value=\"4\"/></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadStackPointerAttrMappings() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"NOT_A_BOOLEAN_STRING\"/></register_mappings><call_frame_cfa value=\"4\"/></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testMissingMappingsElemMappings() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(XmlUtilities.fromString("<dwarf></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadDuplicateMapping() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/><register_mapping dwarf=\"0\" ghidra=\"EBX\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test
	public void testGoodDuplicateMapping() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/><register_mapping dwarf=\"1\" ghidra=\"EAX\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadDWARFRegVal() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping missing_dwarf_attrib=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadDWARFRegVal2() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"not_a_number\" ghidra=\"EAX\" stackpointer=\"true\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testMissingGhidraReg() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" missing_ghidra_attr=\"EAX\" stackpointer=\"true\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadGhidraReg() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"BLAH\" stackpointer=\"true\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test
	public void testAutoInc() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/><register_mapping dwarf=\"1\" ghidra=\"ST0\" auto_count=\"8\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testTooLargeAutoIncCount() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/><register_mapping dwarf=\"1\" ghidra=\"ST0\" auto_count=\"16\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadFormatAutoIncCount() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/><register_mapping dwarf=\"1\" ghidra=\"ST0\" auto_count=\"foo\"/></register_mappings></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testBadCFAValue() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/></register_mappings><call_frame_cfa value=\"foo\"/></dwarf>"),
			x86Lang);
	}

	@Test(expected = IOException.class)
	public void testNegCFAValue() throws JDOMException, IOException {
		DWARFRegisterMappingsManager.readMappingFrom(
			XmlUtilities.fromString(
				"<dwarf><register_mappings><register_mapping dwarf=\"0\" ghidra=\"EAX\" stackpointer=\"true\"/></register_mappings><call_frame_cfa value=\"-1\"/></dwarf>"),
			x86Lang);
	}
}
