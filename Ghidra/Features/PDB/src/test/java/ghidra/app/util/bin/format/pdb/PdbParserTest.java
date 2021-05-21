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
package ghidra.app.util.bin.format.pdb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class PdbParserTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;

	private static final String notepadGUID = "36cfd5f9-888c-4483-b522-b9db242d8478";
	private static final String programBasename = "notepad";

	// Note: this is in hex. Code should translate it to decimal when creating GUID/Age folder name
	private static final String notepadAge = "21";

	private File tempDir, fileLocation;
	private Program testProgram;
	private String pdbFilename, pdbXmlFilename;

	TestFunction[] programFunctions =
		new TestFunction[] { new TestFunction("function1", "0x110", "0x35") };

	@Before
	public void setUp() throws Exception {

		// Get temp directory in which to store files
		tempDir = createTempDirectory("pdb_parser");
		fileLocation = new File(tempDir, "exe");
		testProgram = buildProgram(fileLocation.getAbsolutePath());

		pdbFilename = programBasename + ".pdb";
		pdbXmlFilename = programBasename + ".pdb.xml";
	}

	private Program buildProgram(String exeLocation) throws Exception {

		Program currentTestProgram;

		builder = new ProgramBuilder(programBasename + ".exe", ProgramBuilder._TOY);

		builder.createMemory("test", "0x100", 0x500);
		builder.setBytes("0x110",
			"21 00 01 66 8c 25 28 21 00 01 66 8c 2d 24 21 00 01 9c 8f 05 58 21 00 01 8b 45 00 a3 " +
				"4c 21 00 01 8b 45 04 a3 50 21 00 01 8d 45 08 a3 5c 21 00 01 8b 85 e0 fc ff ff " +
				"c7 05 98 20 00 01 01 00 01 00 a1 50 21 00 01 a3 54 20 00 01 c7 05 48 20 00 01 " +
				"09 04 00 c0 c7 05 4c 20 00 01 01 00 00 00 a1 0c 20 00 01 89 85 d8 fc ff ff a1 " +
				"10 20 00 01 89 85 dc fc ff ff 6a 00 ff 15 28 10 00 01 68 d4 11 00 01 ff 15 38 " +
				"10 00 01 68 09 04 00 c0 ff 15 08 10 00 01 50 ff 15 0c 10 00 01 c3 cc cc cc cc cc");

		currentTestProgram = builder.getProgram();
		currentTestProgram.startTransaction("TEST_" + programBasename + ".exe");

		Options optionsList = currentTestProgram.getOptions(Program.PROGRAM_INFO);
		optionsList.setString(PdbParserConstants.PDB_GUID, notepadGUID);
		optionsList.setString(PdbParserConstants.PDB_AGE, notepadAge);
		optionsList.setString(PdbParserConstants.PDB_FILE, programBasename + ".pdb");
		optionsList.setString("Executable Location",
			exeLocation + File.separator + builder.getProgram().getName());

		return currentTestProgram;
	}


	private File buildPdbXml() throws IOException {
		File destFile = new File(tempDir, pdbXmlFilename);
		try (BufferedWriter xmlBuffWriter = new BufferedWriter(new FileWriter(destFile))) {

			xmlBuffWriter.write("<pdb file=\"" + pdbFilename + "\" exe=\"" + programBasename +
				"\" guid=\"{" + notepadGUID.toUpperCase() + "}\" age=\"" +
				Integer.parseInt(notepadAge, 16) + "\">\n");

//			xmlBuffWriter.write("<enums></enums>\n");
//			xmlBuffWriter.write("<datatypes></datatypes>\n");
//			xmlBuffWriter.write("<typedefs></typedefs>\n");
//			xmlBuffWriter.write("<classes></classes>\n");

			xmlBuffWriter.write("<functions>\n");

			for (TestFunction currentFunction : programFunctions) {
				xmlBuffWriter.write("<function name=\"" + currentFunction.getName() +
					"\" address=\"" + currentFunction.getAddress() + "\" length=\"" +
					currentFunction.getLength() + "\"></function>\n");
			}

			xmlBuffWriter.write("</functions>\n");

//			xmlBuffWriter.write("<tables></tables>");

			xmlBuffWriter.write("</pdb>\n");
		}

		return destFile;
	}

	@Test
	public void testApplyFunctions() throws Exception {

		File pdbXmlFile = buildPdbXml();

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(testProgram);
		DataTypeManagerService dataTypeManagerService = mgr.getDataTypeManagerService();
		PdbParser parser =
			new PdbParser(pdbXmlFile, testProgram, dataTypeManagerService, false, false,
				TaskMonitor.DUMMY);

		parser.openDataTypeArchives();
		parser.parse();
		parser.applyTo(new MessageLog());

		// Now check program to see if the function has been successfully applied
		AddressFactory addressFactory = testProgram.getAddressFactory();

		FunctionManager functionManager = testProgram.getFunctionManager();

		for (TestFunction currentFunction : programFunctions) {
			String currentFunctionAddress = currentFunction.getAddress();
			FunctionDB possibleFunction = (FunctionDB) functionManager.getFunctionAt(
				addressFactory.getAddress(currentFunctionAddress));

			assertNotNull("Expected function at address: " + currentFunctionAddress,
				possibleFunction);
			assertEquals("function1", possibleFunction.getName());
		}
	}
}

// Test loading of file with wrong GUID/Age (PdbParserNEW.parse() --> hasErrors() and hasWarnings())

// Test malformed XML

// Test incomplete information for each type of information

// Test file having name of a folder that is to be created.

class TestFunction {

	private String name, address, length;

	public TestFunction(String name, String address, String length) {
		this.name = name;
		this.address = address;
		this.length = length;
	}

	public String getName() {
		return name;
	}

	public String getAddress() {
		return address;
	}

	public String getLength() {
		return length;
	}

}
