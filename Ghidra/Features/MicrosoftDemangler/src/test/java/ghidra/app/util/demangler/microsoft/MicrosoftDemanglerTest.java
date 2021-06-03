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
package ghidra.app.util.demangler.microsoft;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class MicrosoftDemanglerTest extends AbstractGenericTest {

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x01001000", 0x100);
		program = builder.getProgram();
	}

	@Test
	public void testArrayVariable() throws Exception { // NullPointerException
		String mangled = "?Te@NS1@BobsStuff@@0QAY0BAA@$$CBIA";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObject = demangler.demangle(mangled);

		int txID = program.startTransaction("Test");

		SymbolTable st = program.getSymbolTable();
		st.createLabel(addr("01001000"), mangled, SourceType.ANALYSIS);

		DemanglerOptions options = new DemanglerOptions();
		demangledObject.applyTo(program, addr("01001000"), options, TaskMonitor.DUMMY);
		program.endTransaction(txID, false);
	}

	@Test
	public void testIgnoredManagedStrings_ShouldNotBeIgnored() throws Exception {
		// at one point, this string was getting ignored
		String mangled = "??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = demangler.demangle(mangled);
		assertNotNull(demangledObj);
	}

	@Test
	public void testIgnoredMangledStrings_EndsWithTilde() throws Exception { // IndexOutOfBoundsException
		String mangled = "??_R0?AVCBob@@@8~";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Asterisk() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@*E";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Dash() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@-W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_QuestionMark() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@?W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Tilde() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@~W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Percent() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@%W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_BackTick() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@`W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Plus() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@+W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	@Test
	public void testIgnoredMangledStrings_Slash() throws Exception { // IndexOutOfBoundsException
		String mangled = "?BobsStuffIO@344GPAUHINSTANCE__@@U_COMMPROP@@/W";

		MicrosoftDemangler demangler = new MicrosoftDemangler();
		DemangledObject demangledObj = null;
		try {
			demangledObj = demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			// Expected
			return;
		}
		fail(); // We are expecting an exception.
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

}
