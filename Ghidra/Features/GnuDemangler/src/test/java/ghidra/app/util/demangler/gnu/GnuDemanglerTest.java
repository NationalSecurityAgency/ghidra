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
package ghidra.app.util.demangler.gnu;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class GnuDemanglerTest extends AbstractGenericTest {

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x01001000", 0x100);
		program = builder.getProgram();
	}

	@Test
	public void testNonMangledSymbol() throws Exception {

		String mangled = "Java_org_sqlite_NativeDB__1exec";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		// this throws an exception with the bug in place
		try {
			demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			assertTrue(e.isInvalidMangledName());
		}
	}

	@Test
	public void testDemangleOnlyKnownPatterns_False() throws Exception {

		String mangled = "abracadabra_hocus_pocus";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDemangleOnlyKnownPatterns(false);
		try {
			demangler.demangle(mangled, options);
			fail("Demangle should have failed attempting to demangle a non-mangled string");
		}
		catch (DemangledException e) {
			// expected
		}
	}

	@Test
	public void testDemangleOnlyKnownPatterns_True() throws Exception {

		String mangled = "abracadabra_hocus_pocus";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		DemangledObject result = demangler.demangle(mangled);
		assertNull("Demangle did not skip a name that does not match a known mangled pattern",
			result);
	}

	@Test
	public void testDemangleTypeInfo() throws Exception {

		String mangled = "_ZTIN6AP_HAL3HAL9CallbacksE";

		program.startTransaction("markup...");
		program.getMemory().setInt(addr("01001000"), 0x1001010);

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr("01001000"), mangled, SourceType.IMPORTED);

		GnuDemangler demangler = new GnuDemangler();
		DemangledObject obj = demangler.demangle(mangled);
		assertNotNull(obj);

		//assertEquals("typeinfo for AP_HAL::HAL::Callbacks", obj.getSignature(false));

		assertTrue(
			obj.applyTo(program, addr("01001000"), new GnuDemanglerOptions(), TaskMonitor.DUMMY));

		Symbol s = symbolTable.getPrimarySymbol(addr("01001000"));
		assertNotNull(s);
		assertEquals("typeinfo", s.getName());
		assertEquals("AP_HAL::HAL::Callbacks", s.getParentNamespace().getName(true));

		assertEquals("typeinfo for AP_HAL::HAL::Callbacks",
			program.getListing().getComment(CodeUnit.PLATE_COMMENT, addr("01001000")));

		Data d = program.getListing().getDefinedDataAt(addr("01001000"));
		assertNotNull(d);
		assertTrue(d.isPointer());
	}

	@Test
	public void testDemangleTypeInfoName() throws Exception {

		String mangled = "_ZTSN6AP_HAL3HAL9CallbacksE";

		program.startTransaction("markup...");
		program.getMemory().setBytes(addr("01001000"), "ABC\0".getBytes());

		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr("01001000"), mangled, SourceType.IMPORTED);

		GnuDemangler demangler = new GnuDemangler();
		DemangledObject obj = demangler.demangle(mangled);
		assertNotNull(obj);

		assertEquals("typeinfo name for AP_HAL::HAL::Callbacks", obj.getSignature(false));

		assertTrue(
			obj.applyTo(program, addr("01001000"), new GnuDemanglerOptions(), TaskMonitor.DUMMY));

		Symbol s = symbolTable.getPrimarySymbol(addr("01001000"));
		assertNotNull(s);
		assertEquals("typeinfo-name", s.getName());
		assertEquals("AP_HAL::HAL::Callbacks", s.getParentNamespace().getName(true));

		assertEquals("typeinfo name for AP_HAL::HAL::Callbacks",
			program.getListing().getComment(CodeUnit.PLATE_COMMENT, addr("01001000")));

		Data d = program.getListing().getDefinedDataAt(addr("01001000"));
		assertNotNull(d);
		assertTrue(d.getDataType() instanceof TerminatedStringDataType);
		assertEquals("ABC", d.getValue());
	}

	@Test
	public void testDemangler_Format_EDG_DemangleOnlyKnownPatterns_True()
			throws DemangledException {

		/*
		 						Note:
			This test is less of a requirement and more of an observation.   This symbol was
			seen in the wild and is claimed to be of the Edison Design Group (EDG) format.
			It fails our parsing due to its resemblance to non-mangled text (see
			the test testNonMangledSymbol()).   If we update the code that checks for this
			noise, then this test and it's parter should be consolidated.
		 */

		String mangled = "_$_10MyFunction";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions(GnuDemanglerFormat.EDG);
		DemangledObject result = demangler.demangle(mangled, options);
		assertNull(result);
	}

	@Test
	public void testDemangler_Format_EDG_DemangleOnlyKnownPatterns_False()
			throws DemangledException {

		String mangled = "_$_10MyFunction";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions(GnuDemanglerFormat.AUTO, true);
		options.setDemangleOnlyKnownPatterns(false);
		DemangledObject result = demangler.demangle(mangled, options);
		assertNotNull(result);
		assertEquals("undefined MyFunction::~MyFunction(void)", result.getSignature(false));
	}

	@Test
	public void testDemangler_Format_CodeWarrior_MacOS8or9() throws DemangledException {
		// NOTE: mangled CodeWarrior format symbols with templates will fail
		// This is because the GNU demangler does not support CodeWarrior
		// .scroll__10TTextPanelFUcsi

		String mangled = ".scroll__10TTextPanelFUcsi";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions(GnuDemanglerFormat.AUTO, true);
		options.setDemangleOnlyKnownPatterns(false);
		DemangledObject result = demangler.demangle(mangled, options);
		assertNotNull(result);
		assertEquals("undefined TTextPanel::scroll(unsigned char,short,int)",
			result.getSignature(false));
	}

	@Test
	public void testGnuNativeProcessWithValidArguments() {

		String demanglerName = GnuDemanglerOptions.GNU_DEMANGLER_DEFAULT;
		String applicationArguments = "-s auto";
		try {
			GnuDemanglerNativeProcess.getDemanglerNativeProcess(demanglerName,
				applicationArguments);
		}
		catch (IOException e) {
			fail("Expected an exception when passing unknown arguments to the native demangler");
		}
	}

	@Test
	public void testGnuNativeProcessWithUnknownArguments() {

		String demanglerName = GnuDemanglerOptions.GNU_DEMANGLER_DEFAULT;
		String applicationArguments = "-s MrBob";
		try {
			setErrorsExpected(true);
			GnuDemanglerNativeProcess.getDemanglerNativeProcess(demanglerName,
				applicationArguments);
			fail("Expected an exception when passing unknown arguments to the native demangler");
		}
		catch (IOException e) {
			// expected
			Msg.error(this, "Test error", e);
		}
		setErrorsExpected(false);
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

}
