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
import ghidra.app.util.demangler.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
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
	public void testNonMangledSymbol_DemangleOnlyKnownPatterns_True() throws Exception {

		String mangled = "Java_org_sqlite_NativeDB__1exec";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDemangleOnlyKnownPatterns(true);

		// this throws an exception with the bug in place
		try {
			demangler.demangle(mangled);
		}
		catch (DemangledException e) {
			failWithException("Should not have encountered exception when ignoring unknown symbols",
				e);
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
			MangledContext mangledContext =
				demangler.createMangledContext(mangled, options, program, null);
			demangler.demangle(mangledContext);
			fail("Demangle should have failed attempting to demangle a non-mangled string");
		}
		catch (DemangledException e) {
			// expected
		}
	}

	@Test
	public void testUseStandardReplacements() throws Exception {

		//
		// Mangled: _ZTv0_n24_NSt19basic_ostringstreamIcSt11char_traitsIcE14pool_allocatorIcEED0Ev
		//
		// Demangled: virtual thunk to std::basic_ostringstream<char, std::char_traits<char>, pool_allocator<char> >::~basic_ostringstream()
		//
		// Replaced: virtual thunk to undefined __thiscall std::ostringstream::~ostringstream(void)
		//
		String mangled =
			"_ZTv0_n24_NSt19basic_ostringstreamIcSt11char_traitsIcE14pool_allocatorIcEED0Ev";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setUseStandardReplacements(true);
		MangledContext mangledContext =
			demangler.createMangledContext(mangled, options, program, null);
		DemangledObject dobj = demangler.demangle(mangledContext);
		assertNotNull(dobj);

		String signature = dobj.getSignature();
		assertEquals(
			"virtual thunk to undefined __thiscall std::ostringstream::~ostringstream(void)",
			signature);

		assertEquals(
			"virtual thunk to std::basic_ostringstream<char, std::char_traits<char>, pool_allocator<char> >::~basic_ostringstream()",
			dobj.getRawDemangled());

		//
		// Now disable demangled string replacement
		//
		options.setUseStandardReplacements(false); // options are still in context
		dobj = demangler.demangle(mangledContext);
		assertNotNull(dobj);

		String fullSignature = dobj.getSignature();
		assertEquals(
			"virtual thunk to undefined __thiscall std::basic_ostringstream<char,std::char_traits<char>,pool_allocator<char>>::~basic_ostringstream(void)",
			fullSignature);
	}

	@Test
	public void testUseStandardReplacements2() throws Exception {

		// 
		// Mangled: _ZN7Greeter5greetENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
		//
		// Demangled: undefined Greeter::greet(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>)
		//
		// Replaced: undefined Greeter::greet(std::string)
		//
		String mangled = "_ZN7Greeter5greetENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this perform initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setUseStandardReplacements(true);
		DemangledFunction dobj = (DemangledFunction) demangler.demangle(mangled, options);
		assertNotNull(dobj);

		String signature = dobj.getSignature();
		assertEquals("undefined Greeter::greet(std::string)", signature);

		DemangledParameter demangledParameter = dobj.getParameters().get(0);
		DemangledDataType type = demangledParameter.getType();
		DataType dt = type.getDataType(program.getDataTypeManager());
		assertTrue(dt.isNotYetDefined());
		//@formatter:off
		assertEquals("/Demangler/std/string\n" + 
			"pack(disabled)\n" + 
			"Structure string {\n" + 
			"}\n" + 
			"Length: 0 Alignment: 1\n", dt.toString());
		//@formatter:on

		//
		// Now disable demangled string replacement
		// 
		options.setUseStandardReplacements(false);
		dobj = (DemangledFunction) demangler.demangle(mangled, options);
		assertNotNull(dobj);

		String fullSignature = dobj.getSignature();
		assertEquals(
			"undefined Greeter::greet(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>)",
			fullSignature);

		demangledParameter = dobj.getParameters().get(0);
		type = demangledParameter.getType();
		dt = type.getDataType(program.getDataTypeManager());
		assertEquals("typedef basic_string undefined", dt.toString());

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
		MangledContext mangledContext =
			demangler.createMangledContext(mangled, options, program, null);
		DemangledObject result = demangler.demangle(mangledContext);
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
		MangledContext mangledContext =
			demangler.createMangledContext(mangled, options, program, null);
		DemangledObject result = demangler.demangle(mangledContext);
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
		MangledContext mangledContext =
			demangler.createMangledContext(mangled, options, program, null);
		DemangledObject result = demangler.demangle(mangledContext);
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
