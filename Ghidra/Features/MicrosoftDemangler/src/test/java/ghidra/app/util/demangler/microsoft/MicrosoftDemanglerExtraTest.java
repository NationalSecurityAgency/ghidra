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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import mdemangler.object.MDObjectC;

/**
 * This class performs extra demangler testing for special cases that do not fit
 * the testing pattern found in MDMangBaseTest and {@link MicrosoftDemanglerTest}
 */
public class MicrosoftDemanglerExtraTest extends AbstractGenericTest {

	ProgramBuilder builder32;
	ProgramBuilder builder64;
	private ProgramDB program32;
	private ProgramDB program64;

	private Address address32;
	private Address functionAddress32;
	private Address address64;
	private Address functionAddress64;

	@Before
	public void setUp() throws Exception {
		String blockAddress = "0x01001000";
		String nonFunctionAddress = "0x01001000";
		String functionAddress = "0x01001010";

		builder32 = new ProgramBuilder("test32", "x86:LE:32:default");
		builder32.createMemory(".text", blockAddress, 0x100);
		builder32.createEmptyFunction("function", functionAddress, 1, VoidDataType.dataType);
		program32 = builder32.getProgram();
		address32 = program32.getAddressFactory().getAddress(nonFunctionAddress);
		functionAddress32 = program32.getAddressFactory().getAddress(functionAddress);

		builder64 = new ProgramBuilder("test64", "x86:LE:64:default");
		builder64.createMemory(".text", blockAddress, 0x100);
		builder64.createEmptyFunction("function", functionAddress, 1, VoidDataType.dataType);
		program64 = builder64.getProgram();
		address64 = program64.getAddressFactory().getAddress(nonFunctionAddress);
		functionAddress64 = program64.getAddressFactory().getAddress(functionAddress);
	}

	@After
	public void tearDown() throws Exception {
		builder32.dispose();
		builder64.dispose();
	}

	//==============================================================================================
	// Helpers

	private void processWith32Function(String mangled, String expectDemangled,
			String expectedFunction, String expectedConvention, int expectedNumBytes)
			throws DemangledException {
		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program32, functionAddress32);
		// We do not need to do this here: options.setErrorOnRemainingChars(false);

		// Testing Demangled hierarchy
		DemangledFunction demangledFunction = (DemangledFunction) demangler.demangle(context);
		assertEquals(expectedFunction,
			demangledFunction == null ? null : demangledFunction.toString());

		// Testing MDMang hierarchy
		MDObjectC objc = (MDObjectC) demangler.getMdItem();
		String convention = objc.getCallingConvention();
		int numParameterBytes = objc.getNumParameterBytes();
		assertEquals(expectedConvention, convention);
		assertEquals(expectedNumBytes, numParameterBytes);
		assertEquals(expectDemangled, objc.toString());
	}

	private void processWith32NonFunction(String mangled, String expectDemangled)
			throws DemangledException {
		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program32, address32);
		MicrosoftDemanglerOptions options = (MicrosoftDemanglerOptions) context.getOptions();
		// Important to set to false to standardize our test results to simple expected
		//  results.  When the C-style symbols do not create function results either because
		//  there is not a function at the address or because of the architecture, we might end
		//  up with remaining charactes because the demangler sets its index back tot he start.
		options.setErrorOnRemainingChars(false);

		// Testing Demangled hierarchy
		DemangledFunction demangledFunction = (DemangledFunction) demangler.demangle(context);
		assertEquals(null, demangledFunction);

		// Testing MDMang hierarchy
		MDObjectC objc = (MDObjectC) demangler.getMdItem();
		String convention = objc.getCallingConvention();
		int numParameterBytes = objc.getNumParameterBytes();
		assertEquals(null, convention);
		assertEquals(0, numParameterBytes);
		assertEquals(expectDemangled, objc.toString());
	}

	private void processWith64Function(String mangled, String expectDemangled,
			String expectedFunction, String expectedConvention, int expectedNumBytes)
			throws DemangledException {
		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program64, functionAddress64);
		MicrosoftDemanglerOptions options = (MicrosoftDemanglerOptions) context.getOptions();
		// Important to set to false to standardize our test results to simple expected
		//  results.  When the C-style symbols do not create function results either because
		//  there is not a function at the address or because of the architecture, we might end
		//  up with remaining charactes because the demangler sets its index back tot he start.
		options.setErrorOnRemainingChars(false);

		// Testing Demangled hierarchy
		DemangledFunction demangledFunction = (DemangledFunction) demangler.demangle(context);
		assertEquals(expectedFunction,
			demangledFunction == null ? null : demangledFunction.toString());

		// Testing MDMang hierarchy
		MDObjectC objc = (MDObjectC) demangler.getMdItem();
		String convention = objc.getCallingConvention();
		int numParameterBytes = objc.getNumParameterBytes();
		assertEquals(expectedConvention, convention);
		assertEquals(expectedNumBytes, numParameterBytes);
		assertEquals(expectDemangled, objc.toString());
	}

	private void processWith64NonFunction(String mangled, String expectDemangled)
			throws DemangledException {
		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program64, address64);
		MicrosoftDemanglerOptions options = (MicrosoftDemanglerOptions) context.getOptions();
		// Important to set to false to standardize our test results to simple expected
		//  results.  When the C-style symbols do not create function results either because
		//  there is not a function at the address or because of the architecture, we might end
		//  up with remaining charactes because the demangler sets its index back tot he start.
		options.setErrorOnRemainingChars(false);

		// Testing Demangled hierarchy
		DemangledFunction demangledFunction = (DemangledFunction) demangler.demangle(context);
		assertEquals(null, demangledFunction);

		// Testing MDMang hierarchy
		MDObjectC objc = (MDObjectC) demangler.getMdItem();
		String convention = objc.getCallingConvention();
		int numParameterBytes = objc.getNumParameterBytes();
		assertEquals(null, convention);
		assertEquals(0, numParameterBytes);
		assertEquals(expectDemangled, objc.toString());
	}

	//==============================================================================================

	@Test
	public void testVxTableAnonymousNsInOwnerAndBackref() throws Exception {
		String mangled = "??_7a@?A0xfedcba98@b@@6B012@01@@";
		String mTruth =
			"const b::`anonymous namespace'::a::`vftable'{for `b::A0xfedcba98::a's `A0xfedcba98::a'}";
		String gTruth =
			"const b::_anon_FEDCBA98::a::`vftable'{for `b::_anon_FEDCBA98::a's `_anon_FEDCBA98::a'}";

		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program32, address32);
		DemangledObject obj = demangler.demangle(context);

		String originalDemangled = obj.getOriginalDemangled();
		assertEquals(mTruth, originalDemangled);

		String demangled = demangler.getMdItem().toString();
		assertEquals(gTruth, demangled);
	}

	//==============================================================================================

	@Test
	//This test checks that we can provide a mangled string for a function namespace.
	// The return String from getOriginalMangled() is not null only for this special
	// circumstance.  So, in normal processing, we should check it for non-null to
	// determine that we have a result of this form.
	// The symbol here is from our cn3.cpp source target.
	public void testFunctionNamespace() throws Exception {
		String mangled = "?fn3@?2??Bar3@Foo2b@@SAHXZ@4HA";
		String wholeTruth = "int `public: static int __cdecl Foo2b::Bar3(void)'::`3'::fn3";
		String functionNamespaceMangledTruth = "?Bar3@Foo2b@@SAHXZ";
		String functionNamespaceTruth = "public: static int __cdecl Foo2b::Bar3(void)";

		MicrosoftDemangler demangler = new MicrosoftDemangler();

		MicrosoftMangledContext context =
			demangler.createMangledContext(mangled, null, program32, address32);
		DemangledObject obj = demangler.demangle(context);
		String demangled = demangler.getMdItem().toString();
		assertEquals(wholeTruth, demangled);

		String mangledFunctionNS = obj.getNamespace().getNamespace().getMangledString();
		assertEquals(functionNamespaceMangledTruth, mangledFunctionNS);

		context = demangler.createMangledContext(mangledFunctionNS, null, program32, address32);
		demangler.demangle(context);
		demangled = demangler.getMdItem().toString();
		assertEquals(functionNamespaceTruth, demangled);
	}

	//==============================================================================================
	/*
	 * Follow are C-style mangling scheme under 32-bit model; __vectorcall also valid for 64-bit
	 *      __cdecl: '_' prefix; no suffix; example "_name"
	 *    __stdcall: '_' prefix; "@<decimal_digits>" suffix; example "_name@12"
	 *   __fastcall: '@' prefix; "@<decimal_digits>" suffix; example "@name@12"
	 * __vectorcall: no prefix; "@@<decimal_digits>" suffix; example "name@@12"
	 */

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: cdecl; Architecture size: 32; Function present: yes
	// Result: cdecl function (stripped '_'); 0 bytes
	public void testCStyleCdeclWith32Function() throws Exception {
		String mangled = "_func_cdecl";
		String expectedDemangled = "func_cdecl";
		String expectedFunction = "__cdecl func_cdecl(void)";
		String expectedConvention = "__cdecl";
		int expectedNumBytes = 0;
		processWith32Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: cdecl; Architecture size: 32; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleCdeclWith32NoFunction() throws Exception {
		String mangled = "_func_cdecl";
		String expectedDemangled = "_func_cdecl";
		processWith32NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: cdecl; Architecture size: 64; Function present: yes
	// Result: no function; 0 bytes
	public void testCStyleCdeclWith64Function() throws Exception {
		String mangled = "_func_cdecl";
		String expectedDemangled = "_func_cdecl";
		String expectedFunction = null;
		String expectedConvention = null;
		int expectedNumBytes = 0;
		processWith64Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: cdecl; Architecture size: 64; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleCdeclWith64NoFunction() throws Exception {
		String mangled = "_func_cdecl";
		String expectedDemangled = "_func_cdecl";
		processWith64NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: stdcall; Architecture size: 32; Function present: yes
	// Result: stdcall function; 12 bytes
	public void testCStyleStdcallWith32Function() throws Exception {
		String mangled = "_func_stdcall@12";
		String expectedDemangled = "__stdcall func_stdcall,12";
		String expectedFunction = "__stdcall func_stdcall(void)";
		String expectedConvention = "__stdcall";
		int expectedNumBytes = 12;
		processWith32Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: stdcall; Architecture size: 32; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleStdcallWith32NoFunction() throws Exception {
		String mangled = "_func_stdcall@12";
		String expectedDemangled = "_func_stdcall";
		processWith32NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: stdcall; Architecture size: 64; Function present: yes
	// Result: no function; 0 bytes
	public void testCStyleStdcallWith64Function() throws Exception {
		String mangled = "_func_stdcall@12";
		String expectedDemangled = "_func_stdcall";
		String expectedFunction = null;
		String expectedConvention = null;
		int expectedNumBytes = 0;
		processWith64Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: stdcall; Architecture size: 64; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleStdcallWith64NoFunction() throws Exception {
		String mangled = "_func_stdcall@12";
		String expectedDemangled = "_func_stdcall";
		processWith64NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: fastcall; Architecture size: 32; Function present: yes
	// Result: fastcall function (stripped '@'); 12 bytes
	public void testCStyleFastcallWith32Function() throws Exception {
		String mangled = "@func_fastcall@12";
		String expectedDemangled = "__fastcall func_fastcall,12";
		String expectedFunction = "__fastcall func_fastcall(void)";
		String expectedConvention = "__fastcall";
		int expectedNumBytes = 12;
		processWith32Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: fastcall; Architecture size: 32; Function present: no
	// Result: no function; 12 bytes
	public void testCStyleFastcallWith32NoFunction() throws Exception {
		String mangled = "@func_fastcall@12";
		String expectedDemangled = ""; // empty because the prefix '@' causes an empty name
		processWith32NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: fastcall; Architecture size: 64; Function present: yes
	// Result: no function; 12 bytes
	public void testCStyleFastcallWith64Function() throws Exception {
		String mangled = "@func_fastcall@12";
		String expectedDemangled = ""; // empty because the prefix '@' causes an empty name
		String expectedFunction = null;
		String expectedConvention = null;
		int expectedNumBytes = 0;
		processWith64Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: fastcall; Architecture size: 64; Function present: no
	// Result: fastcall function; 12 bytes
	public void testCStyleFastcallWith64NoFunction() throws Exception {
		String mangled = "@func_fastcall@12";
		String expectedDemangled = ""; // empty because the prefix '@' causes an empty name
		processWith64NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: vectorcall; Architecture size: 32; Function present: yes
	// Result: vectorcall function; 12 bytes
	public void testCStyleVectorcallWith32Function() throws Exception {
		String mangled = "func_vectorcall@@12";
		String expectedDemangled = "__vectorcall func_vectorcall,12";
		String expectedFunction = "__vectorcall func_vectorcall(void)";
		String expectedConvention = "__vectorcall";
		int expectedNumBytes = 12;
		processWith32Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: vectorcall; Architecture size: 32; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleVectorcallWith32NoFunction() throws Exception {
		String mangled = "func_vectorcall@@12";
		String expectedDemangled = "func_vectorcall";
		processWith32NonFunction(mangled, expectedDemangled);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: vectorcall; Architecture size: 32; Function present: yes
	// Result: vectorcall function; 12 bytes
	public void testCStyleVectorcallWith64Function() throws Exception {
		String mangled = "func_vectorcall@@12";
		String expectedDemangled = "__vectorcall func_vectorcall,12";
		String expectedFunction = "__vectorcall func_vectorcall(void)";
		String expectedConvention = "__vectorcall";
		int expectedNumBytes = 12;
		processWith64Function(mangled, expectedDemangled, expectedFunction, expectedConvention,
			expectedNumBytes);
	}

	@Test
	//Uses additional context information for demangling:  architecture size and whether
	// demangling symbol for a known function
	// Scheme: vectorcall; Architecture size: 64; Function present: no
	// Result: no function; 0 bytes
	public void testCStyleVectorcallWith64NoFunction() throws Exception {
		String mangled = "func_vectorcall@@12";
		String expectedDemangled = "func_vectorcall";
		processWith64NonFunction(mangled, expectedDemangled);
	}

}
