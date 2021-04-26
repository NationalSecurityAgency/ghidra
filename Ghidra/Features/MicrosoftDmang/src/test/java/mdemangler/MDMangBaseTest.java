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
package mdemangler;

import java.io.*;

import org.junit.*;
import org.junit.experimental.categories.Category;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import generic.test.AbstractGenericTest;
import generic.test.category.NightlyCategory;
import ghidra.util.Msg;

/*
 * There are many desirable changes for this class.  Some tests have been duplicated because
 *  they were juxtaposed next to other tests, providing counter-point examples for them.
 *  Also many tests are not adequately named.  Moreover, there might be some over-testing...
 *  for example many tests were added as counter-point or fuzzing examples against other tests,
 *  which helped drive the demangler design to its current architecture; these tests might no
 *  longer provide any additional tests of code paths, but in earlier architectures they
 *  revealed why the current design at the time failed in processing some symbols.  So to
 *  say that they do not provide any benefit would be a real big problem and a serious
 *  miss-statement, especially if someone tried to refactor the code from its current state.
 * More tests will be added in the future, and I hope to provide more organization to the
 *  tests overall.
 */
/**
 * This class provides a core set of tests that have been discovered, created, and fuzzed--
 *  though many have been "genericized" with name components such as name0, name1,...  These
 *  tests are then run with different test configurations, though maybe not all of the time.
 *  For instance, only one configuration is currently envisioned for being run during nightly
 *  or continuous testing.  The other tests are intended to be exercised while the code is
 *  being modified.
 * As the developer of this demangler, I wanted to be able to have a demangler that could
 *  provide demangled interpretations based upon what Microsoft said was truth (which is wrong
 *  in many cases) and what I interpreted as truth (and it goes beyond this, as we have at
 *  least 6 different ways at this time for how to run the demangler).  But to use one
 *  set of tests without duplicating them across each configuration, I provide the test
 *  configuration, which creates the appropriate demangler (derived from MDMang) and then
 *  performs the appropriate tests (asserts) for the types of output that each demangler
 *  provides.
 * Note: While I believe there are bugs in some of Microsoft's interpretation, I find that
 *  it is very appropriate to try to model what Microsoft is doing--even trying to get its
 *  white spaces correct (including dangling white spaces)--as this provides insights into
 *  the Microsoft model and helps ups to "believe" that we are on the right track; moreover,
 *  it provides us with the ability to create large sets of data (millions of samples are
 *  available from Windows 7 and Windows 10 symbols) against which we can run our demangler
 *  and discover if we are doing better or worse with any given change.  As an example, I
 *  was able to make a change to this code base and run against the core set of tests below
 *  and found that I broke no tests, but when I ran against the Windows 10 symbols, I failed
 *  more than 1300 of these tests when the norm was to fail 73.  Note too, that I immediately
 *  throw away symbols from these sets that I can immediately say that Microsoft has gotten
 *  wrong (e.g., has "??" in the demangled string), but this approach gives general direction
 *  and it often (as in my example case) leads me to grab another symbol or two to put into
 *  the core set of tests to provide constraints around this living design.
 * The test configuration class names have the form MDMangFooTestConfiguration.  And the test
 *  suites for any of these configurations are in class names of the form MDMangFooTest (all
 *  derived from this class--MDMangBaseTest).  If someone needs to run just a single test
 *  method in this MDMangBaseTest with a different derived class from within Eclipse, then
 *  they can do so by making two line changes below in the constructor of this class--effectively
 *  transforming the class to look like one of its derived classes; at that point the developer
 *  can right-click on the specific test and run or debug that single test method (of course
 *  the constructor below should be changed back to its original form).
 * Note that there is also a test suite for performing nightly and continuous testing that
 *  makes use of junit Categories to annotate and eliminate currently failing test methods
 *  below from the test run.  This test suite is named MDMangBaseTestSuite.  Of course, the
 *  totality of tests can be run as normal by just running all tests in this file, as normal.
 *  This is the typical mode of testing I use.  But I also make use of the test classes
 *  derived from this one, including the (currently 2) Microsoft versions as well as the
 *  MDMangParseInfoTest (or substituting in MDMangParseInfoTestConfiguration in the constructor
 *  below) in order to get an console output of how the base core test is being parsed.
 */
@Category(NightlyCategory.class)
public class MDMangBaseTest extends AbstractGenericTest {
	//Testing output file
	protected static File testFile;
	protected static FileWriter testWriter;
	protected StringBuilder outputInfo;

	//Internal variables
	protected String mangled;
	protected String ms2013Truth;
	protected String msTruth;
	protected String dbTruth; //dumpbin truth
	protected String ghTruth;
	protected String mdTruth;

	protected MDBaseTestConfiguration testConfiguration;

	protected boolean quiet = false;

	protected boolean beQuiet() {
		return quiet || BATCH_MODE;
		//return quiet;
	}

	public MDMangBaseTest() {
		//Normal operation:
		testConfiguration = new MDBaseTestConfiguration(beQuiet());
		//Change out the above for one of the below for doing individual (right-click)
		// testing on any of the many tests below.
//		testConfiguration = new MDParseInfoTestConfiguration(beQuiet());
//		testConfiguration = new MDGhidraTestConfiguration(beQuiet());
//		testConfiguration = new MDVS2015TestConfiguration(beQuiet());
//		testConfiguration = new MDVS2013TestConfiguration(beQuiet());
//		testConfiguration = new MDGenericizeTestConfiguration(beQuiet());
	}

	@Before
	public void setUp() throws Exception {
		if (beQuiet()) {
			return;
		}
		if (testFile == null) {
			File tDir = createTempDirectory("mdmang");
			testFile = new File(tDir, "Results_" + getClass().getSimpleName() + ".txt");
			try {
				testWriter = new FileWriter(testFile);
			}
			catch (Exception e) {
				System.err.println(e.getMessage());
				e.printStackTrace();
			}
		}
	}

	@AfterClass
	public static void tearDown() throws Throwable {
		if (testWriter == null) {
			return;
		}
		testWriter.close();
		Msg.info(MDMangBaseTest.class,
			"Short test demangled results: " + testFile.getAbsolutePath());
	}

	@Rule
	public TestWatcher testWatcher = new TestWatcher() {
		@Override
		protected void failed(Throwable e, Description description) {
			if (testWriter == null) {
				return;
			}
			try {
				testWriter.write(description.getMethodName() + " false\n");
			}
			catch (IOException ex) {
				return;
			}
		}

		@Override
		protected void succeeded(Description description) {
			if (testWriter == null) {
				return;
			}
			try {
				testWriter.write(description.getMethodName() + " true\n");
			}
			catch (IOException ex) {
				return;
			}
		}
	};

	private void demangleAndTest() throws Exception {
		testConfiguration.demangleAndTest(testName, mangled, mdTruth, msTruth, ghTruth,
			ms2013Truth);
	}

	@Test
	public void testTripleQ0() throws Exception {
		mangled = "???__E??_7name0@name1@@6B@@@YMXXZ@?A0x647dec29@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const name1::name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const name1::name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_mod1() throws Exception {
		mangled = "???__E??_7name0@name1@@6Bx@xx@@y@yy@@@z@zz@@YMXXZ@?A0x647dec29@@$$FYMXXZ";
		msTruth =
			"void __clrcall zz::z::`dynamic initializer for 'const name1::name0::`vftable'{for `xx::x's `yy::y'}''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall zz::z::`dynamic initializer for 'const name1::name0::`vftable'{for `xx::x's `yy::y'}''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_mod2() throws Exception {
		mangled = "???__E??_7name0@name1@@6B@z@@YMXXZ@?A0x647dec29@@$$FYMXXZ";
		msTruth =
			"void __clrcall z::`dynamic initializer for 'const name1::name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall z::`dynamic initializer for 'const name1::name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown1() throws Exception {
		mangled = "?var@?A0x647dec29@@$$FYMXXZ";
		msTruth = "void __clrcall `anonymous namespace'::var(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown2() throws Exception {
		mangled = "?var@@YMXXZ";
		msTruth = "void __clrcall var(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown3() throws Exception {
		mangled = "??_7name0@name1@@6B@";
		msTruth = "const name1::name0::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown3a() throws Exception {
		mangled = "??_7name0@name1@@6B";
		msTruth = "const name1::name0::`vftable'{for ??}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown3b() throws Exception {
		mangled = "??_7name0@name1@@6Baaa@@@";
		msTruth = "const name1::name0::`vftable'{for `aaa'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown4() throws Exception {
		mangled = "??__E?var@@6B@@@YMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const var''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ0_breakdown5() throws Exception {
		mangled = "??__Evar@@YMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'var''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ1a() throws Exception {
		mangled = "???__Ename0@name1@@YMXXZ@?A0xd585d5fc@@$$FYMXXZ";
		msTruth = "void __clrcall name1::`dynamic initializer for 'name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall name1::`dynamic initializer for 'name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ1a_breakdown_analysis_000() throws Exception {
		mangled = "?name0@@$$FYMXXZ";
		msTruth = "void __clrcall name0(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ2a() throws Exception {
		mangled = "???__E?name0@name1@<name2>@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ2a_breakdown0() throws Exception {
		mangled = "?var@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth = "void __clrcall `anonymous namespace'::var(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ2a_breakdown1() throws Exception {
		mangled = "?name0@name1@<name2>@@$$Q2_NA";
		msTruth = "public: static bool <name2>::name1::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ2a_breakdown2() throws Exception {
		mangled = "??__E?var@@3HA@@YMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'int var''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTripleQ8a() throws Exception {
		mangled = "???__E??_7name0@@6B@@@YMXXZ@?A0xc2524ebc@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ8a1() throws Exception {
		mangled = "???__E??_7name0@@6B@name1@@YMXXZ@?A0xc2524ebc@@$$FYMXXZ";
		msTruth = "void __clrcall name1::`dynamic initializer for 'const name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall name1::`dynamic initializer for 'const name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ3a() throws Exception {
		mangled = "???__E?name0@name1@@3HA@@YMXXZ@?A0x09343ef7@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'int name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'int name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ1() throws Exception {
		mangled = "???__Ename0@name1@@YMXXZ@?A0xd585d5fc@@$$FYMXXZ";
		msTruth = "void __clrcall name1::`dynamic initializer for 'name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall name1::`dynamic initializer for 'name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ2() throws Exception {
		mangled = "???__E?name0@name1@<name2>@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ3() throws Exception {
		mangled =
			"???__E?name0@name1@name2@@$$Q0V?$name3@PE$AAVname4@name5@@@2@A@@YMXXZ@?A0x09343ef7@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ4() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ5() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2HA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ6() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ7() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testTripleQ8() throws Exception {
		mangled = "???__E??_7name0@@6B@@@YMXXZ@?A0xc2524ebc@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testWhiteSpaceFormatting1() throws Exception {
		// Example: Space after template parameter (cv modifier).
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWhiteSpaceFormatting2() throws Exception {
		mangled = "?name0@name1@@MAEPAPAP6GJPAUname2@@IIJ@ZXZ";
		msTruth =
			"protected: virtual long (__stdcall** * __thiscall name1::name0(void))(struct name2 *,unsigned int,unsigned int,long)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWhiteSpaceFormatting3() throws Exception {
		//Example: Has trailing white space.
		mangled = "?VarName@@3P9ClassName@@DAHXZED";
		msTruth = "int (__cdecl ClassName::*const volatile __ptr64 VarName)(void)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer() throws Exception {
		mangled = "?fn@@3P6AHH@ZA";
		msTruth = "int (__cdecl* fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer_NamedFunctionPointerWithAnonymousFunctionPointerParameter()
			throws Exception {
		mangled = "?fun@@3P6KXP6KXH@Z@ZA";
		msTruth = "void (* fun)(void (*)(int))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer_EMod_invalid() throws Exception {
		mangled = "?fn@@3PE6AHH@ZA";
		msTruth = "?fn@@3PE6AHH@ZA";
		mdTruth = ""; //Should error: EIF not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer_DollarAMod_invalid() throws Exception {
		mangled = "?fn@@3P$A6AHH@ZA";
		msTruth = "?fn@@3P$A6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer_DollarBMod_invalid() throws Exception {
		mangled = "?fn@@3P$B6AHH@ZA";
		msTruth = "?fn@@3P$B6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionPointer_DollarCMod_invalid() throws Exception {
		mangled = "?fn@@3P$C6AHH@ZA";
		msTruth = "?fn@@3P$C6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionReference() throws Exception {
		mangled = "?fn@@3A6AHH@ZA";
		msTruth = "int (__cdecl& fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionReference_EMod_invalid() throws Exception {
		mangled = "?fn@@3AE6AHH@ZA";
		msTruth = "?fn@@3AE6AHH@ZA";
		mdTruth = ""; //Should error: EIF not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionReference_DollarAMod_invalid() throws Exception {
		mangled = "?fn@@3A$A6AHH@ZA";
		msTruth = "?fn@@3A$A6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionReference_DollarBMod_invalid() throws Exception {
		mangled = "?fn@@3A$B6AHH@ZA";
		msTruth = "?fn@@3A$B6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionReference_DollarCMod_invalid() throws Exception {
		mangled = "?fn@@3A$C6AHH@ZA";
		msTruth = "?fn@@3A$C6AHH@ZA";
		mdTruth = ""; //Should error: managed property not allowed on fn* or fn&
		demangleAndTest();
	}

	@Test
	public void testFunctionQuestionModifier_invalid() throws Exception {
		mangled = "?fn@@3?6AHH@ZA";
		msTruth = "?fn@@3?6AHH@ZA";
		mdTruth = ""; //Should error: function ref type not allowed on '?' modifier type
		demangleAndTest();
	}

	//Not sure this is truly a valid symbol.  As mangled, seems to indicate an array of functions, but as demangled, seems to indicate
	// a function returning an array of ints.  I'm not aware that either is legal; plus this difference causes me some confusion.
	@Test
	public void testFunctionArray() throws Exception {
		mangled = "?fn@@3_O6AHH@ZA";
		msTruth = "int (__cdecl fn)(int)[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToFunctionPointer() throws Exception {
		mangled = "?fn@@3PAP6AHH@ZA";
		msTruth = "int (__cdecl** fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToPointerToFunctionPointer() throws Exception {
		mangled = "?fn@@3PAPAP6AHH@ZA";
		msTruth = "int (__cdecl** * fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToData() throws Exception {
		mangled = "?var@@3PBHC";
		msTruth = "int const * volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferenceToData() throws Exception {
		mangled = "?var@@3ABHC";
		msTruth = "int const & volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionToData() throws Exception {
		mangled = "?var@@3?BHC";
		msTruth = "int const volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToPointerToData() throws Exception {
		mangled = "?var@@3PDPBHC";
		msTruth = "int const * const volatile * volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToReferenceToData() throws Exception {
		mangled = "?var@@3PDABHC";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerToQuestionToData() throws Exception {
		mangled = "?var@@3PD?BHC";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferenceToPointerToData() throws Exception {
		mangled = "?var@@3ADPBHC";
		msTruth = "int const * const volatile & volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferenceToReferenceToData() throws Exception {
		mangled = "?var@@3ADABHC";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferenceToQuestionToData() throws Exception {
		mangled = "?var@@3AD?BHC";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionToPointerToData() throws Exception {
		mangled = "?var@@3?DPBHC";
		msTruth = "int const * const volatile volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionToReferenceToData() throws Exception {
		mangled = "?var@@3?DABHC";
		msTruth = "int const & const volatile volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionToQuestionToData() throws Exception {
		mangled = "?var@@3?D?BHC";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_1() throws Exception {
		mangled = "?abort@@$$J0YAXXZ";
		msTruth = "extern \"C\" void __cdecl abort(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J00HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_N() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$N00HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_O() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$O00HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_1() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J110HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_2() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J2220HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_3() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J33330HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_4() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J444440HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_5() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J5555550HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_6() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J66666660HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_7() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J777777770HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_8() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J8888888880HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_2_J_9() throws Exception {
		//Manufactured data
		mangled = "?xyz@@$$J99999999990HA";
		msTruth = "extern \"C\" private: static int xyz";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExternC_3() throws Exception {
		mangled = "?name0@@$$J0YMXP6MXPAX@Z0@Z";
		msTruth = "extern \"C\" void __clrcall name0(void (__clrcall*)(void *),void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileOneSample_2() throws Exception {
		mangled =
			"??1?$name0@PEAUname1@@$0A@P6APEAXPEAX@Z$1?name2@@$$FYAPEAX0@ZP6AAEAPEAU1@AEAPEAU1@@Z$1?name3@?$name4@PEAUname1@@@@$$FSAAEAPEAU1@1@Z@@$$FMEAA@XZ";
		msTruth =
			"protected: virtual __cdecl name0<struct name1 * __ptr64,0,void * __ptr64 (__cdecl*)(void * __ptr64),&void * __ptr64 __cdecl name2(void * __ptr64),struct name1 * __ptr64 & __ptr64 (__cdecl*)(struct name1 * __ptr64 & __ptr64),&public: static struct name1 * __ptr64 & __ptr64 __cdecl name4<struct name1 * __ptr64>::name3(struct name1 * __ptr64 & __ptr64)>::~name0<struct name1 * __ptr64,0,void * __ptr64 (__cdecl*)(void * __ptr64),&void * __ptr64 __cdecl name2(void * __ptr64),struct name1 * __ptr64 & __ptr64 (__cdecl*)(struct name1 * __ptr64 & __ptr64),&public: static struct name1 * __ptr64 & __ptr64 __cdecl name4<struct name1 * __ptr64>::name3(struct name1 * __ptr64 & __ptr64)>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator1() throws Exception {
		mangled = "??Bname0@@QEBAIXZ";
		msTruth = "public: __cdecl name0::operator unsigned int(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator2() throws Exception {
		mangled = "??Bname0@@QEBAVname1@@XZ";
		msTruth = "public: __cdecl name0::operator class name1(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator3() throws Exception {
		mangled = "??Bname0@@QEBAPEBVname1@@XZ";
		msTruth = "public: __cdecl name0::operator class name1 const * __ptr64(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator4() throws Exception {
		mangled = "??Bname0@name1@@QEAAPEAVname2@name3@@XZ";
		msTruth =
			"public: __cdecl name1::name0::operator class name3::name2 * __ptr64(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator5() throws Exception {
		mangled = "??Bname0@@QEBAP6AP6AXXZXZXZ";
		msTruth =
			"public: __cdecl name0::operator void (__cdecl*(__cdecl*)(void))(void)(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator6() throws Exception {
		mangled = "??$?BPEAE@?$name0@PEAE@name1@@QEAA?AU?$name2@PEAE@1@XZ";
		msTruth =
			"public: __cdecl name1::name0<unsigned char * __ptr64>::operator<unsigned char * __ptr64> struct name1::name2<unsigned char * __ptr64>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCastOperator7() throws Exception {
		mangled =
			"??$?BPEAEU?$name0@U?$name1@Uname2@name3@@Uname4@2@Uname5@2@U?$name6@U?$name7@Uname8@name3@@@name3@@Uname9@name10@2@@2@U?$name11@$0A@@2@Uname12@2@@name3@@@name3@@@?$name13@PEAEU?$name0@U?$name1@Uname2@name3@@Uname4@2@Uname5@2@U?$name6@U?$name7@Uname8@name3@@@name3@@Uname9@name10@2@@2@U?$name11@$0A@@2@Uname12@2@@name3@@@name3@@@name3@@QEAA?AU?$name14@PEAEU?$name0@U?$name1@Uname2@name3@@Uname4@2@Uname5@2@U?$name6@U?$name7@Uname8@name3@@@name3@@Uname9@name10@2@@2@U?$name11@$0A@@2@Uname12@2@@name3@@@name3@@@1@XZ";
		msTruth =
			"public: __cdecl name3::name13<unsigned char * __ptr64,struct name3::name0<struct name3::name1<struct name3::name2,struct name3::name4,struct name3::name5,struct name3::name6<struct name3::name7<struct name3::name8>,struct name3::name10::name9>,struct name3::name11<0>,struct name3::name12> > >::operator<unsigned char * __ptr64,struct name3::name0<struct name3::name1<struct name3::name2,struct name3::name4,struct name3::name5,struct name3::name6<struct name3::name7<struct name3::name8>,struct name3::name10::name9>,struct name3::name11<0>,struct name3::name12> > > struct name3::name14<unsigned char * __ptr64,struct name3::name0<struct name3::name1<struct name3::name2,struct name3::name4,struct name3::name5,struct name3::name6<struct name3::name7<struct name3::name8>,struct name3::name10::name9>,struct name3::name11<0>,struct name3::name12> > >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_1() throws Exception {
		mangled = "?name0@name1@@0_OBHB";
		msTruth = "private: static int const name1::name0[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_2() throws Exception {
		mangled = "?name0@@3_OAPEBUname1@@B";
		msTruth = "struct name1 const name0[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_2moda() throws Exception {
		mangled = "?name0@@3_OAPEBPEBPEBUname1@@B"; //Manufactured, added PEBPEB after (one PEB after--as in original)
		msTruth = "struct name1 const name0[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_2modb() throws Exception {
		mangled = "?name0@@3PEBPEB_OAPEBUname1@@B"; //Manufactured, added PEBPEB prior (one PEB after--as in original)
		msTruth = "struct name1 const * __ptr64 const * __ptr64 const name0[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_2modc() throws Exception {
		mangled = "?name0@@3PEBY01_OAPEBUname1@@B"; //Manufactured, added PEBY01 prior (one PEB after--as in original)
		msTruth = "struct name1 (const * __ptr64 const name0)[2][]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_2modd() throws Exception {
		mangled = "?name0@@3PEBY01PEB_OAPEBUname1@@B"; //Manufactured, added PEBYA01PEB prior (one PEB after--as in original)
		msTruth = "struct name1 const * __ptr64 (const * __ptr64 const name0)[2][]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_4() throws Exception {
		mangled = "?name0@name1@@0_OBQEBGB";
		msTruth = "private: static unsigned short const name1::name0[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_5() throws Exception {
		mangled = "?name0@name1@@0_OBPEBPEBP6A?BHH@ZB"; //Manufactured: added pointers to pointers to function pointers, which gets stripped on emit().
		msTruth = "private: static int const (__cdecl*const name1::name0)(int)[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArray_O_6() throws Exception { //manufactured
		mangled = "?name0@name1@@0_O6A?BHH@ZA";
		msTruth = "private: static int const (__cdecl name1::name0)(int)[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testInterestingArrayArray_O_a() throws Exception {
		mangled = "?Var@@0_OBY01QEBHB";
		msTruth = "private: static int const Var[][2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//parses, but ignores EIF, member, based, and const/volatile... will only output const or volatile, with const preference over volatile.
	@Test
	public void testInterestingArrayArray_O_ParsesButIgnoresAllCVEIFMemberBased_1()
			throws Exception {
		mangled = "?Var@@0_OEIF5aaa@@2bbb@@Y01QEBHB";
		msTruth = "private: static int const Var[][2]"; //parses, but ignores EIF
		mdTruth = msTruth;
		demangleAndTest();
	}

	//parses, but ignores EIF, member, based, and const/volatile... will only output const or volatile, with const preference over volatile.
	@Test
	public void testInterestingArrayArray_O_ParsesButIgnoresAllCVEIFMemberBased_2()
			throws Exception {
		mangled = "?Var@@0_OEIF5aaa@@2bbb@@Y01QEIF5ccc@@2ddd@@HB";
		msTruth = "private: static int const Var[][2]"; //parses, but ignores EIF
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	@Test
	public void testInterestingArrayArray_O_b() throws Exception {
		mangled = "?Var@@0_OBY00QEBY01HB";
		msTruth = "private: static int const Var[][1][][2]"; //Seems to indicate array items are appended--we have an extra bracket.  Bug in MSFT undname?
		mdTruth = "private: static int const Var[][1][2]"; //What I would expect.
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	@Test
	public void testInterestingArrayArray_O_c() throws Exception {
		mangled = "?Var@@0_OBY00QEBY01QEBY02HB";
		msTruth = "private: static int const Var[][1][][2][][3]"; //Seems to indicate array items are appended--we have an extra bracket.  Bug in MSFT undname?
		mdTruth = "private: static int const Var[][1][2][3]"; //What I would expect.
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	//Note: if the mangled symbol has the 'A' removed in the '$02EA' segment, then MSFT gets it correct;
	// note, too, that however that the original symbol is a valid symbol from forward programming (perhaps
	// it was only '$01EA'???), so undname has an error--our dispatcher might need to not progress the CVMod
	// ('A')... need to experiment.
	@Test
	public void testSource9a() throws Exception {
		mangled = "?PrintCountsAndBytes_e2@@$$FYMXP$02EA_WPE$AAVEncoding@Text@System@@@Z"; //Has Rank 2
		msTruth =
			"void __clrcall PrintCountsAndBytes_e2(cli::array<System::Text::_WPE$AAVEncoding ,2>^)";
//		mdtruth =
//			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^ __ptr64,class System::Text::Encoding ^ __ptr64)";
		mdTruth =
			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Hand-modified (massaging of real test) to show parts of truth
	@Test
	public void testSource9b() throws Exception {
		mangled = "?PrintCountsAndBytes_e2@@$$FYMXPEA_WPE$AAVEncoding@Text@System@@@Z";
		msTruth =
			"void __clrcall PrintCountsAndBytes_e2(wchar_t * __ptr64,class System::Text::Encoding ^ __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource9c() throws Exception {
		mangled = "?PrintCountsAndBytes_e2@@$$FYMXP$02EA_WPE$AAVEncoding@Text@System@@@Z"; //Has Rank 2
		msTruth =
			"void __clrcall PrintCountsAndBytes(cli::array<System::Text::_WPE$AAVEncoding ,2>^)";
//		mdtruth =
//			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^ __ptr64,class System::Text::Encoding ^ __ptr64)";
		mdTruth =
			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testSource9d() throws Exception {
		mangled = "?name0@@$$FYMXP$01EA_WPE$AAVname1@name2@name3@@@Z";
		msTruth = "void __clrcall name0(cli::array<name3::name2::_WPE$AAVname1 >^)";
		//mdtruth = "void __clrcall name0(cli::array<wchar_t >^ __ptr64,class name3::name2::name1 ^ __ptr64)";
		mdTruth = "void __clrcall name0(cli::array<wchar_t >^,class name3::name2::name1 ^ __ptr64)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testSource9e() throws Exception {
		mangled = "?name0@@$$FYMXQ$02EAP6AXXZPE$AAVname1@name2@name3@@@Z"; //Has Rank 2 with function pointer
		msTruth =
			"void __clrcall name0(cli::array<void (__cdecl*,2>^)(int),class name3::name2::name1 ^ __ptr64)"; //MS has (<(>)) order
		//mdtruth = "void __clrcall name0(cli::array<void (__cdecl*)(void) ,2>^ __ptr64 const,class name3::name2::name1 ^ __ptr64)";
		mdTruth =
			"void __clrcall name0(cli::array<void (__cdecl*)(void) ,2>^,class name3::name2::name1 ^ __ptr64)";
		// From Actual Forward Source: "void PrintCountsAndBytes_e4( array<void (__cdecl *)(void),ARANK>^const chars, Encoding^ enc )"
		// Now doctored with more information:: "void __clrcall PrintCountsAndBytes_e4(cli::array<void (__cdecl *)(void) ,2>^const,class System::Test::Encoding^ __ptr64 )"
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Real symbol: MSFT Win 7.
	@Test
	public void testCLI_1a() throws Exception {
		mangled = "??0name0@name1@name2@name3@name4@@$$FQE$AAM@P$01EAE@Z";
		msTruth = "GARBAGE";
		//mdtruth = "public: __clrcall name4::name3::name2::name1::name0::name0(cli::array<unsigned char >^ __ptr64) __ptr64";
		mdTruth =
			"public: __clrcall name4::name3::name2::name1::name0::name0(cli::array<unsigned char >^) __ptr64";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Real symbol: MSFT Win 7.  MSFT gets this one wrong.
	@Test
	public void testCLI_1b() throws Exception {
		mangled = "?name0@name1@name2@name3@@$$FSMP$01EAEVname4@name5@@PE$AAVname6@5@1P$01EAEHH@Z";
		msTruth = "public: static cli::array<name5::EVname4 >^"; //GARBAGE
		//TODO: CREATE mstruth output (dispatcher) and fix mstruth back to original
		msTruth = "public: static cli::array<unsigned char >^"; //(This truth is based on what I think MSFT intends to output, if it didn't have the 'E' EIF modifiers.
//		mdtruth =
//			"public: static cli::array<unsigned char __clrcall name3::name2::name1::name0(class name5::name4,class name5::name6 ^ __ptr64,class name5::name6 ^ __ptr64,cli::array<unsigned char >^,int,int) >^ __ptr64";
		mdTruth =
			"public: static cli::array<unsigned char >^ __clrcall name3::name2::name1::name0(class name5::name4,class name5::name6 ^ __ptr64,class name5::name6 ^ __ptr64,cli::array<unsigned char >^,int,int)";
		demangleAndTest();
	}

	@Test
	public void testCLI_1b_mod_noE() throws Exception {
		mangled = "?name0@name1@name2@name3@@$$FSMP$01AEVname4@name5@@PE$AAVname6@5@1P$01AEHH@Z";
		msTruth = "public: static cli::array<unsigned char >^";
		mdTruth =
			"public: static cli::array<unsigned char >^ __clrcall name3::name2::name1::name0(class name5::name4,class name5::name6 ^ __ptr64,class name5::name6 ^ __ptr64,cli::array<unsigned char >^,int,int)";
		demangleAndTest();
	}

	@Test
	public void testCLI_1b_mod_changeToPinPtr() throws Exception {
		mangled = "?name0@name1@name2@name3@@$$FSMP$BEAEVname4@name5@@PE$AAVname6@5@1P$BEAEHH@Z";
		msTruth =
			"public: static cli::pin_ptr<unsigned char * __ptr64 __clrcall name3::name2::name1::name0(class name5::name4,class name5::name6 ^ __ptr64,class name5::name6 ^ __ptr64,cli::pin_ptr<unsigned char * __ptr64,int,int)";
		mdTruth =
			"public: static cli::pin_ptr<unsigned char >* __ptr64 __clrcall name3::name2::name1::name0(class name5::name4,class name5::name6 ^ __ptr64,class name5::name6 ^ __ptr64,cli::pin_ptr<unsigned char >* __ptr64,int,int)";
		demangleAndTest();
	}

	//Real symbol: MSFT Win 7.  MSFT gets this one wrong.
	@Test
	public void testCLI_1c() throws Exception {
		mangled = "??0name0@name1@@$$FQE$AAM@P$01EAE0@Z";
		msTruth =
			"public: __clrcall name1::name0::name0(cli::array< ?? :: ?? ::Z::E0 >^, ?? ) __ptr64 throw( ?? )";
		mdTruth =
			"public: __clrcall name1::name0::name0(cli::array<unsigned char >^,cli::array<unsigned char >^) __ptr64";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Real symbol: MSFT Win 7.  MSFT gets this one wrong.
	@Test
	public void testCLI_1d() throws Exception {
		mangled = "?name0@name1@@$$FSM_NP$01EAE@Z";
		msTruth =
			"public: static bool __clrcall name1::name0(cli::array< ?? :: ?? ::Z::E >^, ?? ) throw( ?? )";
		mdTruth = "public: static bool __clrcall name1::name0(cli::array<unsigned char >^)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testBackRefX1() throws Exception {
		mangled =
			"??0name0@name1@name2@@QEAA@AEBV?$name3@_WU?$name4@_W@name5@@V?$name6@_W@2@Vname7@@@name5@@V?$name8@PEAXU?$name9@U?$name10@U?$name11@P6AHPEAX@Z$1?name12@@YAH0@Z@name13@@Uname14@2@Uname15@2@U?$name16@U?$name17@U?$name18@PEAX$0?0@name13@@@name13@@Uname19@name20@2@@2@U?$name21@$0A@@2@Uname22@2@@name13@@@name13@@@name13@@@Z";
		msTruth =
			"public: __cdecl name2::name1::name0::name0(class name5::name3<wchar_t,struct name5::name4<wchar_t>,class name5::name6<wchar_t>,class name7> const & __ptr64,class name13::name8<void * __ptr64,struct name13::name9<struct name13::name10<struct name13::name11<int (__cdecl*)(void * __ptr64),&int __cdecl name12(void * __ptr64)>,struct name13::name14,struct name13::name15,struct name13::name16<struct name13::name17<struct name13::name18<void * __ptr64,-1> >,struct name13::name20::name19>,struct name13::name21<0>,struct name13::name22> > >) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBackRefX2() throws Exception {
		mangled =
			"??0name0@?1??name1@name2@@UAEXXZ@QAE@V?$name3@GU?$name4@G@name5@@V?$name6@G@2@@name5@@0@Z";
		msTruth =
			"public: __thiscall `public: virtual void __thiscall name2::name1(void)'::`2'::name0::name0(class name5::name3<unsigned short,struct name5::name4<unsigned short>,class name5::name6<unsigned short> >,class name5::name3<unsigned short,struct name5::name4<unsigned short>,class name5::name6<unsigned short> >)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpecial__F() throws Exception {
		mangled =
			"??__Fname0@?1??name1@name2@name3@name4@@CAXPEAUname5@@P84@EAAJPEAPEAG@ZW4name6@@PEAUname7@@@Z@YAXXZ";
		msTruth =
			"void __cdecl `private: static void __cdecl name4::name3::name2::name1(struct name5 * __ptr64,long (__cdecl name4::*)(unsigned short * __ptr64 * __ptr64) __ptr64,enum name6,struct name7 * __ptr64)'::`2'::`dynamic atexit destructor for 'name0''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer1a() throws Exception {
		mangled = "?name0@@3P6AP6AXXZXZEA";
		msTruth = "void (__cdecl*(__cdecl* __ptr64 name0)(void))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer1a_with_publicstatic() throws Exception {
		mangled = "?name0@@2P6AP6AXXZXZEA";
		msTruth = "public: static void (__cdecl*(__cdecl* __ptr64 name0)(void))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionReference1a_with_publicstatic() throws Exception {
		mangled = "?name0@@2A6AA6AXXZXZEA";
		msTruth = "public: static void (__cdecl&(__cdecl& __ptr64 name0)(void))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionIndirect1a_with_publicstatic() throws Exception {
		mangled = "?name0@@2$$A6A$$A6AXXZXZEA";
		msTruth = "public: static void (__cdecl(__cdecl __ptr64 name0)(void))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer1b() throws Exception {
		mangled = "?name0@@3_O6AP6AXXZXZEA";
		msTruth = "void (__cdecl*(__cdecl __ptr64 name0)(void))(void)[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer1b1() throws Exception {
		mangled = "?name0@@3_O6AP6AXXZXZA";
		msTruth = "void (__cdecl*(__cdecl name0)(void))(void)[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer1c() throws Exception {
		mangled = "?name0@@3_O6A_O6AXXZXZEA";
		msTruth = "void (__cdecl(__cdecl __ptr64 name0)(void))(void)[][]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer2() throws Exception {
		mangled = "?name0@@3P6AP6AHPEAXIPEBG@ZP6AH0I1@ZK0@ZEA";
		msTruth =
			"int (__cdecl*(__cdecl* __ptr64 name0)(int (__cdecl*)(void * __ptr64,unsigned int,unsigned short const * __ptr64),unsigned long,void * __ptr64))(void * __ptr64,unsigned int,unsigned short const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNestedFunctionPointer3() throws Exception {
		mangled = "?name0@name1@@0P6AP6AHPEAXIPEBG@ZP6AH0I1@ZK0@ZEA";
		msTruth =
			"private: static int (__cdecl*(__cdecl* __ptr64 name1::name0)(int (__cdecl*)(void * __ptr64,unsigned int,unsigned short const * __ptr64),unsigned long,void * __ptr64))(void * __ptr64,unsigned int,unsigned short const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOtherFunctionPointerWithElipses() throws Exception {
		//Demonstrates that varargs ("...") is not a complex type, as if it was,
		//  it would be put on the BackrefParameters list and change the backref used
		mangled = "?name0@name1@@QEAAKP6AKPEAXKZZP6AKPEBGZZ1@Z";
		msTruth =
			"public: unsigned long __cdecl name1::name0(unsigned long (__cdecl*)(void * __ptr64,unsigned long,...),unsigned long (__cdecl*)(unsigned short const * __ptr64,...),unsigned long (__cdecl*)(void * __ptr64,unsigned long,...)) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionPointerRTTI_R0() throws Exception {
		mangled = "??_R0P6AXPEAUname0@@@Z@8";
		msTruth = "void (__cdecl*)(struct name0 * __ptr64) `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testNormalRTTI_R0() throws Exception {
		mangled = "??_R0?P4Vname0@@@8";
		msTruth = "class name0 const volatile __based() `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict1() throws Exception {
		mangled =
			"??1?$name0@PEAXV?$name1@PEAX$1??$name2@PEAX@@YAXPEAX@Z$1?name3@@YAX0@Z$01@@$0?0$1??$name4@PEAX@@YAHPEAX0@Z$01@@QEAA@XZ";
		msTruth =
			"public: __cdecl name0<void * __ptr64,class name1<void * __ptr64,&void __cdecl name2<void * __ptr64>(void * __ptr64),&void __cdecl name3(void * __ptr64),2>,-1,&int __cdecl name4<void * __ptr64>(void * __ptr64,void * __ptr64),2>::~name0<void * __ptr64,class name1<void * __ptr64,&void __cdecl name2<void * __ptr64>(void * __ptr64),&void __cdecl name3(void * __ptr64),2>,-1,&int __cdecl name4<void * __ptr64>(void * __ptr64,void * __ptr64),2>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testScopeWithInterface() throws Exception {
		mangled = "?name0@?Iname1@name2@@UEAA?AW4name3@@XZ";
		msTruth = "public: virtual enum name3 __cdecl name2[::name1]::name0(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict3() throws Exception {
		mangled =
			"??$?8GU?$name0@G@name1@@V?$name2@G@1@@name1@@YA_NAEBV?$name3@GU?$name0@G@name1@@V?$name2@G@2@Vname4@@@0@0@Z";
		msTruth =
			"bool __cdecl name1::operator==<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short> >(class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> const & __ptr64,class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict4() throws Exception {
		mangled = "???__E?name0@name1@<name2>@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testDerelict4related() throws Exception {
		mangled = "???__E??_7name0@@6B@@@YMXXZ@?A0xc2524ebc@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testDerelict4related_part1() throws Exception { //manufactured
		mangled = "??__E??_7name0@@6B@@@YMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const name0::`vftable'''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict4related_diff1() throws Exception {
		mangled = "?name0@@3QAY01$$CBEA";
		msTruth = "unsigned char const (* name0)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict4related_diff1other() throws Exception {
		mangled = "?name0@@3PEAY01EEA";
		msTruth = "unsigned char (* __ptr64 __ptr64 name0)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDerelict20140818() throws Exception {
		mangled =
			"??_7?$name0@V?$name1@PAVname2@name3@@@name4@@$0A@V?$name5@$1?name6@?$name7@PAVname2@name3@@@name8@name4@@SGPAUname9@4@XZ@2@@name4@@6Bname9@1@@";
		msTruth =
			"const name4::name0<class name4::name1<class name3::name2 *>,0,class name4::name5<&public: static struct name4::name9 * __stdcall name4::name8::name7<class name3::name2 *>::name6(void)> >::`vftable'{for `name4::name9'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured (modification)
	@Test
	public void testStdNullptrArg() throws Exception {
		mangled = "?fn@@YAH$$T@Z";
		msTruth = "int __cdecl fn(std::nullptr_t)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured--interestingly, this is probably not valid: see mstruth.
	@Test
	public void testStdNullptrArgVar() throws Exception {
		mangled = "?Name@@3$$TA";
		msTruth = "std::nullptr_t";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testStdNullptrArgReal() throws Exception { //std::nullptr_t
		mangled =
			"??$?9$$A6A_NABW4name0@name1@@@Z@name2@@YA_NABV?$name3@$$A6A_NABW4name0@name1@@@Z@0@$$T@Z";
		msTruth =
			"bool __cdecl name2::operator!=<bool __cdecl(enum name1::name0 const &)>(class name2::name3<bool __cdecl(enum name1::name0 const &)> const &,std::nullptr_t)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_C() throws Exception {
		mangled = "?Name@@3CA";
		msTruth = "signed char Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_D() throws Exception {
		mangled = "?Name@@3DA";
		msTruth = "char Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_E() throws Exception {
		mangled = "?Name@@3EA";
		msTruth = "unsigned char Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_F() throws Exception {
		mangled = "?Name@@3FA";
		msTruth = "short Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_G() throws Exception {
		mangled = "?Name@@3GA";
		msTruth = "unsigned short Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_H() throws Exception {
		mangled = "?Name@@3HA";
		msTruth = "int Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_I() throws Exception {
		mangled = "?Name@@3IA";
		msTruth = "unsigned int Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_J() throws Exception {
		mangled = "?Name@@3JA";
		msTruth = "long Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_K() throws Exception {
		mangled = "?Name@@3KA";
		msTruth = "unsigned long Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_M() throws Exception {
		mangled = "?Name@@3MA";
		msTruth = "float Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_N() throws Exception {
		mangled = "?Name@@3NA";
		msTruth = "double Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testBasicTypes_O() throws Exception {
		mangled = "?Name@@3OA";
		msTruth = "long double Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__D() throws Exception {
		mangled = "?Name@@3_DA";
		msTruth = "__int8 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__E() throws Exception {
		mangled = "?Name@@3_EA";
		msTruth = "unsigned __int8 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__F() throws Exception {
		mangled = "?Name@@3_FA";
		msTruth = "__int16 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__G() throws Exception {
		mangled = "?Name@@3_GA";
		msTruth = "unsigned __int16 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__H() throws Exception {
		mangled = "?Name@@3_HA";
		msTruth = "__int32 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__I() throws Exception {
		mangled = "?Name@@3_IA";
		msTruth = "unsigned __int32 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__J() throws Exception {
		mangled = "?Name@@3_JA";
		msTruth = "__int64 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__K() throws Exception {
		mangled = "?Name@@3_KA";
		msTruth = "unsigned __int64 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__L() throws Exception {
		mangled = "?Name@@3_LA";
		msTruth = "__int128 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__M() throws Exception {
		mangled = "?Name@@3_MA";
		msTruth = "unsigned __int128 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__N() throws Exception {
		mangled = "?Name@@3_NA";
		msTruth = "bool Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__P() throws Exception {
		mangled = "?Name@@3_PA";
		msTruth = "UNKNOWN Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__Q() throws Exception {
		mangled = "?Name@@3_QA";
		msTruth = "char8_t Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__R() throws Exception {
		mangled = "?Name@@3_RA";
		msTruth = "<unknown> Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__S() throws Exception {
		mangled = "?Name@@3_SA";
		msTruth = "char16_t Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__T() throws Exception {
		mangled = "?Name@@3_TA";
		msTruth = "UNKNOWN Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__U() throws Exception {
		mangled = "?Name@@3_UA";
		msTruth = "char32_t Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__V() throws Exception {
		mangled = "?Name@@3_VA";
		msTruth = "UNKNOWN Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testExtendedTypes__W() throws Exception {
		mangled = "?Name@@3_WA";
		msTruth = "wchar_t Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_w64prefix1() throws Exception {
		mangled = "?Name@@3_$HA";
		msTruth = "__w64 int Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_w64prefix2() throws Exception {
		mangled = "?Name@@3_$_$HA";
		msTruth = "__w64 __w64 int Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_w64prefix3() throws Exception {
		mangled = "?Name@@3_$_$PEB_$HA";
		msTruth = "__w64 __w64 __w64 int const * __ptr64 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_w64prefix4() throws Exception {
		mangled = "?Name@@3_$_$PEBPEB_$HA";
		msTruth = "__w64 __w64 __w64 int const * __ptr64 const * __ptr64 Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_w64prefix5() throws Exception {
		mangled = "?FnName@@YA_$PEB_$H_$_$PEB_$D@Z";
		msTruth =
			"__w64 __w64 int const * __ptr64 __cdecl FnName(__w64 __w64 __w64 char const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_T() throws Exception {
		mangled = "?VarName@SpaceName@@3TTypeName@TypeSpace@@FEIA";
		msTruth = "union TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_U() throws Exception {
		mangled = "?VarName@SpaceName@@3UTypeName@TypeSpace@@FEIA";
		msTruth = "struct TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_V() throws Exception {
		mangled = "?VarName@SpaceName@@3VTypeName@TypeSpace@@FEIA";
		msTruth = "class TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_L() throws Exception {
		//Seems that L is a complex type
		mangled = "?VarName@SpaceName@@3LTypeName@TypeSpace@@FEIA";
		msTruth = "TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//The coclass and cointerface symbols were all hand-mangled, which were then input to undname for truth
	//Could not find any in the wild.  Also, have yet to create C source that would
	// have coclass or cointerface types.

	@Test
	public void testComplexTypes__Y() throws Exception {
		mangled = "?VarName@SpaceName@@3_YTypeName@TypeSpace@@FEIA";
		msTruth =
			"cointerface TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes__X() throws Exception {
		mangled = "?VarName@SpaceName@@3_XTypeName@TypeSpace@@FEIA";
		msTruth = "coclass TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_Y() throws Exception {
		mangled = "?VarName@SpaceName@@3YTypeName@TypeSpace@@FEIA";
		msTruth =
			"cointerface TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_X() throws Exception {
		//TODO: Trying to find any symbol (with or without return type or pointer or ???) for which 'X' (coclass) works--no success yet (especially using undname!!!).
//		mangled = "?VarName@SpaceName@@3XTypeName@TypeSpace@@FEIA";
//		mstruth = "coclass TypeSpace::TypeName __unaligned __ptr64 __restrict SpaceName::VarName";
//		mdtruth = mstruth;
//		demangleAndTest();
	}

	@Test
	public void testComplexTypes_Yparam() throws Exception {
		mangled = "?FnName@@YAYRet@@YParam@@@Z";
		msTruth = "cointerface Ret __cdecl FnName(cointerface Param)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testComplexTypes_Xparam() throws Exception {
		mangled = "?FnName@@YA_XRet@@_XParam@@@Z";
		msTruth = "coclass Ret __cdecl FnName(coclass Param)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_P() throws Exception {
		mangled = "?FnName@@YAXPAH@Z";
		msTruth = "void __cdecl FnName(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_Q() throws Exception {
		mangled = "?FnName@@YAXQAH@Z";
		msTruth = "void __cdecl FnName(int * const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_R() throws Exception {
		mangled = "?FnName@@YAXRAH@Z";
		msTruth = "void __cdecl FnName(int * volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_S() throws Exception {
		mangled = "?FnName@@YAXSAH@Z";
		msTruth = "void __cdecl FnName(int * const volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_A() throws Exception {
		mangled = "?FnName@@YAXAAH@Z";
		msTruth = "void __cdecl FnName(int &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_B() throws Exception {
		mangled = "?FnName@@YAXBAH@Z";
		msTruth = "void __cdecl FnName(int & volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_P_WithModifierD() throws Exception {
		mangled = "?FnName@@YAXPDH@Z";
		msTruth = "void __cdecl FnName(int const volatile *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_S_WithModifierD() throws Exception {
		mangled = "?FnName@@YAXSDH@Z";
		msTruth = "void __cdecl FnName(int const volatile * const volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testModifierTypes_B_WithModifierD() throws Exception {
		mangled = "?FnName@@YAXBDH@Z";
		msTruth = "void __cdecl FnName(int const volatile & volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_B() throws Exception {
		mangled = "?VarName@@3HB";
		msTruth = "int const VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_C() throws Exception {
		mangled = "?VarName@@3HC";
		msTruth = "int volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_D() throws Exception {
		mangled = "?VarName@@3HD";
		msTruth = "int const volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_B_OnP() throws Exception {
		mangled = "?VarName@@3PBHA";
		msTruth = "int const * VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_B_onP_to_B_OnH() throws Exception {
		mangled = "?VarName@@3PBHB";
		msTruth = "int const * const VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_B_OnQ() throws Exception {
		mangled = "?VarName@@3QBHA";
		msTruth = "int const * VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_C_OnP_to_C_OnH() throws Exception {
		mangled = "?VarName@@3PCHC";
		msTruth = "int volatile * volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_D_OnP_to_D_OnH() throws Exception {
		mangled = "?VarName@@3PDHD";
		msTruth = "int const volatile * const volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_A_onP_to_C_OnH() throws Exception {
		mangled = "?VarName@@3PCHA";
		msTruth = "int volatile * VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_A_onP_to_D_OnH() throws Exception {
		mangled = "?VarName@@3PDHA";
		msTruth = "int const volatile * VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_C_onP_to_A_OnH() throws Exception {
		mangled = "?VarName@@3PAHC";
		msTruth = "int * volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_D_onP_to_A_OnH() throws Exception {
		mangled = "?VarName@@3PAHD";
		msTruth = "int * const volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_A_onQ_to_Arrayof_A_OnH() throws Exception {
		mangled = "?VarName@@3QAY01HA";
		msTruth = "int (* VarName)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedA() throws Exception {
		//A
		mangled = "?VarName@VarSpace@@3PEAHA";
		msTruth = "int * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//B, J block
	@Test
	public void testCVModifiers_modifiedB() throws Exception {
		mangled = "?VarName@VarSpace@@3PEBHA";
		msTruth = "int const * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedJ() throws Exception {
		mangled = "?VarName@VarSpace@@3PEJHA";
		msTruth = "int const * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//C, G, K block
	@Test
	public void testCVModifiers_modifiedC() throws Exception {
		mangled = "?VarName@VarSpace@@3PECHA";
		msTruth = "int volatile * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedG() throws Exception {
		mangled = "?VarName@VarSpace@@3PEGHA";
		ms2013Truth = "int volatile * __ptr64 VarSpace::VarName";
		msTruth = ""; //CVMod should error for 'H' on non-This pointer
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedK() throws Exception {
		mangled = "?VarName@VarSpace@@3PEKHA";
		msTruth = "int volatile * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//D, H, L block
	@Test
	public void testCVModifiers_modifiedD() throws Exception {
		mangled = "?VarName@VarSpace@@3PEDHA";
		msTruth = "int const volatile * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedH() throws Exception {
		mangled = "?VarName@VarSpace@@3PEHHA";
		ms2013Truth = "int const volatile * __ptr64 VarSpace::VarName";
		msTruth = ""; //CVMod should error for 'H' on non-This pointer
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedL() throws Exception {
		mangled = "?VarName@VarSpace@@3PELHA";
		msTruth = "int const volatile * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//M, N, O, P block
	@Test
	public void testCVModifiers_modifiedM() throws Exception {
		mangled = "?VarName@VarSpace@@3PEM0HA";
		msTruth = "int __based(void) * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedN() throws Exception {
		mangled = "?VarName@VarSpace@@3PEN0HA";
		msTruth = "int const __based(void) * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedO() throws Exception {
		mangled = "?VarName@VarSpace@@3PEO0HA";
		msTruth = "int volatile __based(void) * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedP() throws Exception {
		mangled = "?VarName@VarSpace@@3PEP0HA";
		msTruth = "int const volatile __based(void) * __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Q, U, Y block
	@Test
	public void testCVModifiers_modifiedQ() throws Exception {
		mangled = "?VarName@VarSpace@@3PEQClassName@@HA";
		msTruth = "int ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedU() throws Exception {
		mangled = "?VarName@VarSpace@@3PEUClassName@@HA";
		msTruth = "int ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedY() throws Exception {
		mangled = "?VarName@VarSpace@@3PEYClassName@@HA";
		msTruth = "int ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//R, V, Z block
	@Test
	public void testCVModifiers_modifiedR() throws Exception {
		mangled = "?VarName@VarSpace@@3PERClassName@@HA";
		msTruth = "int const ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedV() throws Exception {
		mangled = "?VarName@VarSpace@@3PEVClassName@@HA";
		msTruth = "int const ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedZ() throws Exception {
		mangled = "?VarName@VarSpace@@3PEZClassName@@HA";
		msTruth = "int const ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//S, W, 0 block
	@Test
	public void testCVModifiers_modifiedS() throws Exception {
		mangled = "?VarName@VarSpace@@3PESClassName@@HA";
		msTruth = "int volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedW() throws Exception {
		mangled = "?VarName@VarSpace@@3PEWClassName@@HA";
		msTruth = "int volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified0() throws Exception {
		mangled = "?VarName@VarSpace@@3PE0ClassName@@HA";
		msTruth = "int volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//T, X, 1 block
	@Test
	public void testCVModifiers_modifiedT() throws Exception {
		mangled = "?VarName@VarSpace@@3PETClassName@@HA";
		msTruth = "int const volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modifiedX() throws Exception {
		mangled = "?VarName@VarSpace@@3PEXClassName@@HA";
		msTruth = "int const volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified1() throws Exception {
		mangled = "?VarName@VarSpace@@3PE1ClassName@@HA";
		msTruth = "int const volatile ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//2, 3, 4 block
	@Test
	public void testCVModifiers_modified2() throws Exception {
		mangled = "?VarName@VarSpace@@3PE2ClassName@@0HA";
		msTruth = "int __based(void) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified3() throws Exception {
		mangled = "?VarName@VarSpace@@3PE3ClassName@@0HA";
		msTruth = "int const __based(void) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified4() throws Exception {
		mangled = "?VarName@VarSpace@@3PE4ClassName@@0HA";
		msTruth = "int volatile __based(void) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//5 and variation 0 on __based()
	@Test
	public void testCVModifiers_modified5_0() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@0HA";
		msTruth = "int const volatile __based(void) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//5 and variation 1 on __based()
	@Test
	public void testCVModifiers_modified5_1() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@1HA";
		msTruth = "int const volatile __based() ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//5 and variation 2 on __based()
	@Test
	public void testCVModifiers_modified5_2() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@2BasedPointer@BasedSpace@@HA";
		msTruth =
			"int const volatile __based(BasedSpace::BasedPointer) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//5 and variation 3 on __based()
	@Test
	public void testCVModifiers_modified5_3() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@3HA";
		msTruth = "int const volatile __based() ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//5 and variation 4 on __based()
	@Test
	public void testCVModifiers_modified5_4() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@4HA";
		msTruth = "int const volatile __based() ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified5_5() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@5HA";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//6, 7, 8, 9, _A, _B, _C, _D block
	@Test
	public void testCVModifiers_modified6() throws Exception {
		mangled = "?VarName@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified7() throws Exception {
		mangled = "?VarName@@3P7AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified8() throws Exception {
		mangled = "?VarName@@3P8ClassName@@EDAHXZED";
		msTruth =
			"int (__cdecl ClassName::*const volatile __ptr64 VarName)(void)const volatile __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified9_E() throws Exception {
		mangled = "?VarName@@3P9ClassName@@EDAHXZED";
		msTruth =
			"int (__cdecl ClassName::*const volatile __ptr64 VarName)(void)const volatile __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified9() throws Exception {
		mangled = "?VarName@@3P9ClassName@@DAHXZED";
		msTruth = "int (__cdecl ClassName::*const volatile __ptr64 VarName)(void)const volatile "; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified_A() throws Exception {
		mangled = "?VarName@@3P_A0AHH@ZEA";
		msTruth = "int (__cdecl __based(void) * __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified_B() throws Exception {
		mangled = "?VarName@@3P_B0AHH@ZEA";
		msTruth = "int (__cdecl __based(void) * __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified_C() throws Exception {
		mangled = "?VarName@@3P_CClassName@@D0AHH@ZEA";
		msTruth = "int (__cdecl __based(void) ClassName::* __ptr64 VarName)(int)const volatile "; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified_D() throws Exception {
		mangled = "?VarName@@3P_DClassName@@D0AHH@ZEA";
		msTruth = "int (__cdecl __based(void) ClassName::* __ptr64 VarName)(int)const volatile "; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiers_modified_D_ED() throws Exception {
		mangled = "?VarName@@3P_DClassName@@D0AHH@ZED";
		msTruth =
			"int (__cdecl __based(void) ClassName::*const volatile __ptr64 VarName)(int)const volatile "; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	//6 with const volatile __ptr64 'ED'
	@Test
	public void testCVModifiers_modified6_ED() throws Exception {
		mangled = "?VarName@@3P6AHH@ZED";
		msTruth = "int (__cdecl*const volatile __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//unaligned, restrict, ptr64, const, volatile
	@Test
	public void testCVModifiers() throws Exception {
		mangled = "?VarName@@3PEIFDHEIFD";
		msTruth =
			"int const volatile __unaligned * __ptr64 __restrict const volatile __unaligned __ptr64 __restrict VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//EI order matters
	@Test
	public void testCVModifiers_modified_EIorder() throws Exception {
		mangled = "?VarName@@3PEIAHA";
		msTruth = "int * __ptr64 __restrict VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//IE order matters
	@Test
	public void testCVModifiers_modified_IEorder() throws Exception {
		mangled = "?VarName@@3PIEAHA";
		msTruth = "int * __restrict __ptr64 VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//many Es and Is with order
	@Test
	public void testCVModifiers_modified_EEEIII() throws Exception {
		mangled = "?VarName@@3PEEEIIIEEEAHA";
		msTruth =
			"int * __ptr64 __ptr64 __ptr64 __restrict __restrict __restrict __ptr64 __ptr64 __ptr64 VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased0() throws Exception {
		mangled = "?Var@@3PBHA";
		msTruth = "int const * Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased1() throws Exception {
		mangled = "?Var@@3PAHN5";
		msTruth = "int * ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased2() throws Exception {
		mangled = "?Var@@3HN5";
		msTruth = "int ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased2a() throws Exception {
		mangled = "?Var@@3HN0";
		msTruth = "int const __based(void) Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased3() throws Exception {
		mangled = "?Var@@3PP5HA";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased3a() throws Exception {
		mangled = "?Var@@3PP0HA";
		msTruth = "int const volatile __based(void) * Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased3b() throws Exception {
		mangled = "?Var@@3PP5Y01HA";
		msTruth = "int [2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased4() throws Exception {
		mangled = "?Var@@3PP0Y01HP0";
		msTruth = "int (const volatile __based(void) * const volatile __based(void) Var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased5() throws Exception {
		mangled = "?Var@@3PP0Y01HP5";
		msTruth = "int (const volatile __based(void) * )[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased6() throws Exception {
		mangled = "?Var@@3PP5Y01HP0";
		msTruth = "int [2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased7() throws Exception {
		mangled = "?Var@@3P_CClass@@D0AHD@ZEP5";
		msTruth = "int (__cdecl __based(void) Class::*)(char)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased8() throws Exception {
		mangled = "?fn@@YAHPEIFN5H@Z";
		msTruth = "int __cdecl fn(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersMoreBased9() throws Exception {
		mangled = "?fn@@YAHSEIFN5H@Z";
		msTruth = "int __cdecl fn(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Test C-V Modifiers __based() variation.
	// TODO:
	// More investigation required.  For __based(), code 5 is supposed to remove the __based() property (according to standard document).
	// For undname, the code 5 seems to work for the `RTTI Type Descriptor' below, but it also removes the const volatile.
	// However, for undname, the __based() is not removed for the non-RTTI object.  This is just data gathering phase of the investigation.
	// We have not yet implemented any code in MDMang to remove the __based() property, as we do not have enough understanding of the
	// cases involved.
	// Upon reading the bible document, I found more under "Function" talking about __based.  I've implemented a test of that below.  I was
	// able to create a __based(void) function using the underscore (_) method.  I then changed the __based code to 5, and I see that
	// it removed this: "__cdecl __based(void)"  The underscore code is not implemented--the "Function" section needs to be codified better.
	// I tried the underscore on a simple data type below as well.  See the "truth" presented there.  The underscore seemed to have no effect,
	// even on a pointer.
	@Test
	public void testCVModifiersBased5_Variation_aaa1() throws Exception {
		mangled = "?Var@@3_OBHN0";
		msTruth = "int const __based(void) Var[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_aaa2() throws Exception {
		mangled = "?Var@@3_OBHN5";
		msTruth = "int []";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_aa1() throws Exception {
		mangled = "?Var@@3PAHN0";
		msTruth = "int * const __based(void) Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_aa2() throws Exception {
		mangled = "?Var@@3PAHN5";
		msTruth = "int * ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ab() throws Exception {
		mangled = "?Var@@3HN5";
		msTruth = "int ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ac() throws Exception {
		mangled = "?Var@@3PP5HA";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ad() throws Exception {
		mangled = "?Var@@3PEP5HEP0";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ae() throws Exception {
		mangled = "?Var@@3QP0Y01HP0";
		msTruth = "int (const volatile __based(void) * const volatile __based(void) Var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_af() throws Exception {
		mangled = "?Var@@3QP0Y01HP5";
		msTruth = "int (const volatile __based(void) * )[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ag() throws Exception {
		mangled = "?Var@@3QP5Y01HP0";
		msTruth = "int [2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ah() throws Exception {
		mangled = "?Var@@3P_CClass@@D0AHD@ZEP0";
		msTruth =
			"int (__cdecl __based(void) Class::*const volatile __based(void) __ptr64 Var)(char)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ai() throws Exception {
		mangled = "?Var@@3P_CClass@@D0AHD@ZEP5";
		msTruth = "int (__cdecl __based(void) Class::*)(char)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//This test seems to dictate that a function pointer should be elaborated internal to CVMod, where the based5 will eliminate all of the function context.
	//  It also seems to indicate that the "int" portion would be the referred-to type and the rest of the function spec would be part of the the function info.
	//  Other information at one time, led me to believe that the return type of a function is special... need to rekinkdle those thoughts, but think related to nested
	//  functions, such as function returning a function pointer..
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testCVModifiersBased5_Variation_aj() throws Exception {
		mangled = "?Var@@3P_CClass@@D5AHD@ZEP0";
		msTruth = "int ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ak() throws Exception {
		mangled = "?Var@@3PEP0HEP0";
		msTruth =
			"int const volatile __based(void) * __ptr64 const volatile __based(void) __ptr64 Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_al() throws Exception {
		mangled = "?Var@@3PEP0HEP5";
		msTruth = "int const volatile __based(void) * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_am() throws Exception {
		mangled = "?Var@@3PEP5HEP0";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_an() throws Exception {
		mangled = "?Var@@3PEBHN5";
		msTruth = "int const * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ao() throws Exception {
		mangled = "??_R0?PAVname0@@@8";
		msTruth = "class name0 const volatile __based() `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ap() throws Exception {
		mangled = "??_R0?P5Vname0@@@8";
		msTruth = "class name0 `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured.
	@Test
	public void testCVModifiersBased5_Variation_aq() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@5HA";
		msTruth = "int"; //20160615 correction
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured.  Added as counterpoint to the above test.
	@Test
	public void testCVModifiersBased5_Variation_aq_0() throws Exception {
		mangled = "?VarName@VarSpace@@3PE5ClassName@@0HA";
		msTruth = "int const volatile __based(void) ClassName::* __ptr64 VarSpace::VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ar() throws Exception {
		mangled = "?FnName@@YAXPAH@Z";
		msTruth = "void __cdecl FnName(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_au() throws Exception {
		mangled = "?Var@@3HA";
		msTruth = "int Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_aw() throws Exception {
		mangled = "?Var@@3HN5";
		msTruth = "int ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ax() throws Exception {
		mangled = "?Var@@3PEBHN0";
		msTruth = "int const * __ptr64 const __based(void) Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ay() throws Exception {
		mangled = "?Var@@3PEBHN5";
		msTruth = "int const * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_az() throws Exception {
		mangled = "?Var@@3PEP0HEP0";
		msTruth =
			"int const volatile __based(void) * __ptr64 const volatile __based(void) __ptr64 Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_ba() throws Exception {
		mangled = "?Var@@3PEP0HEP5";
		msTruth = "int const volatile __based(void) * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_bb() throws Exception {
		mangled = "?Var@@3PEP5HEP0";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_bc() throws Exception {
		mangled = "?Var@@3P_CClass@@D0AHD@ZEP0";
		msTruth =
			"int (__cdecl __based(void) Class::*const volatile __based(void) __ptr64 Var)(char)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModifiersBased5_Variation_bd() throws Exception {
		mangled = "?Var@@3P_CClass@@D0AHD@ZEP5";
		msTruth = "int (__cdecl __based(void) Class::*)(char)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testCVModifiersBased5_Variation_be() throws Exception {
		mangled = "?Var@@3P_CClass@@D5AHD@ZEP0";
		msTruth = "int ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_chartype() throws Exception {
		mangled = "?enumvar@@3W0enumname@enumspace@@A";
		msTruth = "enum char enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_unsignedchartype() throws Exception {
		mangled = "?enumvar@@3W1enumname@enumspace@@A";
		msTruth = "enum unsigned char enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_shorttype() throws Exception {
		mangled = "?enumvar@@3W2enumname@enumspace@@A";
		msTruth = "enum short enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_unsignedshorttype() throws Exception {
		mangled = "?enumvar@@3W3enumname@enumspace@@A";
		msTruth = "enum unsigned short enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_inttype() throws Exception {
		mangled = "?enumvar@@3W4enumname@enumspace@@A";
		msTruth = "enum enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_unsignedinttype() throws Exception {
		mangled = "?enumvar@@3W5enumname@enumspace@@A";
		msTruth = "enum unsigned int enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_longtype() throws Exception {
		mangled = "?enumvar@@3W6enumname@enumspace@@A";
		msTruth = "enum long enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEnums_unsignedlongtype() throws Exception {
		mangled = "?enumvar@@3W7enumname@enumspace@@A";
		msTruth = "enum unsigned long enumspace::enumname enumvar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_metatype8() throws Exception {
		mangled = "?Var@Namespace@@8";
		msTruth = "Namespace::Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_guard5() throws Exception {
		mangled = "?Var@Namespace@@51";
		msTruth = "Namespace::Var{2}'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_1a() throws Exception {
		mangled = "?name0@name1@@1Uname2@@A";
		msTruth = "protected: static struct name2 name1::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_1b() throws Exception {
		mangled = "?name0@name1@@1PAUname2@1@A";
		msTruth = "protected: static struct name1::name2 * name1::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// O,P (don't have a P yet) block
	@Test
	public void testAccessLevels_Oa() throws Exception {
		mangled = "?name0@name1@@O7EAAKXZ";
		msTruth =
			"[thunk]:protected: virtual unsigned long __cdecl name1::name0`adjustor{8}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_Ob() throws Exception {
		mangled = "?name0@name1@@OBA@EAAKXZ";
		msTruth =
			"[thunk]:protected: virtual unsigned long __cdecl name1::name0`adjustor{16}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// W,X (don't have an X yet) block
	@Test
	public void testAccessLevels_Wa() throws Exception {
		mangled = "?name0@name1@@W7EAAJAEBUname2@@@Z";
		msTruth =
			"[thunk]:public: virtual long __cdecl name1::name0`adjustor{8}' (struct name2 const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_Wb() throws Exception {
		mangled = "?name0@name1@@W7EAAJXZ";
		msTruth = "[thunk]:public: virtual long __cdecl name1::name0`adjustor{8}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// $0,$1 (don't have a $1 yet) block
	@Test
	public void testAccessLevels_dollar0() throws Exception {
		mangled = "?name0@name1@@$0PPPPPPPM@A@EAAKAEAKAEAPEAG@Z";
		msTruth =
			"[thunk]:private: virtual unsigned long __cdecl name1::name0`vtordisp{4294967292,0}' (unsigned long & __ptr64,unsigned short * __ptr64 & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// $2,$3 (don't have a $3 yet) block
	@Test
	public void testAccessLevels_dollar2a() throws Exception {
		mangled = "?name0@name1@@$2PPPPPPPM@7EAAJXZ";
		msTruth =
			"[thunk]:protected: virtual long __cdecl name1::name0`vtordisp{4294967292,8}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_dollar2b() throws Exception {
		mangled = "?name0@name1@@$2PPPPPPPM@BI@EAAJXZ";
		msTruth =
			"[thunk]:protected: virtual long __cdecl name1::name0`vtordisp{4294967292,24}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R2, real a
	@Test
	public void testAccessLevels_dollarR2a() throws Exception {
		mangled = "?name0@name1@name2@@$R2BAA@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:protected: virtual void __cdecl name2::name1::name0`vtordispex{256,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R2, real b
	@Test
	public void testAccessLevels_dollarR2b() throws Exception {
		mangled = "?name0@name1@name2@@$R2BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:protected: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R3, manufactured from $R2
	@Test
	public void testAccessLevels_dollarR3() throws Exception {
		mangled = "?name0@name1@name2@@$R3BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:protected: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R0, manufactured from $R2
	@Test
	public void testAccessLevels_dollarR0() throws Exception {
		mangled = "?name0@name1@name2@@$R0BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:private: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R1, manufactured from $R2
	@Test
	public void testAccessLevels_dollarR1() throws Exception {
		mangled = "?name0@name1@name2@@$R1BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:private: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R4, manufactured from $R2
	@Test
	public void testAccessLevels_dollarR4() throws Exception {
		mangled = "?name0@name1@name2@@$R4BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:public: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$R5, manufactured from $R2
	@Test
	public void testAccessLevels_dollarR5() throws Exception {
		mangled = "?name0@name1@name2@@$R5BI@7PPPPPPPM@BAI@EAAXXZ";
		msTruth =
			"[thunk]:public: virtual void __cdecl name2::name1::name0`vtordispex{24,8,4294967292,264}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B, real a
	@Test
	public void testAccessLevels_dollarBa() throws Exception {
		mangled = "??_9name0@@$BBII@AA";
		msTruth = "[thunk]: __cdecl name0::`vcall'{392,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B, real b
	@Test
	public void testAccessLevels_dollarBb() throws Exception {
		mangled = "??_7?$name0@H$H??_9name1@@$BHI@AAA@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',0}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B, real c
	@Test
	public void testAccessLevels_dollarBc() throws Exception {
		mangled = "??1?$name0@Uname1@@P81@EAAJXZ$1??_91@$BCA@AA@@QEAA@XZ";
		msTruth =
			"public: __cdecl name0<struct name1,long (__cdecl name1::*)(void) __ptr64,&[thunk]: __cdecl name1::`vcall'{32,{flat}}' }'>::~name0<struct name1,long (__cdecl name1::*)(void) __ptr64,&[thunk]: __cdecl name1::`vcall'{32,{flat}}' }'>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO 20160615: Moved from Base5... These are related to "based" but seem to happen from Access level
	//  parsing.  I forget how I found these--fuzzing or other.  These are not working, but require
	//  more investigation.  Compare with "?FnName@@YAXPAH@Z" (remove Y and 0)
	@Test
	public void testAccessLevels_underscore_based0_globalfunction() throws Exception {
		mangled = "?FnName@@_Y0AXPAH@Z";
		msTruth = "void __cdecl __based(void) FnName(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO 20170419: Likely fix is to do what is indicated below for testAccessLevels_basedG()
	//TODO 20160615: Moved from Base5... These are related to "based" but seem to happen from Access level
	//  parsing.  I forget how I found these--fuzzing or other.  These are not working, but require
	//  more investigation.  Compare with "?FnName@@YAXPAH@Z" (remove Y and 5)
	@Test
	public void testAccessLevels_underscore_based5_globalfunction() throws Exception {
		mangled = "?FnName@@_Y5AXPAH@Z";
		msTruth = "void FnName(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO 20160615: Moved from Base5... These are related to "based" but seem to happen from Access level
	//  parsing.  I forget how I found these--fuzzing or other.  These are not working, but require
	//  more investigation.  This one is counterpoint to "based"
	@Test
	public void testAccessLevels_underscore_based0_data() throws Exception {
		mangled = "?Var@@_3HA";  //should be "?Var@@_30HA"
		msTruth = "int Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured from other.
	@Test
	public void testAccessLevels_underscore_based0_vtordisp() throws Exception {
		mangled = "?name0@name1@@_$40PPPPPPPM@A@EAAJUname2@@HPEBGPEAPEAGK2KK1PEAEKPEAVname3@@@Z";
		msTruth =
			"[thunk]:public: virtual long __cdecl __based(void) name1::name0`vtordisp{4294967292,0}' (struct name2,int,unsigned short const * __ptr64,unsigned short * __ptr64 * __ptr64,unsigned long,unsigned short * __ptr64 * __ptr64,unsigned long,unsigned long,unsigned short const * __ptr64,unsigned char * __ptr64,unsigned long,class name3 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured from other.
	@Test
	public void testAccessLevels_underscore_based0_vtordispex() throws Exception {
		mangled = "??_9testAccessLevel@@_$R50A@B@C@D@AA@H@HH@";
		msTruth =
			"[thunk]:public: virtual __cdecl __based(void) testAccessLevel::`vcall'`vtordispex{0,1,2,3}' (int) throw(int,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAccessLevels_based0_guard() throws Exception {
		mangled = "?Var@Namespace@@51";
		msTruth = "Namespace::Var{2}'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testAccessLevels_based0_vftable() throws Exception {
		mangled = "??_7a@b@@6B@";
		msTruth = "const b::a::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testAccessLevels_based0_vftable_fuzz_for_unprocessed_terminating_at()
			throws Exception {
		mangled = "??_7a@b@@6Bx@xx@@y@yy@@@";
		msTruth = "const b::a::`vftable'{for `xx::x's `yy::y'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured.  Note that the following work:
	//   C, D, K, L, S, T, which are all static member functions
	@Test
	public void testAccessLevels_based0_staticmember() throws Exception {
		mangled = "?FnName@@_C0AXPAH@Z";
		msTruth = "private: static void __cdecl __based(void) FnName(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO 20170419: Problem is that I put MDBasedType inside of MDType, but then MDAdjustor extends
	//  MDFunctionType, which parses super() (MDFunctionType) after parsing the Adjustor values.  Real
	//  solution is likely that all MDType parsing/outputting needs to be in MDTypeInfo (at the opposite
	//  end of the spectrum).
	//Manufactured.  Note that the following work:
	//   G, H, O, P, W, X, which are all adjustor functions (probably non-displaying static)
	@Test
	public void testAccessLevels_basedG() throws Exception {
		mangled = "?FnName@@_G0BA@EAAHXZ";
		msTruth =
			"[thunk]:private: virtual int __cdecl __based(void) FnName`adjustor{16}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSimpleTemplate() throws Exception {
		mangled = "?Ti@@3V?$Tc@H@@A";
		msTruth = "class Tc<int> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured to show that whole MDTemplateNameAndArgumentsList is a valid name backref.
	@Test
	public void testTemplateBackrefOfWholeTemplateAsQual() throws Exception {
		mangled = "?Ti@@3V?$Tc@H@1@A";
		msTruth = "class Tc<int>::Tc<int> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSimpleTemplateMain() throws Exception {
		mangled = "?$Tc@H";
		msTruth = "Tc<int>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSimpleTemplateMainBetter() throws Exception {
		mangled = "?$Tc@HH";
		msTruth = "Tc<int,int>";
		mdTruth = msTruth;
		demangleAndTest();
	}

//Invalid test: remains of 3 or 4 for high level template--never have scope opportunity to retrieve a backreference
//	@Test
//	public void testSimpleTemplateMainBackrefOfWholeTemplate() throws Exception {
//		mangled = "?$Tc@H@0@A"; //backref does nothing by microsoft or by this stuff (can change backref to any number and get same).
//		mstruth = "Tc<int>";
//		mdtruth = mstruth;
//		demangleAndTest();
//	}

	@Test
	public void testTemplateAsTemplateParameter() throws Exception {
		mangled = "?Ti@@3V?$Tc@V?$Tb@H@@@@A";
		msTruth = "class Tc<class Tb<int> > Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured 20170512: to test MDTemplateNameAndArguments inside of MDReusableName and gets put into backreference names.
	@Test
	public void testTemplateInReusableInQual() throws Exception {
		mangled = "?Var@?I?$templatename@H@1@3HA";
		msTruth = "int templatename<int>[::templatename<int>]::Var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: ?#
	@Test
	public void testSpecialTemplateParameters_questionnumber() throws Exception {
		mangled = "??0?$name0@?0Uname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<`template-parameter-1',struct name1>::name0<`template-parameter-1',struct name1>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $0
	@Test
	public void testSpecialTemplateParameters_dollar0() throws Exception {
		mangled =
			"??$?0V?$A@_NABW4B@C@@@D@E@@@?$F@V?$G@U?$H@Q6A_NABW4B@C@@@Z$0A@@D@E@@_NABW4B@C@@@D@E@@@E@@QAE@ABV?$F@V?$A@_NABW4B@C@@@D@E@@@1@@Z";
		msTruth =
			"public: __thiscall E::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> >::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >(class E::F<class E::D::A<bool,enum C::B const &> > const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $1
	@Test
	public void testSpecialTemplateParameters_dollar1() throws Exception {
		mangled = "??0?$name0@Vname1@@$1?name2@@3Uname3@@B$1?name4@@3QBGB@@QEAA@XZ";
		msTruth =
			"public: __cdecl name0<class name1,&struct name3 const name2,&unsigned short const * const name4>::name0<class name1,&struct name3 const name2,&unsigned short const * const name4>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Blank (zero) exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_blankzeroexp() throws Exception {
		mangled = "??$F@$2B@@@@QAE@@Z";
		msTruth = "public: __thiscall F<1.e0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple mantissa and simple exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplemant_simpleexp() throws Exception {
		mangled = "??$F@$2B@B@@@QAE@@Z";
		msTruth = "public: __thiscall F<1.e1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Bigger more mantissa and simple exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_complexmant_simpleexp() throws Exception {
		mangled = "??$F@$2BB@B@@@QAE@@Z";
		msTruth = "public: __thiscall F<1.7e1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Bigger more mantissa and simple exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_negcomplexmant_simpleexp() throws Exception {
		mangled = "??$F@$2?BB@B@@@QAE@@Z";
		msTruth = "public: __thiscall F<-1.7e1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple mantissa and simple negative exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplemant_negexp() throws Exception {
		mangled = "??$F@$2B@?B@@@QAE@@Z";
		msTruth = "public: __thiscall F<1.e-1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple negative mantissa and simple exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_negmant_simpleexp() throws Exception {
		mangled = "??$F@$2?B@B@@@QAE@@Z";
		msTruth = "public: __thiscall F<-1.e1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple negative mantissa and simple negative exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_negmant_negexp() throws Exception {
		mangled = "??$F@$2?B@?B@@@QAE@@Z";
		msTruth = "public: __thiscall F<-1.e-1>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple zero mantissa and simple zero exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplezeromant_simplezeroexp()
			throws Exception {
		mangled = "??$F@$2A@A@@@QAE@@Z";
		msTruth = "public: __thiscall F<0.e0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple zero mantissa and blank (zero) exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplezeromant_blankzeroexp()
			throws Exception {
		mangled = "??$F@$2A@@@@QAE@@Z";
		msTruth = "public: __thiscall F<0.e0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Blank (zero) mantissa and simple zero exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_blankzeromant_simplezeroexp()
			throws Exception {
		mangled = "??$F@$2@A@@@QAE@@Z";
		msTruth = "public: __thiscall F<0.e0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Blank (zero) mantissa and blank (zero) exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_blankzeromant_blankzeroexp()
			throws Exception {
		mangled = "??$F@$2@@@@QAE@@Z";
		msTruth = "public: __thiscall F<0.e0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple negative zero mantissa and simple negative zero exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplenegzeromant_simplenegzeroexp()
			throws Exception {
		mangled = "??$F@$2?A@?A@@@QAE@@Z";
		msTruth = "public: __thiscall F<-0.e-0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $2 Simple negative blank (zero) mantissa and simple negative blank (zero) exponent
	@Test
	public void testSpecialTemplateParameters_dollar2_simplenegblankzeromant_simplenegblankzeroexp()
			throws Exception {
		mangled = "??$F@$2?@?@@@QAE@@Z";
		msTruth = "public: __thiscall F<-0.e-0>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $D
	@Test
	public void testSpecialTemplateParameters_dollarD() throws Exception {
		mangled = "??0?$name0@$D0Uname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<`template-parameter1',struct name1>::name0<`template-parameter1',struct name1>(void) __ptr64";
		mangled = "??0?$allocator@$D0U_GUID@@@std@@QEAA@XZ";
		msTruth =
			"public: __cdecl std::allocator<`template-parameter1',struct _GUID>::allocator<`template-parameter1',struct _GUID>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $E
	@Test
	public void testSpecialTemplateParameters_dollarE() throws Exception {
		mangled = "??0?$name0@V?$name1@Vname2@@$E?name3@@3Uname4@@B@@@name5@@QEAA@PEAX@Z";
		msTruth =
			"public: __cdecl name5::name0<class name1<class name2,struct name4 const name3> >::name0<class name1<class name2,struct name4 const name3> >(void * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $F Simple zero and zero parameters
	@Test
	public void testSpecialTemplateParameters_dollarF_zero_zero() throws Exception {
		mangled = "??$F@$FA@A@@@QAE@@Z";
		msTruth = "public: __thiscall F<{0,0}>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $F Simple negative zero and negative zero parameters
	@Test
	public void testSpecialTemplateParameters_dollarF_negzero_negzero() throws Exception {
		mangled = "??$F@$F?A@?A@@@QAE@@Z";
		msTruth = "public: __thiscall F<{-0,-0}>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $G Simple zero, zero, and zero parameters
	@Test
	public void testSpecialTemplateParameters_dollarF_zero_zero_zero() throws Exception {
		mangled = "??$F@$GA@A@A@@@QAE@@Z";
		msTruth = "public: __thiscall F<{0,0,0}>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $G Simple negative zero, negative zero, and negative zero parameters
	@Test
	public void testSpecialTemplateParameters_dollarF_negzero_negzero_negzero() throws Exception {
		mangled = "??$F@$G?A@?A@?A@@@QAE@@Z";
		msTruth = "public: __thiscall F<{-0,-0,-0}>()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $H
	@Test
	public void testSpecialTemplateParameters_dollarH_zero() throws Exception {
		mangled = "??_7?$name0@H$H??_9name1@@$BHI@AA?B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',-1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $H (from $H)
	@Test
	public void testSpecialTemplateParameters_dollarH_one() throws Exception {
		mangled = "??_7?$name0@H$H??_9name1@@$BHI@AA?B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',-1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $I (from $H)
	@Test
	public void testSpecialTemplateParameters_dollarH_one_one() throws Exception {
		mangled = "??_7?$name0@H$I??_9name1@@$BHI@AAB@B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',1,1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $I (from $H)
	@Test
	public void testSpecialTemplateParameters_dollarH_negone_negone() throws Exception {
		mangled = "??_7?$name0@H$I??_9name1@@$BHI@AA?B@?B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',-1,-1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $J (from $H)
	@Test
	public void testSpecialTemplateParameters_dollarJ() throws Exception {
		mangled = "??_7?$name0@H$J??_9name1@@$BHI@AAB@B@B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',1,1,1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol: $J (from $H)
	@Test
	public void testSpecialTemplateParameters_dollarJ_with_negs() throws Exception {
		mangled = "??_7?$name0@H$J??_9name1@@$BHI@AA?B@?B@?B@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',-1,-1,-1}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();

	}

	//TODO: Are there others, such as $K, $L, $M, $N, $O, $P ???

	//real symbol: $Q
	@Test
	public void testSpecialTemplateParameters_dollarQ() throws Exception {
		mangled = "??0?$name0@$Q0Uname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<`non-type-template-parameter1',struct name1>::name0<`non-type-template-parameter1',struct name1>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol: $R
	@Test
	public void testSpecialTemplateParameters_dollarR() throws Exception {
		mangled = "??0?$name0@$Rname1@EAAABAAB@@name2@name3@name4@name5@@$$FQE$AAM@AE$AAV01234@@Z";
		msTruth =
			"public: __clrcall name5::name4::name3::name2::name0<name1>::name0<name1>(class name5::name4::name3::name2::name0<name1> % __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testFunctionParameter_BQRS_DirectArgModifiers() throws Exception {
		//BQRS modifiers are only valid on direct arguments of functions and templates.
		mangled = "?main@@YAHHPEAPEADQEAPEADREAPEADSEAPEADAEAPEADBEAPEAD@Z";
		msTruth =
			"int __cdecl main(int,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64 const,char * __ptr64 * __ptr64 volatile,char * __ptr64 * __ptr64 const volatile,char * __ptr64 & __ptr64,char * __ptr64 & __ptr64 volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testFunctionParameter_BQRS_NonDirectArgModifiers() throws Exception {
		//BQRS modifiers are only valid on direct arguments of functions and templates.
		// Cannot have "pointer to reference" or "reference to reference," so cannot test these non-direct cases.
		mangled = "?main@@YAHHPEAPEADPEAQEADPEAREADPEASEAD@Z";
		msTruth =
			"int __cdecl main(int,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testTemplateParameter_BQRS_DirectArgModifiers() throws Exception {
		//BQRS modifiers are only valid on direct arguments of functions and templates.
		mangled = "?Ti@@3V?$Tc@PEAPEADQEAPEADREAPEADSEAPEADAEAPEADBEAPEAD@@A";
		msTruth =
			"class Tc<char * __ptr64 * __ptr64,char * __ptr64 * __ptr64 const,char * __ptr64 * __ptr64 volatile,char * __ptr64 * __ptr64 const volatile,char * __ptr64 & __ptr64,char * __ptr64 & __ptr64 volatile> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testTemplateParameter_BQRS_NonDirectArgModifiers() throws Exception {
		//BQRS modifiers are only valid on direct arguments of functions and templates.
		// Cannot have "pointer to reference" or "reference to reference," so cannot test these non-direct cases.
		mangled = "?Ti@@3V?$Tc@PEAPEADPEAQEADPEAREADPEASEAD@@A";
		msTruth =
			"class Tc<char * __ptr64 * __ptr64,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64,char * __ptr64 * __ptr64> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testParameterConst_FunctionDirectArg() throws Exception {
		//When can P,Q:const,R:volatile,S:const volatile be seen in arguments emission?
		// Seems that these are used and stored when Direct Argument (not a referred to type within an argument)
		//  of a function.  TODO: seems that for a modified type in a template, there is an issue--checking this 20140521
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testParameterConst_TemplateDirectArg() throws Exception {
		//When can P,Q:const,R:volatile,S:const volatile be seen in arguments emission?
		// Seems that these are used and stored when Direct Argument (not a referred to type within an argument)
		//  of a function.  TODO: seems that for a modified type in a template, there is an issue--checking this 20140521
		mangled = "??0?$name0@Vname1@@$1?name2@@3Uname3@@B$1?name4@@3QBGB@@QEAA@XZ";
		msTruth =
			"public: __cdecl name0<class name1,&struct name3 const name2,&unsigned short const * const name4>::name0<class name1,&struct name3 const name2,&unsigned short const * const name4>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testTemplateParameterVoid() throws Exception {
		//The "void" argument can be the first in a template arguments list, and still needs an '@' terminator for the list.
		mangled = "?Ti@@3V?$Tc@X@@A";
		msTruth = "class Tc<void> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testTemplateParameterVoidVoid() throws Exception {
		//Testing "void" as the first and second arguments of a template.
		mangled = "?Ti@@3V?$Tc@XX@@A";
		msTruth = "class Tc<void,void> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//A,B: __cdecl block
	@Test
	public void testFunctionCallingConventions_A__cdecl() throws Exception {
		mangled = "?fnii@@YAHH@Z";
		msTruth = "int __cdecl fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_B__cdecl() throws Exception {
		mangled = "?fnii@@YBHH@Z";
		msTruth = "int __cdecl fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//C,D: __pascal block
	@Test
	public void testFunctionCallingConventions_C__pascal() throws Exception {
		mangled = "?fnii@@YCHH@Z";
		msTruth = "int __pascal fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_D__pascal() throws Exception {
		mangled = "?fnii@@YDHH@Z";
		msTruth = "int __pascal fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//E,F: __thiscall block
	@Test
	public void testFunctionCallingConventions_E__thiscall() throws Exception {
		mangled = "?fnii@@YEHH@Z";
		msTruth = "int __thiscall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_F__thiscall() throws Exception {
		mangled = "?fnii@@YFHH@Z";
		msTruth = "int __thiscall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//G,H: __stdcall block
	@Test
	public void testFunctionCallingConventions_G__stdcall() throws Exception {
		mangled = "?fnii@@YGHH@Z";
		msTruth = "int __stdcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_H__stdcall() throws Exception {
		mangled = "?fnii@@YHHH@Z";
		msTruth = "int __stdcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//I,J: __fastcall block
	@Test
	public void testFunctionCallingConventions_I__fastcall() throws Exception {
		mangled = "?fnii@@YIHH@Z";
		msTruth = "int __fastcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_J__fastcall() throws Exception {
		mangled = "?fnii@@YJHH@Z";
		msTruth = "int __fastcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//K,L: blank block
	@Test
	public void testFunctionCallingConventions_K() throws Exception {
		mangled = "?fnii@@YKHH@Z";
		msTruth = "int fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_L() throws Exception {
		mangled = "?fnii@@YLHH@Z";
		msTruth = "int fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//M,N: __clrcall block
	@Test
	public void testFunctionCallingConventions_M__clrcall() throws Exception {
		mangled = "?fnii@@YMHH@Z";
		msTruth = "int __clrcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_N__clrcall() throws Exception {
		mangled = "?fnii@@YNHH@Z";
		msTruth = "int __clrcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//O,P: __eabi block
	@Test
	public void testFunctionCallingConventions_O__eabi() throws Exception {
		mangled = "?fnii@@YOHH@Z";
		msTruth = "int __eabi fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionCallingConventions_P___eabi() throws Exception {
		mangled = "?fnii@@YPHH@Z";
		msTruth = "int __eabi fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Q: __vectorcall block
	@Test
	public void testFunctionCallingConventions_Q__vectorcall() throws Exception {
		mangled = "?fnii@@YQHH@Z";
		msTruth = "int __vectorcall fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionThrow_a() throws Exception {
		mangled = "?fnii@@YAHH@@";
		msTruth = "int __cdecl fnii(int) throw()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionThrow_b() throws Exception {
		mangled = "?fnii@@YAHH@HH@";
		msTruth = "int __cdecl fnii(int) throw(int,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionNoReturnNotVoid() throws Exception {
		mangled = "?fnii@@YA@H@Z";
		msTruth = "__cdecl fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Having Void (X) for the first argument terminates the list and an '@' terminator is an error--so we should not error here.
	@Test
	public void testFunctionArgumentsVoidOnlyNoList() throws Exception {
		mangled = "?fn@@YAHXZ";
		msTruth = "int __cdecl fn(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Having Void (X) for the first argument terminates the list and an '@' terminator is an error--so we should error here.
	@Test
	public void testFunctionArgumentsVoidOnlyInList() throws Exception {
		mangled = "?fn@@YAHX@Z";
		msTruth = "?fn@@YAHX@Z";
		mdTruth = "";
		demangleAndTest();
	}

	//Having Void (X) after the first argument is allows, and it does not terminate the list.
	@Test
	public void testFunctionArgumentsVoidNotFirstInList() throws Exception {
		mangled = "?fn@@YAHHXH@Z";
		msTruth = "int __cdecl fn(int,void,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testFunctionBackrefArgs_0() throws Exception {
		mangled = "?fn@@YAHAAHBAHCDEFGHIJKLabc@@MNOPAHQAHRAHSAHTdef@@Ughi@@Vjkl@@0123456789@Z";
		msTruth =
			"int __cdecl fn(int &,int & volatile,signed char,char,unsigned char,short,unsigned short,int,unsigned int,long,unsigned long,abc,float,double,long double,int *,int * const,int * volatile,int * const volatile,union def,struct ghi,class jkl,int &,int & volatile,abc,int *,int * const,int * volatile,int * const volatile,union def,struct ghi,class jkl)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testFunctionBackrefArgs_1() throws Exception {
		mangled = "?fn@@YAHW0mno@@XYpqr@@_$H_D_E_F_G_H_I_J0123456789@Z";
		msTruth =
			"int __cdecl fn(enum char mno,void,cointerface pqr,__w64 int,__int8,unsigned __int8,__int16,unsigned __int16,__int32,unsigned __int32,__int64,enum char mno,cointerface pqr,__w64 int,__int8,unsigned __int8,__int16,unsigned __int16,__int32,unsigned __int32,__int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testFunctionBackrefArgs_2() throws Exception {
		mangled = "?fn@@YAH_K_L_M_N_OAH_W_Xstu@@_Yvwx@@01234567@Z";
		msTruth =
			"int __cdecl fn(unsigned __int64,__int128,unsigned __int128,bool,int[],wchar_t,coclass stu,cointerface vwx,unsigned __int64,__int128,unsigned __int128,bool,int[],wchar_t,coclass stu,cointerface vwx)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; demonstrates problem in TemplateBackrefArgs more succinctly.
	@Test
	public void testTemplateBackrefArgs_comma_problem() throws Exception {
		mangled = "?Ti@@3V?$Tc@VAAA@@00@@A";
		msTruth = "class Tc<class AAAclass AAAclass AAA> Ti";
		mdTruth = "class Tc<class AAA,class AAA,class AAA> Ti";
		demangleAndTest();
	}

	//Manufactured; Keep. Have not seen real examples, but undname works this way.
	@Test
	public void testTemplateBackrefArgs_0() throws Exception {
		mangled = "?Ti@@3V?$Tc@AAHBAHCDEFGHIJKLabc@@MNOPAHQAHRAHSAHTdef@@Ughi@@Vjkl@@0123456789@@A";
		msTruth =
			"class Tc<int &,int & volatile,signed char,char,unsigned char,short,unsigned short,int,unsigned int,long,unsigned long,abc,float,double,long double,int *,int * const,int * volatile,int * const volatile,union def,struct ghi,class jklint &int & volatileabcint *int * constint * volatileint * const volatileunion defstruct ghiclass jkl> Ti";
		mdTruth =
			"class Tc<int &,int & volatile,signed char,char,unsigned char,short,unsigned short,int,unsigned int,long,unsigned long,abc,float,double,long double,int *,int * const,int * volatile,int * const volatile,union def,struct ghi,class jkl,int &,int & volatile,abc,int *,int * const,int * volatile,int * const volatile,union def,struct ghi,class jkl> Ti";
		demangleAndTest();
	}

	//Manufactured; Keep. Have not seen real examples, but undname works this way.
	@Test
	public void testTemplateBackrefArgs_1() throws Exception {
		mangled = "?Ti@@3V?$Tc@W0mno@@XYpqr@@_$H_D_E_F_G_H_I_J0123456789@@A";
		msTruth =
			"class Tc<enum char mno,void,cointerface pqr,__w64 int,__int8,unsigned __int8,__int16,unsigned __int16,__int32,unsigned __int32,__int64enum char mnocointerface pqr__w64 int__int8unsigned __int8__int16unsigned __int16__int32unsigned __int32__int64> Ti";
		mdTruth =
			"class Tc<enum char mno,void,cointerface pqr,__w64 int,__int8,unsigned __int8,__int16,unsigned __int16,__int32,unsigned __int32,__int64,enum char mno,cointerface pqr,__w64 int,__int8,unsigned __int8,__int16,unsigned __int16,__int32,unsigned __int32,__int64> Ti";
		demangleAndTest();
	}

	//Manufactured; Keep. Have not seen real examples, but undname works this way.
	@Test
	public void testTemplateBackrefArgs_2() throws Exception {
		mangled = "?Ti@@3V?$Tc@H_K_L_M_N_OAH_W_Xstu@@_Yvwx@@01234567@@A";
		msTruth =
			"class Tc<int,unsigned __int64,__int128,unsigned __int128,bool,int[],wchar_t,coclass stu,cointerface vwxunsigned __int64__int128unsigned __int128boolint[]wchar_tcoclass stucointerface vwx> Ti";
		mdTruth =
			"class Tc<int,unsigned __int64,__int128,unsigned __int128,bool,int[],wchar_t,coclass stu,cointerface vwx,unsigned __int64,__int128,unsigned __int128,bool,int[],wchar_t,coclass stu,cointerface vwx> Ti";
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question0a() throws Exception {
		mangled = "??0Array@@$$FQAE@XZ";
		msTruth = "public: __thiscall Array::Array(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question0b() throws Exception {
		mangled = "??0Array@@$$FQAE@ABVJunk@@@Z";
		msTruth = "public: __thiscall Array::Array(class Junk const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question1() throws Exception {
		mangled = "??1Array@@$$FQAE@XZ";
		msTruth = "public: __thiscall Array::~Array(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question2a() throws Exception {
		mangled = "??2@$$FYAPAXI@Z";
		msTruth = "void * __cdecl operator new(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question2b() throws Exception {
		mangled = "??2Array@@$$FSAPAXI@Z";
		msTruth = "public: static void * __cdecl Array::operator new(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question3a() throws Exception {
		mangled = "??3@$$FYAXPAX@Z";
		msTruth = "void __cdecl operator delete(void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question3b() throws Exception {
		mangled = "??3Array@@$$FSAXPAX@Z";
		msTruth = "public: static void __cdecl Array::operator delete(void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question4() throws Exception {
		mangled = "??4Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question5() throws Exception {
		mangled = "??5Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator>>(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question6() throws Exception {
		mangled = "??6Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator<<(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question7() throws Exception {
		mangled = "??7Array@@$$FQAEAAV0@XZ";
		msTruth = "public: class Array & __thiscall Array::operator!(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question8() throws Exception {
		mangled = "??8Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator==(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question9() throws Exception {
		mangled = "??9Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator!=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionA() throws Exception {
		mangled = "??AArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator[](class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionB() throws Exception {
		mangled = "??BArray@@$$FQAE?AVJunk@@XZ";
		msTruth = "public: __thiscall Array::operator class Junk(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionC() throws Exception {
		mangled = "??CArray@@$$FQAEPAVJunk@@XZ";
		msTruth = "public: class Junk * __thiscall Array::operator->(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionD() throws Exception {
		mangled = "??DArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator*(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionE() throws Exception {
		mangled = "??EArray@@$$FQAEAAV0@H@Z";
		msTruth = "public: class Array & __thiscall Array::operator++(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionF() throws Exception {
		mangled = "??FArray@@$$FQAEAAV0@H@Z";
		msTruth = "public: class Array & __thiscall Array::operator--(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionG() throws Exception {
		mangled = "??GArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator-(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionH() throws Exception {
		mangled = "??HArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator+(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionI() throws Exception {
		mangled = "??IArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator&(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionJ() throws Exception {
		mangled = "??JArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator->*(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionK() throws Exception {
		mangled = "??KArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator/(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionL() throws Exception {
		mangled = "??LArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator%(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionM() throws Exception {
		mangled = "??MArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator<(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionN() throws Exception {
		mangled = "??NArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator<=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionO() throws Exception {
		mangled = "??OArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator>(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionP() throws Exception {
		mangled = "??PArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator>=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionQ() throws Exception {
		mangled = "??QArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator,(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionR() throws Exception {
		mangled = "??RArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator()(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionS() throws Exception {
		mangled = "??SArray@@$$FQAEAAV0@XZ";
		msTruth = "public: class Array & __thiscall Array::operator~(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionT() throws Exception {
		mangled = "??TArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator^(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionU() throws Exception {
		mangled = "??UArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator|(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionV() throws Exception {
		mangled = "??VArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator&&(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionW() throws Exception {
		mangled = "??WArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator||(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionX() throws Exception {
		mangled = "??XArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator*=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionY() throws Exception {
		mangled = "??YArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator+=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_questionZ() throws Exception {
		mangled = "??ZArray@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator-=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_0() throws Exception {
		mangled = "??_0Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator/=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_1() throws Exception {
		mangled = "??_1Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator%=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_2() throws Exception {
		mangled = "??_2Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator>>=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_3() throws Exception {
		mangled = "??_3Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator<<=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_4() throws Exception {
		mangled = "??_4Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator&=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_5() throws Exception {
		mangled = "??_5Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator|=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testClassOperators_question_6() throws Exception {
		mangled = "??_6Array@@$$FQAEAAV0@ABV0@@Z";
		msTruth = "public: class Array & __thiscall Array::operator^=(class Array const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCharString_nul_only() throws Exception {
		//Has hex-coded nul char only
		mangled = "??_C@_00CNPNBAHC@?$AA@";
		msTruth = "`string'";
		mdTruth = "";
		demangleAndTest();
	}

	//Has regular char
	@Test
	public void testCharString_reg_char() throws Exception {
		mangled = "??_C@_01ELNMCGJD@W?$AA@";
		msTruth = "`string'";
		mdTruth = "W";
		demangleAndTest();
	}

	//Has special char
	@Test
	public void testCharString_special_char_a() throws Exception {
		mangled = "??_C@_01IHBHIGKO@?0?$AA@";
		msTruth = "`string'";
		mdTruth = ",";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_b() throws Exception {
		mangled = "??_C@_01KMDKNFGN@?1?$AA@";
		msTruth = "`string'";
		mdTruth = "/";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_c() throws Exception {
		mangled = "??_C@_01KICIPPFI@?2?$AA@";
		msTruth = "`string'";
		mdTruth = "\\"; //Note: this is a single '\' that is escaped
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_d() throws Exception {
		mangled = "??_C@_01JLIPDDHJ@?3?$AA@";
		msTruth = "`string'";
		mdTruth = ":";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_e() throws Exception {
		mangled = "??_C@_01LFCBOECM@?4?$AA@";
		msTruth = "`string'";
		mdTruth = ".";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_f() throws Exception {
		mangled = "??_C@_01CLKCMJKC@?5?$AA@";
		msTruth = "`string'";
		mdTruth = " ";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_g() throws Exception {
		mangled = "??_C@_01EEMJAFIK@?6?$AA@";
		msTruth = "`string'";
		mdTruth = "\n";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_h() throws Exception {
		mangled = "??_C@_01GPOEFGEJ@?7?$AA@";
		msTruth = "`string'";
		mdTruth = "\t";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_i() throws Exception {
		mangled = "??_C@_01GEODFPGF@?8?$AA@";
		msTruth = "`string'";
		mdTruth = "'";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_j() throws Exception {
		mangled = "??_C@_01JOAMLHOP@?9?$AA@";
		msTruth = "`string'";
		mdTruth = "-";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_k() throws Exception {
		mangled = "??_C@_01CIIBJEOE@?h?$AA@";
		msTruth = "`string'";
		//mdtruth = "\u00E8";
		mdTruth = new String(new byte[] { (byte) 0xe8 }, "UTF-8");
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_l() throws Exception {
		mangled = "??_C@_01FFPGGAKB@?m?$AA@";
		msTruth = "`string'";
		//mdtruth = "í"; //windows-1252
		mdTruth = new String(new byte[] { (byte) 0xed }, "UTF-8");
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_m() throws Exception {
		mangled = "??_C@_01KKJKAMLN@?p?$AA@";
		msTruth = "`string'";
		//mdtruth = "ð"; //windows-1252
		mdTruth = new String(new byte[] { (byte) 0xf0 }, "UTF-8");
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_n() throws Exception {
		mangled = "??_C@_01JIKMGODP@?r?$AA@";
		msTruth = "`string'";
		//mdtruth = "ò"; //windows-1252
		mdTruth = new String(new byte[] { (byte) 0xf2 }, "UTF-8");
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_o() throws Exception {
		mangled = "??_C@_01EANLCPLP@y?$AA@";
		msTruth = "`string'";
		mdTruth = "y";
		demangleAndTest();
	}

	@Test
	public void testCharString_special_char_p() throws Exception {
		mangled = "??_C@_02BDIFHNNP@?1?9?$AA@";
		msTruth = "`string'";
		mdTruth = "/-";
		demangleAndTest();
	}

	//Has hex-coded char
	@Test
	public void testCharString_hexcoded_char() throws Exception {
		mangled = "??_C@_01EOFPKCAF@?$EA?$AA@";
		msTruth = "`string'";
		mdTruth = "@";
		demangleAndTest();
	}

	@Test
	public void testCharStringWithUnknownSpecialAddress_there_a() throws Exception {
		//Microsoft gets this one wrong--has additional information after the nul char.  What is this?
		mangled = "??_C@_00CNPNBAHC@?$AA@FNODOBFM@"; //Putative address of: 0x5DE3E15C
		//mstruth = " ?? ?? ::FNODOBFM::`string'"; //This is what undname is returning at the moment for this one.
		msTruth = "`string'";
		mdTruth = "";
		demangleAndTest();
		//Simlar ones to the above:
		//mangled = "??_C@_00CNPNBAHC@?$AA@JKADOLAD@";
		//mangled = "??_C@_00CNPNBAHC@?$AA@LNCPHCLB@";
		//mangled = "??_C@_00CNPNBAHC@?$AA@NNGAKEGL@";
		//mangled = "??_C@_00CNPNBAHC@?$AA@OKHAJAOM@";
		//mangled = "??_C@_00CNPNBAHC@?$AA@OMFIFPKP@";
		//mangled = "??_C@_00CNPNBAHC@?$AA@PBOPGDP@";
	}

	//Win7 SP1, netw5v64.pdb (netw5v64.sys)
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_gone_b() throws Exception {
		mangled = "??_C@_07CONGLLKI@WPA_PSK?$AA@"; //Without special address
		msTruth = "`string'";
		mdTruth = "WPA_PSK";
		demangleAndTest();
	}

	//Win7 SP1, netw5v64.pdb (netw5v64.sys)
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_there_b() throws Exception {
		mangled = "??_C@_07CONGLLKI@WPA_PSK?$AA@FNODOBFM@"; //With special address
		//mstruth = " ?? ?? ::FNODOBFM::`string'";
		msTruth = "`string'";
		mdTruth = "WPA_PSK";
		demangleAndTest();
	}

	//Win7 SP1, bcmwl664.pdb (bcmwl664.sys)
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_gone_c() throws Exception {
		mangled = "??_C@_07DAFDOJHI@macaddr?$AA@"; //Without special address
		msTruth = "`string'";
		mdTruth = "macaddr";
		demangleAndTest();
	}

	//Win7 SP1, bcmwl664.pdb (bcmwl664.sys)
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_there_c() throws Exception {
		mangled = "??_C@_07DAFDOJHI@macaddr?$AA@FNODOBFM@"; //With special address
		//mstruth = " ?? ?? ::FNODOBFM::`string'";
		msTruth = "`string'";
		mdTruth = "macaddr";
		demangleAndTest();
	}

	//Win7 SP1, dicowan.pdb and dicowans.pdb
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_gone_d() throws Exception {
		mangled = "??_C@_07CBCILOAJ@FaxTask?$AA@"; //Without special address
		msTruth = "`string'";
		mdTruth = "FaxTask";
		demangleAndTest();
	}

	//Win7 SP1, dicowan.pdb and dicowans.pdb
	@Test
	public void testCharStringWithUnknownSpecialAddress_samefile_there_d() throws Exception {
		mangled = "??_C@_07CBCILOAJ@FaxTask?$AA@FNODOBFM@"; //With special address
		//mstruth = " ?? ?? ::FNODOBFM::`string'";
		msTruth = "`string'";
		mdTruth = "FaxTask";
		demangleAndTest();
	}

	@Test
	public void testWCharString_a() throws Exception {
		mangled = "??_C@_11LOCGONAA@?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "";
		demangleAndTest();
	}

	@Test
	public void testWCharString_b() throws Exception {
		mangled = "??_C@_13BDBHJCJN@u?3?$AA?$AA@";
		msTruth = "`string'";
		//mdtruth = "町"; //windows-1252
		mdTruth = new String(new byte[] { 0x75, 0x3a }, "UTF-16");
		demangleAndTest();
	}

	@Test
	public void testWCharString_c() throws Exception {
		mangled = "??_C@_1BA@KFOBIOMM@?$AAT?$AAY?$AAP?$AAE?$AAL?$AAI?$AAB?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "TYPELIB";
		demangleAndTest();
	}

	@Test
	public void testWCharString_d() throws Exception {
		mangled =
			"??_C@_1EK@KFPEBLPK@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AAB@";
		msTruth = "`string'";
		mdTruth = "012345678901234567890123456789AB";
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testUnderscore7a() throws Exception {
		mangled = "??_7CAnalogAudioStream@@6BCUnknown@@CKsSupport@@@";
		msTruth = "const CAnalogAudioStream::`vftable'{for `CUnknown's `CKsSupport'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testUnderscore7b() throws Exception {
		mangled = "??_7a@b@@6B@";
		msTruth = "const b::a::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testUnderscore7c() throws Exception {
		mangled = "??_7a@b@@6Bc@d@@@";
		msTruth = "const b::a::`vftable'{for `d::c'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testUnderscore7d() throws Exception {
		mangled = "??_7a@b@@6Bc@d@@e@f@@@";
		msTruth = "const b::a::`vftable'{for `d::c's `f::e'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured tests that teased out more details.
	@Test
	public void testUnderscore7e() throws Exception {
		mangled = "??_7a@b@@6Bc@d@e@@f@g@h@@i@j@k@@@";
		msTruth = "const b::a::`vftable'{for `e::d::c's `h::g::f's `k::j::i'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpecialNames_R() throws Exception {
		mangled = "??_R0X@8";
		msTruth = "void `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_7() throws Exception {
		mangled = "??_7testAccessLevel@@6B@";
		msTruth = "const testAccessLevel::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_8() throws Exception {
		mangled = "??_8testAccessLevel@@$BA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`vbtable'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_9a() throws Exception {
		mangled = "??_9testAccessLevel@@$BA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`vcall'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpecialNames_9b() throws Exception {
		mangled = "??_9testAccessLevel@@$R5A@B@C@D@AA@@@";
		msTruth =
			"[thunk]:public: virtual __cdecl testAccessLevel::`vcall'`vtordispex{0,1,2,3}' () throw()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_9c() throws Exception {
		mangled = "??_9testAccessLevel@@$R5A@B@C@D@AA@H@HH@";
		msTruth =
			"[thunk]:public: virtual __cdecl testAccessLevel::`vcall'`vtordispex{0,1,2,3}' (int) throw(int,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_A() throws Exception {
		mangled = "??_AtestAccessLevel@@$BA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`typeof'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_B() throws Exception {
		mangled = "??_B?1??name0@name1@name2@@KAHPEBGAEAG@Z@51";
		msTruth =
			"`protected: static int __cdecl name2::name1::name0(unsigned short const * __ptr64,unsigned short & __ptr64)'::`2'::`local static guard'{2}'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_C() throws Exception {
		mangled = "??_B?1??VTFromRegType@CRegParser@ATL@@KAHPEBGAEAG@Z@51";
		msTruth =
			"`protected: static int __cdecl ATL::CRegParser::VTFromRegType(unsigned short const * __ptr64,unsigned short & __ptr64)'::`2'::`local static guard'{2}'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_D() throws Exception {
		mangled = "??_DArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`vbase destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_E() throws Exception {
		mangled = "??_EArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_F() throws Exception {
		mangled = "??_FArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`default constructor closure'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_Ga() throws Exception {
		mangled = "??_GArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_Gb() throws Exception {
		mangled =
			"??_Gname0@?1???$name1@W4name2@name3@@@name3@@YA?AW4name2@1@PAV?$name4@W4name2@name3@@@1@IPBV?$name5@$$A6A_NABW4name2@name3@@@Z@name6@name7@@@Z@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall `enum name3::name2 __cdecl name3::name1<enum name3::name2>(class name3::name4<enum name3::name2> *,unsigned int,class name7::name6::name5<bool __cdecl(enum name3::name2 const &)> const *)'::`2'::name0::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_H() throws Exception {
		mangled = "??_HArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`vector constructor iterator'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_I() throws Exception {
		mangled = "??_IArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`vector destructor iterator'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_J() throws Exception {
		mangled = "??_JArray@@$$FQAEPAXI@Z";
		msTruth =
			"public: void * __thiscall Array::`vector vbase constructor iterator'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_K() throws Exception {
		mangled = "??_KArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`virtual displacement map'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_La() throws Exception {
		mangled = "??_L@$$FYMXPAXIHP6MX0@Z1@Z";
		msTruth =
			"void __clrcall `eh vector constructor iterator'(void *,unsigned int,int,void (__clrcall*)(void *),void (__clrcall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_Lb() throws Exception {
		mangled = "??_L@YGXPAXIHP6EX0@Z1@Z";
		msTruth =
			"void __stdcall `eh vector constructor iterator'(void *,unsigned int,int,void (__thiscall*)(void *),void (__thiscall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_M() throws Exception {
		mangled = "??_M@$$FYMXPAXIHP6MX0@Z@Z";
		msTruth =
			"void __clrcall `eh vector destructor iterator'(void *,unsigned int,int,void (__clrcall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_N() throws Exception {
		mangled = "??_NArray@@$$FQAEPAXI@Z";
		msTruth =
			"public: void * __thiscall Array::`eh vector vbase constructor iterator'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_O() throws Exception {
		mangled = "??_OArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`copy constructor closure'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_P() throws Exception {
		//_P is prefix for another special name, such that:
		//  "?_PE" that looks like (prefix) and "?E" or
		//  "?_P_E" that looks like (prefix) and "?_E"
		//  Prefix is "`udt returning'"
		mangled = "??_PENameSpace@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall NameSpace::`udt returning'operator++(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_P_nested() throws Exception {
		//_P is prefix for another special name, such that:
		//  "?_PE" that looks like (prefix) and "?E" or
		//  "?_P_E" that looks like (prefix) and "?_E"
		//  Prefix is "`udt returning'"
		mangled = "??_P_P_PENameSpace@@$$FQAEPAXI@Z";
		msTruth =
			"public: void * __thiscall NameSpace::`udt returning'`udt returning'`udt returning'operator++(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	//TODO: look into the "`EH'" possibility (found information somewhere before, but never had a good symbol)
	@Test
	public void testSpecialNames_Q() throws Exception {
		//name = "`EH'"; //must have more embedding as we haven't gotten undname to return yet.
		//manufactured and not sure if good example or not... needs to output "`EH'" ???
		//TODO: need to look closer... as this must be a function, I think (but so do all of those other operators above).
		mangled = "??_QNamespace1@Namespace2@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Namespace2::Namespace1::(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//modified real symbol
	@Test
	public void testSpecialNames_R0a() throws Exception {
		mangled = "??_R0?PAVname0@name1@@@0HB";
		msTruth =
			"private: static int const class name1::name0 const volatile __based() `RTTI Type Descriptor'";
		mangled = "??_R0?PAVCOleException@xyz@@@0HB";
		msTruth =
			"private: static int const class xyz::COleException const volatile __based() `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_R0b() throws Exception {
		mangled = "??_R0?AVtestAccessLevel@@@8";
		msTruth = "class testAccessLevel `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_R1() throws Exception {
		mangled = "??_R1A@?0A@EA@testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Base Class Descriptor at (0,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_R2() throws Exception {
		mangled = "??_R2testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_R3() throws Exception {
		mangled = "??_R3testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_R4() throws Exception {
		mangled = "??_R4testAccessLevel@@6B@";
		msTruth = "const testAccessLevel::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_S() throws Exception {
		mangled = "??_SArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`local vftable'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_T() throws Exception {
		mangled = "??_TArray@@$$FQAEPAXI@Z";
		msTruth =
			"public: void * __thiscall Array::`local vftable constructor closure'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_Ua() throws Exception {
		mangled = "??_UArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::operator new[](unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//real symbol
	@Test
	public void testSpecialNames_Ub() throws Exception {
		mangled = "??_U@YAPEAX_K@Z";
		msTruth = "void * __ptr64 __cdecl operator new[](unsigned __int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_V() throws Exception {
		mangled = "??_VArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::operator delete[](unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_X() throws Exception {
		mangled = "??_XArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`placement delete closure'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames_Y() throws Exception {
		mangled = "??_YArray@@$$FQAEPAXI@Z";
		msTruth = "public: void * __thiscall Array::`placement delete[] closure'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__A() throws Exception {
		mangled = "??__AtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`managed vector constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__B() throws Exception {
		mangled = "??__BtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`managed vector destructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__C() throws Exception {
		mangled = "??__CtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`eh vector copy constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__D() throws Exception {
		mangled = "??__DtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`eh vector vbase copy constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: __E (we have many of these with ???, but want ??__E if we can find it)

	//real symbol
	@Test
	public void testSpecialNames__F() throws Exception {
		mangled =
			"??__Fname0@?1??name1@name2@name3@name4@@CAXPEAUname5@@P84@EAAJPEAPEAG@ZW4name6@@PEAUname7@@@Z@YAXXZ";
		msTruth =
			"void __cdecl `private: static void __cdecl name4::name3::name2::name1(struct name5 * __ptr64,long (__cdecl name4::*)(unsigned short * __ptr64 * __ptr64) __ptr64,enum name6,struct name7 * __ptr64)'::`2'::`dynamic atexit destructor for 'name0''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__G() throws Exception {
		mangled = "??__GtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`vector copy constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__H() throws Exception {
		mangled = "??__HtestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`vector vbase copy constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__I() throws Exception {
		mangled = "??__ItestAccessLevel@@$BA@AA";
		msTruth =
			"[thunk]: __cdecl testAccessLevel::`managed vector copy constructor iterator'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__J() throws Exception {
		mangled = "??__JtestAccessLevel@@$BA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`local static thread guard'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__K() throws Exception {
		mangled = "??__Kabc@def@@3HA";
		msTruth = "int def::operator \"\" abc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//manufactured symbol
	@Test
	public void testSpecialNames__K_confirmNonMDReusableName() throws Exception {
		mangled = "??__Kabc@def@0@3HA";
		msTruth = "int def::def::operator \"\" abc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQualification_withInterfaceNamespace_a() throws Exception {
		mangled = "?var@?IInterfaceNamespace@Namespace@@3HA";
		msTruth = "int Namespace[::InterfaceNamespace]::var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQualification_withInterfaceNamespace_b() throws Exception {
		mangled = "?var@Namespace@?IInterfaceNamespace@@3HA";
		msTruth = "int InterfaceNamespace]::Namespace::var"; //Notice that MSFT does not include starting bracket
		mdTruth = "int [InterfaceNamespace]::Namespace::var";
		demangleAndTest();
	}

	@Test
	public void testQualification_withInterfaceNamespace_c() throws Exception {
		mangled = "?var@Namespace@?IInterfaceNamespace1@?IInterfaceNamespace2@@3HA";
		msTruth = "int InterfaceNamespace2][::InterfaceNamespace1]::Namespace::var"; //Notice that MSFT does not include starting bracket
		mdTruth = "int [InterfaceNamespace2][::InterfaceNamespace1]::Namespace::var";
		demangleAndTest();
	}

	@Test
	public void testQualification_withInterfaceNamespace_d() throws Exception {
		mangled = "?var@?IInterfaceNamespace1@Namespace@?IInterfaceNamespace2@@3HA";
		msTruth = "int InterfaceNamespace2]::Namespace[::InterfaceNamespace1]::var"; //Notice that MSFT does not include starting bracket
		mdTruth = "int [InterfaceNamespace2]::Namespace[::InterfaceNamespace1]::var";
		demangleAndTest();
	}

	@Test
	public void testQualification_withInterfaceNamespace_e() throws Exception {
		mangled = "?var@?IInterfaceNamespace1@?IInterfaceNamespace2@Namespace@@3HA";
		msTruth = "int Namespace[::InterfaceNamespace2][::InterfaceNamespace1]::var";
		mdTruth = "int Namespace[::InterfaceNamespace2][::InterfaceNamespace1]::var";
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_a() throws Exception {
//		//Not standard C??, but begins with standard __mep; Non begin with question mark.  Can be found using bindump /symbols, but undname doesn't work on these.
		mangled = "__mep@??_EArray@@$$FQAEPAXI@Z";
		msTruth = "__mep@??_EArray@@$$FQAEPAXI@Z";
		dbTruth =
			"[MEP] public: void * __thiscall Array::`vector deleting destructor'(unsigned int)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_b() throws Exception {
		mangled = "__t2m@??_EArray@@QAEPAXI@Z";
		msTruth = "__t2m@??_EArray@@QAEPAXI@Z";
		dbTruth =
			"[T2M] public: void * __thiscall Array::`vector deleting destructor'(unsigned int)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_c() throws Exception {
		mangled = "__mep@?main@@$$HYAHHQAPAD@Z";
		msTruth = "__mep@?main@@$$HYAHHQAPAD@Z";
		dbTruth = "[MEP] int __cdecl main(int,char * * const)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_d() throws Exception {
		mangled = "__t2m@??0Array@@QAE@ABVJunk@@@Z";
		msTruth = "__t2m@??0Array@@QAE@ABVJunk@@@Z";
		dbTruth = "[T2M] public: __thiscall Array::Array(class Junk const &)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_e() throws Exception {
		mangled = "__mep@??0Array@@$$FQAE@ABVJunk@@@Z";
		msTruth = "__mep@??0Array@@$$FQAE@ABVJunk@@@Z";
		dbTruth = "[MEP] public: __thiscall Array::Array(class Junk const &)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_f() throws Exception {
		mangled = "__t2m@??0Array@@QAE@ABVGunk@@@Z";
		msTruth = "__t2m@??0Array@@QAE@ABVGunk@@@Z";
		dbTruth = "[T2M] public: __thiscall Array::Array(class Gunk const &)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_g() throws Exception {
		mangled = "__mep@??0Array@@$$FQAE@ABVGunk@@@Z";
		msTruth = "__mep@??0Array@@$$FQAE@ABVGunk@@@Z";
		dbTruth = "[MEP] public: __thiscall Array::Array(class Gunk const &)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_h() throws Exception {
		mangled = "__t2m@??BArray@@QAE?AVJunk@@XZ";
		msTruth = "__t2m@??BArray@@QAE?AVJunk@@XZ";
		dbTruth = "[T2M] public: __thiscall Array::operator class Junk(void)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_i() throws Exception {
		mangled = "__mep@??BArray@@$$FQAE?AVJunk@@XZ";
		msTruth = "__mep@??BArray@@$$FQAE?AVJunk@@XZ";
		dbTruth = "[MEP] public: __thiscall Array::operator class Junk(void)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_j() throws Exception {
		mangled = "__t2m@??CArray@@QAEPAVJunk@@XZ";
		msTruth = "__t2m@??CArray@@QAEPAVJunk@@XZ";
		dbTruth = "[T2M] public: class Junk * __thiscall Array::operator->(void)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testFragmentStart_k() throws Exception {
		mangled = "__mep@??CArray@@$$FQAEPAVJunk@@XZ";
		msTruth = "__mep@??CArray@@$$FQAEPAVJunk@@XZ";
		dbTruth = "[MEP] public: class Junk * __thiscall Array::operator->(void)";
		mdTruth = dbTruth;
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testMoreFun_a() throws Exception {
		mangled = "?fn@@3P6A?BHH@ZA";
		msTruth = "int const (__cdecl* fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMoreFun_b() throws Exception {
		mangled = "?foo@test1@@QAAXXZ";
		msTruth = "public: void __cdecl test1::foo(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMessyTemplate() throws Exception {
		mangled =
			"??$?0V?$A@_NABW4B@C@@@D@E@@@?$F@V?$G@U?$H@Q6A_NABW4B@C@@@Z$0A@@D@E@@_NABW4B@C@@@D@E@@@E@@QAE@ABV?$F@V?$A@_NABW4B@C@@@D@E@@@1@@Z";
		msTruth =
			"public: __thiscall E::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> >::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >(class E::F<class E::D::A<bool,enum C::B const &> > const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_a() throws Exception {
		mangled = "??_R17?0A@EC@IUnknown@@8";
		msTruth = "IUnknown::`RTTI Base Class Descriptor at (8,-1,0,66)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_b() throws Exception {
		mangled = "??_R1A@?0A@EA@testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Base Class Descriptor at (0,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_c() throws Exception {
		mangled = "??_R1BA@?0A@EA@B@@8";
		msTruth = "B::`RTTI Base Class Descriptor at (16,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_d() throws Exception {
		mangled = "??_R17?0A@EA@name0@name1@@8";
		msTruth = "name1::name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_e() throws Exception {
		mangled = "??_R17?0A@EA@name0@name1@@8";
		msTruth = "name1::name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_f() throws Exception {
		mangled = "??_R17?0A@EA@?$name0@Vname1@name2@@@name2@@8";
		msTruth = "name2::name0<class name2::name1>::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_g() throws Exception {
		mangled = "??_R17?0A@EA@name0@@8";
		msTruth = "name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_h() throws Exception {
		mangled = "??_R17?0A@EA@?$name0@Vname1@name2@@@name2@@8";
		msTruth = "name2::name0<class name2::name1>::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_i() throws Exception {
		mangled = "??_R17?0A@EA@name0@name1@@8";
		msTruth = "name1::name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_j() throws Exception {
		mangled = "??_R17?0A@EA@?$name0@Vname1@name2@@@name2@@8";
		msTruth = "name2::name0<class name2::name1>::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_k() throws Exception {
		mangled = "??_R17?0A@EA@name0@@8";
		msTruth = "name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testRTTI_R1_l() throws Exception {
		mangled = "??_R17?0A@EA@?$name0@Vname1@name2@@@name2@@8";
		msTruth = "name2::name0<class name2::name1>::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_s2a() throws Exception {
		mangled =
			"??$ft2@P6APEADP6APEAXPEAHPEAF@Z@ZP6APEAFP6APEAX11@Z@ZH@@$$FYAHP6APEADP6APEAXPEAHPEAF@Z@ZP6APEAFP6APEAX11@Z@Z@Z";
		msTruth =
			"int __cdecl ft2<char * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)),int>(char * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_s2b() throws Exception {
		mangled =
			"??$ft2@P6APEAXPEAHP6APEAX0@ZP6APEADP6APEAX0PEAF@Z@ZP6APEAX2@Z2P6APEAF3@ZP6APEAFP6APEAX22@Z@ZPEAD@ZP6APEAF7@ZH@@$$FYAHP6APEAXPEAHP6APEAX0@ZP6APEADP6APEAX0PEAF@Z@ZP6APEAX2@Z2P6APEAF3@ZP6APEAFP6APEAX22@Z@ZPEAD@Z8@Z";
		msTruth =
			"int __cdecl ft2<void * __ptr64 (__cdecl*)(int * __ptr64,void * __ptr64 (__cdecl*)(int * __ptr64),char * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),void * __ptr64 (__cdecl*)(short * __ptr64),short * __ptr64,short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)),char * __ptr64),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)),int>(void * __ptr64 (__cdecl*)(int * __ptr64,void * __ptr64 (__cdecl*)(int * __ptr64),char * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),void * __ptr64 (__cdecl*)(short * __ptr64),short * __ptr64,short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)),char * __ptr64),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_aa() throws Exception {
		mangled =
			"?fai@@3P6APEAXPEAHP6APEAX0@ZP6APEADP6APEAX0PEAF@Z@ZP6APEAX2@Z2P6APEAF3@ZP6APEAFP6APEAX22@Z@ZPEAD@ZEA";
		msTruth =
			"void * __ptr64 (__cdecl* __ptr64 fai)(int * __ptr64,void * __ptr64 (__cdecl*)(int * __ptr64),char * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),void * __ptr64 (__cdecl*)(short * __ptr64),short * __ptr64,short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(int * __ptr64,short * __ptr64)),short * __ptr64 (__cdecl*)(void * __ptr64 (__cdecl*)(short * __ptr64,short * __ptr64)),char * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ab() throws Exception {
		mangled = "??_7testAccessLevel@@6B@";
		msTruth = "const testAccessLevel::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ac() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ac_mod1() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EIFDAPEAVCCC@@XZ@Z";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void)const volatile __unaligned __ptr64 __restrict) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ad() throws Exception {
		mangled = "?w1@@3HD";
		msTruth = "int const volatile w1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ae() throws Exception {
		mangled = "?Tci2@@3V?$Tc@V?$Tb@H@@@@A";
		msTruth = "class Tc<class Tb<int> > Tci2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_af() throws Exception {
		mangled = "?Tci1@@3V?$Tc@H@@A";
		msTruth = "class Tc<int> Tci1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ag() throws Exception {
		mangled = "?fncii@@YA?BHH@Z";
		msTruth = "int const __cdecl fncii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ai() throws Exception {
		mangled = "?fnii@@YAHH@Z";
		msTruth = "int __cdecl fnii(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_aj() throws Exception {
		mangled = "?fn1@BBB@@QEAAPEAVCCC@@XZ";
		msTruth = "public: class CCC * __ptr64 __cdecl BBB::fn1(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ak() throws Exception {
		mangled = "?pfspro@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 pfspro)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_al() throws Exception {
		mangled = "?pfspub@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 pfspub)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_am() throws Exception {
		mangled = "?pfspri@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 pfspri)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_an() throws Exception {
		mangled = "?ttt@@3Vtest1@@A";
		msTruth = "class test1 ttt";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ao() throws Exception {
		mangled = "?s@@3P8BBB@@EAAPEAVCCC@@XZEQ1@";
		msTruth = "class CCC * __ptr64 (__cdecl BBB::* __ptr64 s)(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ap() throws Exception {
		mangled = "?PBBBMbr@@3PEQBBB@@HEQ1@";
		msTruth = "int BBB::* __ptr64 __ptr64 PBBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_aq() throws Exception {
		mangled = "?PBBBMbr_r@@3PEIQBBB@@HEIQ1@";
		msTruth = "int BBB::* __ptr64 __restrict __ptr64 __restrict PBBBMbr_r";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ar() throws Exception {
		mangled = "?PBBBMbr_u@@3PEQBBB@@HEQ1@";
		msTruth = "int BBB::* __ptr64 __ptr64 PBBBMbr_u";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_as() throws Exception {
		mangled = "?PBBBMbr_ru@@3PEIQBBB@@HEIQ1@";
		msTruth = "int BBB::* __ptr64 __restrict __ptr64 __restrict PBBBMbr_ru";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_at() throws Exception {
		mangled = "?PBBBMbr_ur@@3PEIQBBB@@HEIQ1@";
		msTruth = "int BBB::* __ptr64 __restrict __ptr64 __restrict PBBBMbr_ur";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_au() throws Exception {
		mangled = "?a@@3HA";
		msTruth = "int a";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_av() throws Exception {
		mangled = "?pui@@3PEFAHEFA";
		msTruth = "int __unaligned * __ptr64 __unaligned __ptr64 pui";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_aw() throws Exception {
		mangled = "?upui@@3PEFAHEFA";
		msTruth = "int __unaligned * __ptr64 __unaligned __ptr64 upui";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ax() throws Exception {
		mangled = "?rpi@@3PEIAHEIA";
		msTruth = "int * __ptr64 __restrict __ptr64 __restrict rpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ay() throws Exception {
		mangled = "?pur@@3PEIFAHEIFA";
		msTruth = "int __unaligned * __ptr64 __restrict __unaligned __ptr64 __restrict pur";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_az() throws Exception {
		mangled = "?cpur@@3PEIFBHEIFB";
		msTruth =
			"int const __unaligned * __ptr64 __restrict const __unaligned __ptr64 __restrict cpur";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ba() throws Exception {
		mangled = "?cvpur@@3PEIFDHEIFD";
		msTruth =
			"int const volatile __unaligned * __ptr64 __restrict const volatile __unaligned __ptr64 __restrict cvpur";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bb() throws Exception {
		mangled = "?vpur@@3PEIFCHEIFC";
		msTruth =
			"int volatile __unaligned * __ptr64 __restrict volatile __unaligned __ptr64 __restrict vpur";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bc() throws Exception {
		mangled = "?pci@@3PEBHEB";
		msTruth = "int const * __ptr64 const __ptr64 pci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bd() throws Exception {
		mangled = "?pvi@@3PECHEC";
		msTruth = "int volatile * __ptr64 volatile __ptr64 pvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_be() throws Exception {
		mangled = "?pcvi@@3PEDHED";
		msTruth = "int const volatile * __ptr64 const volatile __ptr64 pcvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bf() throws Exception {
		mangled = "?cpci@@3QEBHEB";
		msTruth = "int const * __ptr64 const __ptr64 cpci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bg() throws Exception {
		mangled = "?vpvi@@3RECHEC";
		msTruth = "int volatile * __ptr64 volatile __ptr64 vpvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bh() throws Exception {
		mangled = "?cpvi@@3QECHEC";
		msTruth = "int volatile * __ptr64 volatile __ptr64 cpvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bi() throws Exception {
		mangled = "?cvpcvi@@3SEDHED";
		msTruth = "int const volatile * __ptr64 const volatile __ptr64 cvpcvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bj() throws Exception {
		mangled = "?cpi@@3QEAHEA";
		msTruth = "int * __ptr64 __ptr64 cpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bk() throws Exception {
		mangled = "?xpci@@3REBHEB";
		msTruth = "int const * __ptr64 const __ptr64 xpci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bl() throws Exception {
		mangled = "?vpi@@3REAHEA";
		msTruth = "int * __ptr64 __ptr64 vpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bm() throws Exception {
		mangled = "?cvpi@@3SEAHEA";
		msTruth = "int * __ptr64 __ptr64 cvpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bn() throws Exception {
		mangled = "?cpcpci@@3QEBQEBHEB";
		msTruth = "int const * __ptr64 const * __ptr64 const __ptr64 cpcpci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bo() throws Exception {
		mangled = "?cpcpvi@@3QEBQECHEB";
		msTruth = "int volatile * __ptr64 const * __ptr64 const __ptr64 cpcpvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bp() throws Exception {
		mangled = "?vpvpvi@@3RECRECHEC";
		msTruth = "int volatile * __ptr64 volatile * __ptr64 volatile __ptr64 vpvpvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bq() throws Exception {
		mangled = "?cvpcvpcvi@@3SEDSEDHED";
		msTruth =
			"int const volatile * __ptr64 const volatile * __ptr64 const volatile __ptr64 cvpcvpcvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_br() throws Exception {
		mangled = "?pcpci@@3PEBQEBHEB";
		msTruth = "int const * __ptr64 const * __ptr64 const __ptr64 pcpci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bs() throws Exception {
		mangled = "?pfnii@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 pfnii)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bt() throws Exception {
		mangled = "?pfncii@@3P6A?BHH@ZEA";
		msTruth = "int const (__cdecl* __ptr64 pfncii)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bu() throws Exception {
		mangled = "?cpfncii@@3Q6A?BHH@ZEA";
		msTruth = "int const (__cdecl* __ptr64 cpfncii)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bv() throws Exception {
		mangled = "?enI@@3W4enumI@enumspace@@A";
		msTruth = "enum enumspace::enumI enI";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bw() throws Exception {
		mangled = "?enUI@@3W4enumUI@enumspace@@A";
		msTruth = "enum enumspace::enumUI enUI";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bx() throws Exception {
		mangled = "?enC@@3W4enumC@enumspace@@A";
		msTruth = "enum enumspace::enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_by() throws Exception {
		mangled = "?enUC@@3W4enumUC@enumspace@@A";
		msTruth = "enum enumspace::enumUC enUC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_bz() throws Exception {
		mangled = "?enS@@3W4enumS@enumspace@@A";
		msTruth = "enum enumspace::enumS enS";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ca() throws Exception {
		mangled = "?enUS@@3W4enumUS@enumspace@@A";
		msTruth = "enum enumspace::enumUS enUS";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cb() throws Exception {
		mangled = "?enL@@3W4enumL@enumspace@@A";
		msTruth = "enum enumspace::enumL enL";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cc() throws Exception {
		mangled = "?enUL@@3W4enumUL@enumspace@@A";
		msTruth = "enum enumspace::enumUL enUL";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cd() throws Exception {
		mangled = "?void3@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 void3";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ce() throws Exception {
		mangled = "?void4@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 void4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cf() throws Exception {
		mangled = "?void5@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 void5";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cg() throws Exception {
		mangled = "?blah2@@YA?BHH@Z";
		msTruth = "int const __cdecl blah2(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ch() throws Exception {
		mangled = "?use@@YAHPEAVB@@@Z";
		msTruth = "int __cdecl use(class B * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ci() throws Exception {
		mangled = "?fnx2@@3P6A?BHH@ZEA";
		msTruth = "int const (__cdecl* __ptr64 fnx2)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cj() throws Exception {
		mangled = "?foo@test1@@QEAAXXZ";
		msTruth = "public: void __cdecl test1::foo(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ck() throws Exception {
		mangled = "?fnx1@@3P6A?BHH@ZEA";
		msTruth = "int const (__cdecl* __ptr64 fnx1)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cl() throws Exception {
		mangled = "?blah1@test1@@SA?BHH@Z";
		msTruth = "public: static int const __cdecl test1::blah1(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cm() throws Exception {
		mangled = "?doit@testAccessLevel@@QEAAXXZ";
		msTruth = "public: void __cdecl testAccessLevel::doit(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cn() throws Exception {
		mangled = "?fnpri@testAccessLevel@@AEAAHH@Z";
		msTruth = "private: int __cdecl testAccessLevel::fnpri(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_co() throws Exception {
		mangled = "?fnpro@testAccessLevel@@IEAAHH@Z";
		msTruth = "protected: int __cdecl testAccessLevel::fnpro(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cp() throws Exception {
		mangled = "?fnpub@testAccessLevel@@QEAAHH@Z";
		msTruth = "public: int __cdecl testAccessLevel::fnpub(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cq() throws Exception {
		mangled = "?fspri@testAccessLevel@@CAHH@Z";
		msTruth = "private: static int __cdecl testAccessLevel::fspri(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cr() throws Exception {
		mangled = "?fspro@testAccessLevel@@KAHH@Z";
		msTruth = "protected: static int __cdecl testAccessLevel::fspro(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cs() throws Exception {
		mangled = "?fspub@testAccessLevel@@SAHH@Z";
		msTruth = "public: static int __cdecl testAccessLevel::fspub(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ct() throws Exception {
		mangled = "??0testAccessLevel@@QEAA@XZ";
		msTruth = "public: __cdecl testAccessLevel::testAccessLevel(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cu() throws Exception {
		mangled = "??_R4testAccessLevel@@6B@";
		msTruth = "const testAccessLevel::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cv() throws Exception {
		mangled = "??_R0?AVtestAccessLevel@@@8";
		msTruth = "class testAccessLevel `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cw() throws Exception {
		mangled = "??_7type_info@@6B@";
		msTruth = "const type_info::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cx() throws Exception {
		mangled = "??_R3testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cy() throws Exception {
		mangled = "??_R2testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_cz() throws Exception {
		mangled = "??_R1A@?0A@EA@testAccessLevel@@8";
		msTruth = "testAccessLevel::`RTTI Base Class Descriptor at (0,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_da() throws Exception {
		mangled = "?fvpub@testAccessLevel@@UEAAHH@Z";
		msTruth = "public: virtual int __cdecl testAccessLevel::fvpub(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_db() throws Exception {
		mangled = "?fvpro@testAccessLevel@@MEAAHH@Z";
		msTruth = "protected: virtual int __cdecl testAccessLevel::fvpro(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dc() throws Exception {
		mangled = "?fvpri@testAccessLevel@@EEAAHH@Z";
		msTruth = "private: virtual int __cdecl testAccessLevel::fvpri(int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dd() throws Exception {
		mangled = "??_9testAccessLevel@@$BA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`vcall'{0,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_de() throws Exception {
		mangled = "??_9testAccessLevel@@$BBA@AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`vcall'{16,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_df() throws Exception {
		mangled = "??_9testAccessLevel@@$B7AA";
		msTruth = "[thunk]: __cdecl testAccessLevel::`vcall'{8,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dg() throws Exception {
		mangled = "?acpi@@3QEAY01HEA";
		msTruth = "int (* __ptr64 __ptr64 acpi)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dh() throws Exception {
		mangled = "?arr@@3PEAY01HEA";
		msTruth = "int (* __ptr64 __ptr64 arr)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_di() throws Exception {
		mangled = "??0C@@QEAA@XZ";
		msTruth = "public: __cdecl C::C(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dj() throws Exception {
		mangled = "??_7C@@6BB@@@";
		msTruth = "const C::`vftable'{for `B'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dk() throws Exception {
		mangled = "??_7C@@6BA@@@";
		msTruth = "const C::`vftable'{for `A'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dl() throws Exception {
		mangled = "??_R4C@@6BA@@@";
		msTruth = "const C::`RTTI Complete Object Locator'{for `A'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dm() throws Exception {
		mangled = "??_R0?AVC@@@8";
		msTruth = "class C `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dn() throws Exception {
		mangled = "??_R3C@@8";
		msTruth = "C::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_do() throws Exception {
		mangled = "??_R2C@@8";
		msTruth = "C::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dp() throws Exception {
		mangled = "??_R0?AVA@@@8";
		msTruth = "class A `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dq() throws Exception {
		mangled = "??_R3A@@8";
		msTruth = "A::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dr() throws Exception {
		mangled = "??_R2A@@8";
		msTruth = "A::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ds() throws Exception {
		mangled = "??_R1BA@?0A@EA@B@@8";
		msTruth = "B::`RTTI Base Class Descriptor at (16,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dt() throws Exception {
		mangled = "??_R0?AVB@@@8";
		msTruth = "class B `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_du() throws Exception {
		mangled = "??_R3B@@8";
		msTruth = "B::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dv() throws Exception {
		mangled = "??_R2B@@8";
		msTruth = "B::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dw() throws Exception {
		mangled = "??_R4C@@6BB@@@";
		msTruth = "const C::`RTTI Complete Object Locator'{for `B'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dx() throws Exception {
		mangled = "?access@C@@EEAAHXZ";
		msTruth = "private: virtual int __cdecl C::access(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dy() throws Exception {
		mangled = "??0A@@QEAA@XZ";
		msTruth = "public: __cdecl A::A(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_dz() throws Exception {
		mangled = "??_7A@@6B@";
		msTruth = "const A::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ea() throws Exception {
		mangled = "??_R4A@@6B@";
		msTruth = "const A::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_eb() throws Exception {
		mangled = "?access@A@@UEAAHXZ";
		msTruth = "public: virtual int __cdecl A::access(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ec() throws Exception {
		mangled = "??0B@@QEAA@XZ";
		msTruth = "public: __cdecl B::B(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ed() throws Exception {
		mangled = "??_7B@@6B@";
		msTruth = "const B::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ee() throws Exception {
		mangled = "??_R4B@@6B@";
		msTruth = "const B::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ef() throws Exception {
		mangled = "?access@B@@UEAAHXZ";
		msTruth = "public: virtual int __cdecl B::access(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_eg() throws Exception {
		mangled = "?access@C@@GBA@EAAHXZ";
		msTruth = "[thunk]:private: virtual int __cdecl C::access`adjustor{16}' (void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_eh() throws Exception {
		mangled = "?cvi@@3HD";
		msTruth = "int const volatile cvi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ei() throws Exception {
		mangled = "?ci@@3HB";
		msTruth = "int const ci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ej() throws Exception {
		mangled = "?vi@@3HC";
		msTruth = "int volatile vi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8_ek() throws Exception {
		mangled = "?c@@3VC@@A";
		msTruth = "class C c";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_aa() throws Exception {
		mangled = "?extppfvprica@@3PEQtestAccessLevel@@Y01P81@EBAHH@ZEQ1@";
		msTruth =
			"int (__cdecl testAccessLevel::*(testAccessLevel::* __ptr64 __ptr64 extppfvprica)[2])(int)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ab() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64,long (__cdecl BBB::*)(class CCC * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ac() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZPEBGHZZ";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ad() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZHZZ";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ae() throws Exception {
		mangled = "??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZZZ";
		msTruth =
			"public: __cdecl AAA<class BBB,class CCC>::AAA<class BBB,class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_af() throws Exception {
		mangled = "??0?$AAA@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z";
		msTruth =
			"public: __cdecl AAA<class CCC>::AAA<class CCC>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ag() throws Exception {
		mangled = "??0?$AAA@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z";
		msTruth =
			"public: __cdecl AAA<>::AAA<>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ah() throws Exception {
		mangled = "??$AAA@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z";
		msTruth =
			"public: __cdecl AAA<>(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ai() throws Exception {
		mangled = "?AAA@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z";
		msTruth = "public: __cdecl AAA(class CCC * __ptr64 (__cdecl BBB::*)(void) __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_aj() throws Exception {
		mangled = "?AAA@@QAA@P8BBB@@AAPAVCCC@@XZ@Z";
		msTruth = "public: __cdecl AAA(class CCC * (__cdecl BBB::*)(void))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ak() throws Exception {
		mangled = "?BBBMbr@@3PEQBBB@@HEQ1@";
		msTruth = "int BBB::* __ptr64 __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_al() throws Exception {
		mangled = "?BBBMbr@@3PEQBBB@@HQ1@";
		msTruth = "int BBB::* __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_am() throws Exception {
		mangled = "?BBBMbr@@3PEFQBBB@@HEQ1@";
		msTruth = "int BBB::__unaligned * __ptr64 __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_an() throws Exception {
		mangled = "?BBBMbr@@3PEIQBBB@@HEQ1@";
		msTruth = "int BBB::* __ptr64 __restrict __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ao() throws Exception {
		mangled = "?BBBMbr@@3PEFIQBBB@@HEQ1@";
		msTruth = "int BBB::__unaligned * __ptr64 __restrict __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ap() throws Exception {
		mangled = "?BBBMbr@@3PFIEQBBB@@HEQ1@";
		msTruth = "int BBB::__unaligned * __restrict __ptr64 __ptr64 BBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_aq() throws Exception {
		mangled = "??0a@@3HA";
		msTruth = "int a::a";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ar() throws Exception {
		mangled = "?pci@@3PAHB";
		msTruth = "int * const pci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_as() throws Exception {
		mangled = "?xpci@@3PBHA";
		msTruth = "int const * xpci";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_at() throws Exception {
		mangled = "?xaa@@3PBHA";
		msTruth = "int const * xaa";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_au() throws Exception {
		mangled = "?xbb@@3QBHA";
		msTruth = "int const * xbb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_av() throws Exception {
		mangled = "?xcc@@3QAHA";
		msTruth = "int * xcc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_aw() throws Exception {
		mangled = "?xaaa@@3PAHB";
		msTruth = "int * const xaaa";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ax() throws Exception {
		mangled = "?xbbb@@3QBHB";
		msTruth = "int const * const xbbb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ay() throws Exception {
		mangled = "?xbbbb@@3PBHB";
		msTruth = "int const * const xbbbb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_az() throws Exception {
		mangled = "?enC@@3W0enumC@@A";
		msTruth = "enum char enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_ba() throws Exception {
		mangled = "?enC@@3W1enumC@@A";
		msTruth = "enum unsigned char enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bb() throws Exception {
		mangled = "?enC@@3W2enumC@@A";
		msTruth = "enum short enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bc() throws Exception {
		mangled = "?enC@@3W3enumC@@A";
		msTruth = "enum unsigned short enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bd() throws Exception {
		mangled = "?enC@@3W4enumC@@A";
		msTruth = "enum enumC enC";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_be() throws Exception {
		mangled =
			"??$?0V?$A@_NAEBW4B@C@@@D@E@@@?$F@V?$G@U?$H@Q6A_NAEBW4I@J@@@Z$0A@@K@L@@_NAEBW4M@N@@@O@P@@@Q@@QEAA@AEBV?$R@V?$T@_NAEBW4U@V@@@W@X@@@1@@Z";
		msTruth =
			"public: __cdecl Q::F<class P::O::G<struct L::K::H<bool (__cdecl*const)(enum J::I const & __ptr64),0>,bool,enum N::M const & __ptr64> >::F<class P::O::G<struct L::K::H<bool (__cdecl*const)(enum J::I const & __ptr64),0>,bool,enum N::M const & __ptr64> ><class E::D::A<bool,enum C::B const & __ptr64> >(class Q::R<class X::W::T<bool,enum V::U const & __ptr64> > const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bf() throws Exception {
		mangled = "?Ti@@3V?$Tc@H@@A";
		msTruth = "class Tc<int> Ti";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bg() throws Exception {
		mangled = "?xb@@3QCHA";
		msTruth = "int volatile * xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bh() throws Exception {
		mangled = "?xb@@3PCHA";
		msTruth = "int volatile * xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bi() throws Exception {
		mangled = "?xb@@3HA";
		msTruth = "int xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bj() throws Exception {
		mangled = "?xb@@3HC";
		msTruth = "int volatile xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bk() throws Exception {
		mangled = "?xb@@3PBQCHA";
		msTruth = "int volatile * const * xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bl() throws Exception {
		mangled = "?xb@@3PBQCHB";
		msTruth = "int volatile * const * const xb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bm() throws Exception {
		mangled = "?cpi@@3PBHA";
		msTruth = "int const * cpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bn() throws Exception {
		mangled = "?cpi@@3QBHA";
		msTruth = "int const * cpi";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bo() throws Exception {
		mangled =
			"??$?0V?$A@_NABW4B@C@@@D@E@@@?$F@V?$G@U?$H@Q6A_NABW4B@C@@@Z$0A@@D@E@@_NABW4B@C@@@D@E@@@E@@QAE@ABV?$F@V?$A@_NABW4B@C@@@D@E@@@1@@Z";
		msTruth =
			"public: __thiscall E::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> >::F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>,bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >(class E::F<class E::D::A<bool,enum C::B const &> > const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bp() throws Exception {
		mangled = "?void2@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 void2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bq() throws Exception {
		mangled = "?void1@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 void1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_br() throws Exception {
		mangled = "?pb@@3PEM2pBased@@HEM21@";
		msTruth = "int __based(pBased) * __ptr64 __based(pBased) __ptr64 pb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bs() throws Exception {
		mangled = "?pb@xyz@@3PEM2pBased@abc@@HEM223@";
		msTruth = "int __based(abc::pBased) * __ptr64 __based(abc::pBased) __ptr64 xyz::pb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bt() throws Exception {
		mangled = "?pb@xyz@@3SEM2pBased@abc@@HEM223@"; // const volatile
		msTruth = "int __based(abc::pBased) * __ptr64 __based(abc::pBased) __ptr64 xyz::pb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource8undname_bu() throws Exception {
		mangled = "?pb1@xyz@@3PE5BBB@@2pBased@abc@@HEP234@";
		msTruth =
			"int const volatile __based(abc::pBased) BBB::* __ptr64 const volatile __based(abc::pBased) __ptr64 xyz::pb1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_aa() throws Exception {
		mangled = "?VVCPPP2@@3PEAPEAPEBXEA";
		msTruth = "void const * __ptr64 * __ptr64 * __ptr64 __ptr64 VVCPPP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ab() throws Exception {
		mangled = "?VVCPP2@@3PEAPEBXEA";
		msTruth = "void const * __ptr64 * __ptr64 __ptr64 VVCPP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ac() throws Exception {
		mangled = "?VVCP2@@3PEBXEB";
		msTruth = "void const * __ptr64 const __ptr64 VVCP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ad() throws Exception {
		mangled = "?VIC2@@3HB";
		msTruth = "int const VIC2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ae() throws Exception {
		mangled = "?VVPPP1@@3PEAPEAPEAXEA";
		msTruth = "void * __ptr64 * __ptr64 * __ptr64 __ptr64 VVPPP1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_af() throws Exception {
		mangled = "?VVPPP2@@3PEAPEAPEAXEA";
		msTruth = "void * __ptr64 * __ptr64 * __ptr64 __ptr64 VVPPP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ag() throws Exception {
		mangled = "?VVPP1@@3PEAPEAXEA";
		msTruth = "void * __ptr64 * __ptr64 __ptr64 VVPP1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ah() throws Exception {
		mangled = "?VVPP2@@3PEAPEAXEA";
		msTruth = "void * __ptr64 * __ptr64 __ptr64 VVPP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ai() throws Exception {
		mangled = "?VVP1@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 VVP1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_aj() throws Exception {
		mangled = "?VVP2@@3PEAXEA";
		msTruth = "void * __ptr64 __ptr64 VVP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ak() throws Exception {
		mangled = "?VIP1@@3PEAHEA";
		msTruth = "int * __ptr64 __ptr64 VIP1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_al() throws Exception {
		mangled = "?VIP2@@3PEAHEA";
		msTruth = "int * __ptr64 __ptr64 VIP2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_am() throws Exception {
		mangled = "?VIR1@@3AEAHEA";
		msTruth = "int & __ptr64 __ptr64 VIR1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_an() throws Exception {
		mangled = "?VIR2@@3AEAHEA";
		msTruth = "int & __ptr64 __ptr64 VIR2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ao() throws Exception {
		mangled = "?VUIUR@@3AEAHEA";
		msTruth = "int & __ptr64 __ptr64 VUIUR";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ap() throws Exception {
		mangled = "?VUIUP@@3PEIFAHEIFA";
		msTruth = "int __unaligned * __ptr64 __restrict __unaligned __ptr64 __restrict VUIUP";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_aq() throws Exception {
		mangled = "?VUIUPARR@@3PEIAY01$$CFAHEIA";
		msTruth = "int __unaligned (* __ptr64 __restrict __ptr64 __restrict VUIUPARR)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ar() throws Exception {
		mangled = "?VB1@@3_NA";
		msTruth = "bool VB1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_as() throws Exception {
		mangled = "?VB2@@3_NA";
		msTruth = "bool VB2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_at() throws Exception {
		mangled = "?VLD1@@3OA";
		msTruth = "long double VLD1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_au() throws Exception {
		mangled = "?VLD2@@3OA";
		msTruth = "long double VLD2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_av() throws Exception {
		mangled = "?VD1@@3NA";
		msTruth = "double VD1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_aw() throws Exception {
		mangled = "?VD2@@3NA";
		msTruth = "double VD2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ax() throws Exception {
		mangled = "?VF1@@3MA";
		msTruth = "float VF1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ay() throws Exception {
		mangled = "?VF2@@3MA";
		msTruth = "float VF2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_az() throws Exception {
		mangled = "?VULL1@@3_KA";
		msTruth = "unsigned __int64 VULL1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_ba() throws Exception {
		mangled = "?VULL2@@3_KA";
		msTruth = "unsigned __int64 VULL2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bb() throws Exception {
		mangled = "?VLL1@@3_JA";
		msTruth = "__int64 VLL1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bc() throws Exception {
		mangled = "?VLL2@@3_JA";
		msTruth = "__int64 VLL2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bd() throws Exception {
		mangled = "?VUL1@@3KA";
		msTruth = "unsigned long VUL1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_be() throws Exception {
		mangled = "?VUL2@@3KA";
		msTruth = "unsigned long VUL2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bf() throws Exception {
		mangled = "?VL1@@3JA";
		msTruth = "long VL1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bg() throws Exception {
		mangled = "?VL2@@3JA";
		msTruth = "long VL2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bh() throws Exception {
		mangled = "?VUI1@@3IA";
		msTruth = "unsigned int VUI1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bi() throws Exception {
		mangled = "?VUI2@@3IA";
		msTruth = "unsigned int VUI2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bj() throws Exception {
		mangled = "?VI1@@3HA";
		msTruth = "int VI1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bk() throws Exception {
		mangled = "?VI2@@3HA";
		msTruth = "int VI2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bl() throws Exception {
		mangled = "?VUS1@@3GA";
		msTruth = "unsigned short VUS1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bm() throws Exception {
		mangled = "?VUS2@@3GA";
		msTruth = "unsigned short VUS2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bn() throws Exception {
		mangled = "?VS1@@3FA";
		msTruth = "short VS1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bo() throws Exception {
		mangled = "?VS2@@3FA";
		msTruth = "short VS2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bp() throws Exception {
		mangled = "?VUC1@@3EA";
		msTruth = "unsigned char VUC1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bq() throws Exception {
		mangled = "?VUC2@@3EA";
		msTruth = "unsigned char VUC2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_br() throws Exception {
		mangled = "?VC1@@3DA";
		msTruth = "char VC1";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSource6undname_bs() throws Exception {
		mangled = "?VC2@@3DA";
		msTruth = "char VC2";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_aa() throws Exception {
		mangled = "?name0@?1??name1@name2@name3@@KAHPEBGAEAG@Z@4QBUname4@?1??123@KAH01@Z@B";
		msTruth =
			"struct `protected: static int __cdecl name3::name2::name1(unsigned short const * __ptr64,unsigned short & __ptr64)'::`2'::name4 const * const `protected: static int __cdecl name3::name2::name1(unsigned short const * __ptr64,unsigned short & __ptr64)'::`2'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ab() throws Exception {
		mangled = "??_L@YGXPAXIHP6EX0@Z1@Z";
		msTruth =
			"void __stdcall `eh vector constructor iterator'(void *,unsigned int,int,void (__thiscall*)(void *),void (__thiscall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ac() throws Exception {
		mangled = "?name0@?2??name1@name2@name3@3@KGPAUname4@@PAG@Z@4QBUname5@233@B";
		msTruth =
			"struct name3::name3::name2::name5 const * const `protected: static struct name4 * __stdcall name3::name3::name2::name1(unsigned short *)'::`3'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ad() throws Exception {
		mangled = "?name0@?1??name1@name2@name3@@SGPBUname4@name5@@XZ@4QBU45@B";
		msTruth =
			"struct name5::name4 const * const `public: static struct name5::name4 const * __stdcall name3::name2::name1(void)'::`2'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ae() throws Exception {
		mangled = "?name0@name1@@SAHD@Z";
		msTruth = "public: static int __cdecl name1::name0(char)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_af() throws Exception {
		mangled = "??_C@_1BA@KFOBIOMM@?$AAT?$AAY?$AAP?$AAE?$AAL?$AAI?$AAB?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "TYPELIB";
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ag() throws Exception {
		mangled = "?name0@name1@@MAEPAP6GJPAUname2@@IIJ@ZXZ";
		msTruth =
			"protected: virtual long (__stdcall** __thiscall name1::name0(void))(struct name2 *,unsigned int,unsigned int,long)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ah() throws Exception {
		mangled = "??0name0@@AAE@PBQBD@Z";
		msTruth = "private: __thiscall name0::name0(char const * const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ai() throws Exception {
		mangled = "??0name0@@QAE@ABQBD@Z";
		msTruth = "public: __thiscall name0::name0(char const * const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_aj() throws Exception {
		mangled = "??_U@YAPEAX_K@Z";
		msTruth = "void * __ptr64 __cdecl operator new[](unsigned __int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ak() throws Exception {
		mangled = "?name0@name1@@QAEPAPAPAPAMXZ";
		msTruth = "public: float * * * * __thiscall name1::name0(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_al() throws Exception {
		mangled = "?name0@name1@name2@name3@@0PAV123@A";
		msTruth = "private: static class name3::name2::name1 * name3::name2::name1::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_am() throws Exception {
		mangled = "??_7name0@@6B@";
		msTruth = "const name0::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_an() throws Exception {
		mangled = "?name0@@3PAY0IA@EA";
		msTruth = "unsigned char (* name0)[128]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ao() throws Exception {
		mangled = "?name0@@3PAY11BAA@Uname1@@A";
		msTruth = "struct name1 (* name0)[2][256]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ap() throws Exception {
		mangled = "?name0@@YAP6AXIPAUname1@@@ZP6AXI0@Z@Z";
		msTruth =
			"void (__cdecl*__cdecl name0(void (__cdecl*)(unsigned int,struct name1 *)))(unsigned int,struct name1 *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_aq() throws Exception {
		mangled = "??_R0?PAVname0@@@8";
		msTruth = "class name0 const volatile __based() `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ar() throws Exception {
		mangled = "??$name0@_W@name1@@YAHPB_W000PBUname2@@@Z";
		msTruth =
			"int __cdecl name1::name0<wchar_t>(wchar_t const *,wchar_t const *,wchar_t const *,wchar_t const *,struct name2 const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_as() throws Exception {
		mangled = "??$?0_W@?$name0@Uname1@name2@@@name2@@QAE@ABV?$name0@_W@1@@Z";
		msTruth =
			"public: __thiscall name2::name0<struct name2::name1>::name0<struct name2::name1><wchar_t>(class name2::name0<wchar_t> const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_at() throws Exception {
		mangled = "??4?$name0@Uname1@@$1?name2@@3Uname3@@B@@QAEAAV0@PAUname1@@@Z";
		msTruth =
			"public: class name0<struct name1,&struct name3 const name2> & __thiscall name0<struct name1,&struct name3 const name2>::operator=(struct name1 *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_au() throws Exception {
		mangled = "??$name0@D@name1@@YAIPAD0PBD1PBUname2@@@Z";
		msTruth =
			"unsigned int __cdecl name1::name0<char>(char *,char *,char const *,char const *,struct name2 const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_av() throws Exception {
		mangled =
			"??1?$name0@U?$name1@Vname2@?Aname3@name4@@$0A@@name5@name6@@XPAV?$name7@I@name4@@@name5@name6@@UAE@XZ";
		msTruth =
			"public: virtual __thiscall name6::name5::name0<struct name6::name5::name1<class name4::`anonymous namespace'::name2,0>,void,class name4::name7<unsigned int> *>::~name0<struct name6::name5::name1<class name4::`anonymous namespace'::name2,0>,void,class name4::name7<unsigned int> *>(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_aw() throws Exception {
		mangled =
			"??_G?$name0@U?$name1@Vname2@?Aname3@name4@@$0A@@name5@name6@@XPAV?$name7@W4name8@name4@@@name4@@@name5@name6@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall name6::name5::name0<struct name6::name5::name1<class name4::`anonymous namespace'::name2,0>,void,class name4::name7<enum name4::name8> *>::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ax() throws Exception {
		mangled = "??1name0@@UEAA@XZ";
		msTruth = "public: virtual __cdecl name0::~name0(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ay() throws Exception {
		mangled = "??0name0@@AEAA@PEAUname1@@@Z";
		msTruth = "private: __cdecl name0::name0(struct name1 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_az() throws Exception {
		mangled = "?name0@name1@@$4PPPPPPPM@A@EAAJUname2@@HPEBGPEAPEAGK2KK1PEAEKPEAVname3@@@Z";
		msTruth =
			"[thunk]:public: virtual long __cdecl name1::name0`vtordisp{4294967292,0}' (struct name2,int,unsigned short const * __ptr64,unsigned short * __ptr64 * __ptr64,unsigned long,unsigned short * __ptr64 * __ptr64,unsigned long,unsigned long,unsigned short const * __ptr64,unsigned char * __ptr64,unsigned long,class name3 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_ba() throws Exception {
		mangled = "?name0@@YAXP6AJPEAPEAVname1@@@ZP6AJPEAVname2@@PEAPEAUname3@@@ZP6AJ3@Z@Z";
		msTruth =
			"void __cdecl name0(long (__cdecl*)(class name1 * __ptr64 * __ptr64),long (__cdecl*)(class name2 * __ptr64,struct name3 * __ptr64 * __ptr64),long (__cdecl*)(struct name3 * __ptr64 * __ptr64))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bb() throws Exception {
		mangled = "?name0@name1@@$4PPPPPPPM@A@EAAJUname2@@PEBGW4name3@@11PEAEK3KPEAXPEAVname4@@@Z";
		msTruth =
			"[thunk]:public: virtual long __cdecl name1::name0`vtordisp{4294967292,0}' (struct name2,unsigned short const * __ptr64,enum name3,unsigned short const * __ptr64,unsigned short const * __ptr64,unsigned char * __ptr64,unsigned long,unsigned char * __ptr64,unsigned long,void * __ptr64,class name4 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bc() throws Exception {
		mangled = "?name0@name1@@QEAAJPEAUname2@@PEAUname3@@@Z";
		msTruth =
			"public: long __cdecl name1::name0(struct name2 * __ptr64,struct name3 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bd() throws Exception {
		mangled = "?name0@name1@@2Uname2@@B";
		msTruth = "public: static struct name2 const name1::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_be() throws Exception {
		mangled = "?name0@name1@@MAEPAVname2@@XZ";
		msTruth = "protected: virtual class name2 * __thiscall name1::name0(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bf() throws Exception {
		mangled = "??_Gname0@?1???$name1@I@name2@@YA_NPAV?$name3@I@1@ABI@Z@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall `bool __cdecl name2::name1<unsigned int>(class name2::name3<unsigned int> *,unsigned int const &)'::`2'::name0::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bg() throws Exception {
		mangled =
			"??$?0V?$name0@_NABW4name1@name2@@@name3@name4@@@?$name5@V?$name6@U?$name7@Q6A_NABW4name1@name2@@@Z$0A@@name3@name4@@_NABW4name1@name2@@@name3@name4@@@name4@@QAE@ABV?$name5@V?$name0@_NABW4name1@name2@@@name3@name4@@@1@@Z";
		msTruth =
			"public: __thiscall name4::name5<class name4::name3::name6<struct name4::name3::name7<bool (__cdecl*const)(enum name2::name1 const &),0>,bool,enum name2::name1 const &> >::name5<class name4::name3::name6<struct name4::name3::name7<bool (__cdecl*const)(enum name2::name1 const &),0>,bool,enum name2::name1 const &> ><class name4::name3::name0<bool,enum name2::name1 const &> >(class name4::name5<class name4::name3::name0<bool,enum name2::name1 const &> > const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bh() throws Exception {
		mangled =
			"??_Gname0@?1???$name1@W4name2@name3@@@name3@@YA?AW4name2@1@PAV?$name4@W4name2@name3@@@1@IPBV?$name5@$$A6A_NABW4name2@name3@@@Z@name6@name7@@@Z@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall `enum name3::name2 __cdecl name3::name1<enum name3::name2>(class name3::name4<enum name3::name2> *,unsigned int,class name7::name6::name5<bool __cdecl(enum name3::name2 const &)> const *)'::`2'::name0::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bi() throws Exception {
		mangled = "??_B?1??name0@name1@name2@@KAHPEBGAEAG@Z@51";
		msTruth =
			"`protected: static int __cdecl name2::name1::name0(unsigned short const * __ptr64,unsigned short & __ptr64)'::`2'::`local static guard'{2}'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bj() throws Exception {
		mangled =
			"??$?0V?$name0@_NABW4name1@name2@@@name3@name4@@@?$name5@V?$name6@U?$name7@Q6A_NABW4name1@name2@@@Z$0A@@name3@name4@@_NABW4name1@name2@@@name3@name4@@@name4@@QAE@ABV?$name5@V?$name0@_NABW4name1@name2@@@name3@name4@@@1@@Z";
		msTruth =
			"public: __thiscall name4::name5<class name4::name3::name6<struct name4::name3::name7<bool (__cdecl*const)(enum name2::name1 const &),0>,bool,enum name2::name1 const &> >::name5<class name4::name3::name6<struct name4::name3::name7<bool (__cdecl*const)(enum name2::name1 const &),0>,bool,enum name2::name1 const &> ><class name4::name3::name0<bool,enum name2::name1 const &> >(class name4::name5<class name4::name3::name0<bool,enum name2::name1 const &> > const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bk() throws Exception {
		mangled = "??6?Aname0@name1@@YAAAVname2@1@AAV21@ABVname3@1@@Z";
		msTruth =
			"class name1::name2 & __cdecl name1::`anonymous namespace'::operator<<(class name1::name2 &,class name1::name3 const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bl() throws Exception {
		mangled = "??8@YAHAEBVname0@@0@Z";
		msTruth = "int __cdecl operator==(class name0 const & __ptr64,class name0 const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bm() throws Exception {
		mangled =
			"??$?9$$A6A_NABW4name0@name1@@@Z@name2@@YA_NABV?$name3@$$A6A_NABW4name0@name1@@@Z@0@$$T@Z";
		msTruth =
			"bool __cdecl name2::operator!=<bool __cdecl(enum name1::name0 const &)>(class name2::name3<bool __cdecl(enum name1::name0 const &)> const &,std::nullptr_t)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bn() throws Exception {
		mangled = "?name0@name1@@SGPAV1@PAUname2@@@Z";
		msTruth = "public: static class name1 * __stdcall name1::name0(struct name2 *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bo() throws Exception {
		mangled = "?name0@name1@@QEBAPEFBUname2@@AEBUname3@@K@Z";
		msTruth =
			"public: struct name2 const __unaligned * __ptr64 __cdecl name1::name0(struct name3 const & __ptr64,unsigned long)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bp() throws Exception {
		mangled = "??_R17?0A@EA@name0@name1@@8";
		msTruth = "name1::name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Following is OK to move to LOW--test is already on LOW in WineDemanglerTest.
//	//TODO: Research this.  Not sure about this symbol and result.  Came from WineDemanglerTest.
//	//MSFT 2015 undname yields: "S358<`template-parameter-2',CHelper_AD::tARootDir,AVCString * const volatile,void,unsigned char, ?? &>"
//	//  This is wrong for multiple reasons: "??" and "GetADRoot" -> "tARoot..."
//	@Test
//	public void testOrigTest_bq() throws Exception {
//		mangled = "?$S358@?1??GetADRootDir@CHelper_AD@@SA?AVCString@@XZ@4EA";
//		mstruth =
//			"unsigned char `public: static class CString __cdecl CHelper_AD::GetADRootDir(void)'::`2'::$S358";
//		mdtruth = mstruth;
//		demangleAndTest();
//	}

	@Test
	public void testOrigTest_br() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AHPEAUname2@@@ZEA";
		msTruth = "int (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testOrigTest_bs() throws Exception {
		mangled = "?name0@name1@name2@@0QAY0BAA@$$CBIA";
		msTruth = "private: static unsigned int const (* name2::name1::name0)[256]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_1() throws Exception {
		// Example: Space after template parameter (cv modifier).
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ"; //This is a DataType $$C Modifier
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_2() throws Exception {
		mangled = "?name0@@3QAY01$$CBEA"; //This is a DataType $$C Modifier
		msTruth = "unsigned char const (* name0)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_3() throws Exception {
		mangled = "?fn@@YAH$$T@Z"; //manufactured. //This is a DataType $$T Modifier
		msTruth = "int __cdecl fn(std::nullptr_t)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_4() throws Exception {
		mangled = "?Name@@3$$TA"; //manufactured--interestingly, this is probably not valid: see mstruth. //This is a DataType $$T Modifier
		msTruth = "std::nullptr_t";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_5() throws Exception {
		mangled = "?name0@@3PEIAY01$$CFAHEIA";
		msTruth = "int __unaligned (* __ptr64 __restrict __ptr64 __restrict name0)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_6() throws Exception {
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ"; //found elsewhere ($$C)
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_7() throws Exception {
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_8() throws Exception {
		mangled = "?abort@@$$J0YAXXZ";
		msTruth = "extern \"C\" void __cdecl abort(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_9() throws Exception {
		mangled = "?PrintCountsAndBytes_e2@@$$FYMXP$02EA_WPE$AAVEncoding@Text@System@@@Z"; //Has Rank 2
		msTruth =
			"void __clrcall PrintCountsAndBytes(cli::array<System::Text::_WPE$AAVEncoding ,2>^)";
//		mdtruth =
//			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^ __ptr64,class System::Text::Encoding ^ __ptr64)";
		mdTruth =
			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_10() throws Exception {
		mangled = "??0Array@@$$FQAE@XZ";
		msTruth = "public: __thiscall Array::Array(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_11() throws Exception {
		//STILL A PROBLEM 20140430 and 20140515
		mangled = "???__E?name0@name1@name2@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_12() throws Exception {
		mangled = "???__E?name0@name1@<name2>@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool <name2>::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_13() throws Exception {
		//When can P,Q:const,R:volatile,S:const volatile be seen in arguments emission?
		// Seems that these are used and stored when Direct Argument (not a referred to type within an argument)
		//  of a function.  TODO: seems that for a modified type in a template, there is an issue--checking this 20140521
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_14() throws Exception {
		mangled = "__mep@?main@@$$HYAHHQAPAD@Z";
		msTruth = "[MEP] int __cdecl main(int,char * * const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_15() throws Exception {
		//From ~LINE 3473
		mangled = "?var@@3$$BY0C@HA"; //mod of a later one
		msTruth = "int ( var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_16() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?FN@@QAAH$$A6AH@Z@Z";
		msTruth = "public: int __cdecl FN(int __cdecl())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_17() throws Exception {
		mangled = "??0?$name0@$$BY0BAE@G@@QEAA@PEAY0BAE@G@Z";
		msTruth =
			"public: __cdecl name0<unsigned short [260]>::name0<unsigned short [260]>(unsigned short (* __ptr64)[260]) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_18() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6AH@ZA";
		msTruth = "int (__cdecl var)()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_19() throws Exception {
		//hand-made $$A but as template parameter (full FN property vs. FN pointer as in _18, above.)
		mangled = "?T@@3V?$TC@$$A6AH@Z@@A";
		msTruth = "class TC<int __cdecl()> T";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_20() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A8blah@@AAH@ZA";
		msTruth = "int (__cdecl blah:: var)()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_21() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P)
		mangled = "?VarName@@3$$A_DClassName@@D0AHH@ZEA";
		msTruth = "int (__cdecl __based(void) ClassName:: __ptr64 VarName)(int)const volatile "; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep--should not encapsulate function reference "__cdecl __based(void) ClassName::" in parentheses.
	@Test
	public void testDollarDollar_22() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@$$A_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int __cdecl __based(void) ClassName::(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22_mod1() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@P_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::*)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22_mod2() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@S_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::*const volatile)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22_mod3() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@A_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::&)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22_mod4() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@B_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::&volatile)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22_mod4a() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?VarName@@3V?$TC@R_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::*volatile)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Manufactured; Keep--should not encapsulate function reference "__cdecl __based(void) ClassName::" in parentheses.
	@Test
	public void testDollarDollar_22_mod5() throws Exception {
		//hand-made $$A: Mod of one in CV testing (doing $$A instead of P) and mod of one above, changing to template parameter
		mangled = "?var@@3V?$TC@$$A6AHH@Z@@A";
		msTruth = "class TC<int __cdecl(int)> var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_22a() throws Exception {
		//hand-made A instead of $$A of last one
		mangled = "?VarName@@3V?$TC@A_DClassName@@D0AHH@Z@@EA";
		msTruth =
			"class TC<int (__cdecl __based(void) ClassName::&)(int)const volatile > __ptr64 VarName"; //Has trailing space
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_23() throws Exception {
		//real symbol
		mangled =
			"??_Gname0@?1???$name1@W4name2@name3@@@name3@@YA?AW4name2@1@PAV?$name4@W4name2@name3@@@1@IPBV?$name5@$$A6A_NABW4name2@name3@@@Z@name6@name7@@@Z@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall `enum name3::name2 __cdecl name3::name1<enum name3::name2>(class name3::name4<enum name3::name2> *,unsigned int,class name7::name6::name5<bool __cdecl(enum name3::name2 const &)> const *)'::`2'::name0::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testDollarDollar_24() throws Exception {
		mangled =
			"??$name0@H$$A6AJPEAUname1@@PEAVname2@name3@@@Z@?$name4@HP6AJPEAUname1@@PEAVname2@name3@@@ZV?$name5@H@@V?$name5@P6AJPEAUname1@@PEAVname2@name3@@@Z@@@@QEAAJAEBHA6AJPEAUname1@@PEAVname2@name3@@@ZPEAVname6@0@@Z";
		msTruth =
			"public: long __cdecl name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name0<int,long __cdecl(struct name1 * __ptr64,class name3::name2 * __ptr64)>(int const & __ptr64,long (__cdecl&)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name6 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testTempBBBQualBlankNameWhileCheckingDollarDollarA() throws Exception {
		mangled = "?PBBBMbr@@3PEQBBB@@HEQ1@";
		msTruth = "int BBB::* __ptr64 __ptr64 PBBBMbr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_aa() throws Exception {
		mangled = "?FN@@QEAM@PE$02AVCL@@@Z"; //copied from below.
		msTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64"; //MSFT undname does not include __ptr64 on cli::array<>
//		mdtruth = "public: __clrcall FN(cli::array<class CL ,2>^ __ptr64) __ptr64";
		mdTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ab() throws Exception {
		mangled = "?Test0@@$$FYMP$01AP$AEBVB@@XZ";
		msTruth = "cli::array<class B const ^ __ptr64 >^";
		mdTruth = "cli::array<class B const ^ __ptr64 >^ __clrcall Test0(void)";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ac() throws Exception {
		mangled = "?Test0@@$$FYMP$01AP$AAVB@@XZ";
		msTruth = "cli::array<class B ^ >^";
		mdTruth = "cli::array<class B ^ >^ __clrcall Test0(void)";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ad() throws Exception {
		mangled = "??0?$name0@$$BY02Uname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<struct name1 [3]>::name0<struct name1 [3]>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//DUPLICATE
//	@Test
//	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ae() throws Exception {
//		mangled = "?Test0@@$$FYMP$01AP$AAVB@@XZ";
//		mstruth = "cli::array<class B ^ >^";
//		mdtruth = "cli::array<class B ^ >^ __clrcall Test0(void)";
//    	mstruth = mdtruth;
//		demangleAndTest();
//	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_af() throws Exception {
		mangled = "?var@@3$$BY0C@HA"; //mod of a later one
		msTruth = "int ( var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ag() throws Exception {
		mangled = "?vp4@@3PE$BAXA"; //mod... NOTICE WITH X, DOES NOT DO pin_ptr
		msTruth = "void * __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ah() throws Exception {
		mangled = "?vp4@@3PE$BAHA"; //mod... NOTICE WITHOUT X, DOES DO pin_ptr
		msTruth = "cli::pin_ptr<int * __ptr64 vp4";
		mdTruth = "cli::pin_ptr<int >* __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ai() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?FN@@QAAH$$A6AH@Z@Z";
		msTruth = "public: int __cdecl FN(int __cdecl())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_aj() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "??Bvar@@3$$A6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl var::operator)(int __cdecl())"; //NOTE... This is what undname outputs, but it doesn't really follow any model for of the cast operator, but then I might be abusing it by trying to have a "$$A (pointer/reference)" to it.  So I wouldn't keep it unless is supports the processing we end up with.
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ak() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "??Bvar@@3A6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl& var::operator)(int __cdecl())"; //NOTE... This is what undname outputs, but it doesn't really follow any model for of the cast operator, but then I might be abusing it by trying to have a "$$A (pointer/reference)" to it.  So I wouldn't keep it unless is supports the processing we end up with.
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_al() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl var)(int __cdecl())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_am() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3A6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl& var)(int __cdecl())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_an() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3P6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl* var)(int __cdecl())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ao() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3A6AHA6AH@Z@ZA";
		msTruth = "int (__cdecl& var)(int (__cdecl&)())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ap() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3P6AHP6AH@Z@ZA";
		msTruth = "int (__cdecl* var)(int (__cdecl*)())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_aq() throws Exception {
		mangled = "?FN@@QEAM@PE$02AVCL@@@Z"; //copied from below.
		msTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64"; //MSFT undname does not include __ptr64 on cli::array<>
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ar() throws Exception {
		mangled = "?FN@@QEAM@P$02AVCL@@@Z"; //modified from above (eliminated 'E' on pin_ptr)
		msTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_as() throws Exception {
		//found elsewhere ($$A)
		mangled =
			"??$name0@H$$A6AJPEAUname1@@PEAVname2@name3@@@Z@?$name4@HP6AJPEAUname1@@PEAVname2@name3@@@ZV?$name5@H@@V?$name5@P6AJPEAUname1@@PEAVname2@name3@@@Z@@@@QEAAJAEBHA6AJPEAUname1@@PEAVname2@name3@@@ZPEAVname6@0@@Z";
		msTruth =
			"public: long __cdecl name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name0<int,long __cdecl(struct name1 * __ptr64,class name3::name2 * __ptr64)>(int const & __ptr64,long (__cdecl&)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name6 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_at() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6AH@ZA";
		msTruth = "int (__cdecl var)()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ata() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A8blah@@AAH@ZA";
		msTruth = "int (__cdecl blah:: var)()";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_au() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6AH$$A6AH@Z@ZA";
		msTruth = "int (__cdecl var)(int __cdecl())"; //NOTE: in parentheses if varname is included (like with function pointers)
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_av() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6AH$$A6A$$A6AH@Z@Z@ZA";
		msTruth = "int (__cdecl var)(int (__cdecl__cdecl())())"; //NOTE: in parentheses if varname is included (like with function pointers); this returns function type
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_av_mod() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3P6AHP6AP6AH@Z@Z@ZA";
		msTruth = "int (__cdecl* var)(int (__cdecl*(__cdecl*)())())"; //NOTE: in parentheses if varname is included (like with function pointers); this returns function type
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_aw() throws Exception {
		//hand-made $$A ($$A works for functions: 6, 7, 8, 9; but nothing yet for non-function modifiers)
		mangled = "?var@@3$$A6A$$A6AH@Z$$A6AH@Z@ZA";
		msTruth = "int (__cdecl(__cdecl var)(int __cdecl()))()"; //NOTE: in parentheses if varname is included (like with function pointers)
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ax() throws Exception {
		mangled = "?vp4@@3PECRE$BAXEC"; //from testManagedExtensions2() ($B)
		msTruth = "void * __ptr64 volatile * __ptr64 volatile __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ay() throws Exception {
		mangled = "?vp4@@3PECRE$BAHEC"; //manufactured/modified from above.  Note that above doesn't give pin_ptr (for void *), but anything else does (like int *)
		msTruth = "cli::pin_ptr<int * __ptr64 volatile * __ptr64 volatile __ptr64 vp4"; //Note MSFT missing '>' somewhere
		//mdtruth = "cli::pin_ptr<int * __ptr64> volatile * __ptr64 volatile __ptr64 vp4"; //Guess as to where '>' goes
		//mdtruth = "cli::pin_ptr<int> * __ptr64 volatile * __ptr64 volatile __ptr64 vp4"; //Guess as to where '>' goes
		mdTruth = "cli::pin_ptr<int >* __ptr64 volatile * __ptr64 volatile __ptr64 vp4"; //Guess as to where '>' goes
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_az() throws Exception {
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ"; //found elsewhere ($$C)
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_ba() throws Exception {
		mangled = "??0?$name0@$$BUname1@@@name2@@QEAA@XZ"; //mod of above (same as $$C, but no modifier)
		msTruth = "public: __cdecl name2::name0<struct name1>::name0<struct name1>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bb() throws Exception {
		mangled = "??0?$name0@$$BY02Uname1@@@name2@@QEAA@XZ"; //mod of above (same as $$C, but no modifier)
		msTruth =
			"public: __cdecl name2::name0<struct name1 [3]>::name0<struct name1 [3]>(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bc() throws Exception {
		mangled = "?var@@3$$BY0C@HA"; //mod of a later one
		msTruth = "int ( var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bd() throws Exception {
		mangled = "?vp4@@3PECRE$BAXEC"; //from testManagedExtension1 (below)
		msTruth = "void * __ptr64 volatile * __ptr64 volatile __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_be() throws Exception {
		mangled = "?vp4@@3PE$BAXA"; //mod... NOTICE WITH X, DOES NOT DO pin_ptr
		msTruth = "void * __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bf() throws Exception {
		mangled = "?vp4@@3PE$BAHA"; //mod... NOTICE WITHOUT X, DOES DO pin_ptr
		msTruth = "cli::pin_ptr<int * __ptr64 vp4";
		mdTruth = "cli::pin_ptr<int >* __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bg() throws Exception {
		mangled = "??$var@H$$BY0C@HH@@QEAA@@Z"; //mod of a later one
		msTruth = "public: __cdecl var<int,int [2],int>() __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bh() throws Exception {
		mangled = "??$var@H$$BY0C@HH@@QEAA@$$BY0C@H@Z"; //mod of a later one
		msTruth = "public: __cdecl var<int,int [2],int>(int [2]) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bi() throws Exception {
		mangled = "?var@@QAA@$$BY0C@H@Z"; //mod of a later one
		msTruth = "public: __cdecl var(int [2])";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bj() throws Exception {
		mangled = "?var@@3$$BY0C@HA"; //mod of a later one
		msTruth = "int ( var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bk() throws Exception {
		mangled = "?var@@3$$BHA"; //mod of a later one
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bl() throws Exception {
		mangled = "??0?$name0@$$BY0BAE@G@@QEAA@PEAY0BAE@G@Z";
		msTruth =
			"public: __cdecl name0<unsigned short [260]>::name0<unsigned short [260]>(unsigned short (* __ptr64)[260]) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bm() throws Exception {
		mangled = "?FN@@QEAM@A$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL &) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >&) __ptr64"; //Guessing where '>' goes (not really sure :( )
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bn() throws Exception {
		mangled = "?FN@@QEAM@AE$AE$AE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL % __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >% __ptr64 __ptr64 __ptr64) __ptr64"; //Guessing where '>' goes (not really sure :( )
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bo() throws Exception {
		mangled = "?FN@@QEAM@PE$02AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bp() throws Exception {
		// Example: Space after template parameter (cv modifier).
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bq() throws Exception {
		mangled = "?abort@@$$J0YAXXZ";
		msTruth = "extern \"C\" void __cdecl abort(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_br() throws Exception {
		mangled = "?PrintCountsAndBytes_e2@@$$FYMXP$02EA_WPE$AAVEncoding@Text@System@@@Z"; //Has Rank 2
		msTruth =
			"void __clrcall PrintCountsAndBytes(cli::array<System::Text::_WPE$AAVEncoding ,2>^)"; //MSFT undname does not include __ptr64 on cli::array<>
//		mdtruth =
//			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^ __ptr64,class System::Text::Encoding ^ __ptr64)";
		mdTruth =
			"void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64)";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bs() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bt() throws Exception {
		//real symbol
		mangled =
			"??_Gname0@?1???$name1@W4name2@name3@@@name3@@YA?AW4name2@1@PAV?$name4@W4name2@name3@@@1@IPBV?$name5@$$A6A_NABW4name2@name3@@@Z@name6@name7@@@Z@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall `enum name3::name2 __cdecl name3::name1<enum name3::name2>(class name3::name4<enum name3::name2> *,unsigned int,class name7::name6::name5<bool __cdecl(enum name3::name2 const &)> const *)'::`2'::name0::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_bu() throws Exception {
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	/////************** NEW TESTS *****************////

	//Next 4 tests (int):
	// PE$BAHA
	// AE$BAHA
	// ?E$BAHA
	// $E$BAHA
	@Test
	public void testManagedProperties_PinPtr_Int_PointerModifier() throws Exception {
		mangled = "?var@@3PE$BAHA";
		msTruth = "cli::pin_ptr<int * __ptr64 var";
		mdTruth = "cli::pin_ptr<int >* __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Int_ReferenceModifier() throws Exception {
		mangled = "?var@@3AE$BAHA";
		msTruth = "cli::pin_ptr<int & __ptr64 var";
		mdTruth = "cli::pin_ptr<int >& __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Int_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$BAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Int_DollarModifier() throws Exception {
		mangled = "?var@@3$E$BAHA";
		msTruth = "?var@@3$E$BAHA";
		mdTruth = ""; //Should error
		//mstruth = mdtruth;
		demangleAndTest();
	}

	//Next 6 tests (void):
	// PE$BAXA
	// AE$BAXA
	// ?E$BAXA
	// $E$BAXA
	// ?$AE$BAXA
	// ?$CE$BAXA
	@Test
	public void testManagedProperties_PinPtr_Void_PointerModifier() throws Exception {
		mangled = "?var@@3PE$BAXA";
		msTruth = "void * __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Void_ReferenceModifier() throws Exception {
		mangled = "?var@@3AE$BAXA";
		msTruth = "cli::pin_ptr<void & __ptr64 var";
		mdTruth = "cli::pin_ptr<void >& __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Void_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$BAXA";
		msTruth = "void __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Void_DollarModifier() throws Exception {
		mangled = "?var@@3$E$BAXA";
		msTruth = "?var@@3$E$BAXA";
		mdTruth = ""; //Should error
		demangleAndTest();
	}

	//V outofplace?
	@Test
	public void testManagedProperties_PinPtr_Void_QuestionModifier_DollarA() throws Exception {
		mangled = "?var@@3?$AE$BAXA";
		msTruth = "void __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtr_Void_QuestionModifier_DollarC() throws Exception {
		mangled = "?var@@3?$CE$BAXA";
		msTruth = "void % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//^ outofplace?

	//Next 5 tests Pointer (int) with $B combined with other $Managed in mixed order:
	// P$AE$BAHA
	// P$CE$BAHA
	// P$BE$BAHA
	// P$BE$AAHA
	// P$BE$CAHA
	@Test
	public void testManagedProperties_PinPtr_Int_QuestionModifier_DollarC() throws Exception {
		mangled = "?var@@3P$AE$BAHA";
		msTruth = "cli::pin_ptr<int ^ __ptr64 var";
		mdTruth = "cli::pin_ptr<int >^ __ptr64 var";
		demangleAndTest();
	}

	//
	//NEW NEW
	//

	//Tail modifier tests:
	//Normal int
	//$A int
	//$B int
	//$C int
	@Test
	public void testManagedProperties_TailModifier_Normal() throws Exception {
		mangled = "?var@@3HD";
		msTruth = "int const volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_TailModifier_DollarA() throws Exception {
		mangled = "?var@@3H$AD";
		msTruth = "int const volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_TailModifier_DollarB() throws Exception {
		mangled = "?var@@3H$BD";
		msTruth = "int const volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_TailModifier_DollarC() throws Exception {
		mangled = "?var@@3H$CD";
		msTruth = "int const volatile % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Complicated Tail modifier tests:
	//All A,B,C double combos
	//$A$A int
	//$A$B int
	//$A$C int
	//$B$A int
	//$B$B int
	//$B$C int
	//$C$A int
	//$C$B int
	//$C$C int
	@Test
	public void testManagedProperties_ComplexTailModifier_DollarADollarA() throws Exception {
		mangled = "?var@@3H$AE$AD";
		msTruth = "int const volatile __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarADollarB() throws Exception {
		mangled = "?var@@3H$AE$BD";
		msTruth = "int const volatile __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarADollarC() throws Exception {
		mangled = "?var@@3H$AE$CD";
		msTruth = "int const volatile % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarBDollarA() throws Exception {
		mangled = "?var@@3H$BE$AD";
		msTruth = "int const volatile __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarBDollarB() throws Exception {
		mangled = "?var@@3H$BE$BD";
		msTruth = "int const volatile __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarBDollarC() throws Exception {
		mangled = "?var@@3H$BE$CD";
		msTruth = "int const volatile % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarCDollarA() throws Exception {
		mangled = "?var@@3H$CE$AD";
		msTruth = "int const volatile % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarCDollarB() throws Exception {
		mangled = "?var@@3H$CE$BD";
		msTruth = "int const volatile % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_ComplexTailModifier_DollarCDollarC() throws Exception {
		mangled = "?var@@3H$CE$CD";
		msTruth = "int const volatile % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//CVMod Tail modifier tests:
	@Test
	public void testCVModTailModifier_CV5() throws Exception {
		mangled = "?var@@3H5xxx@@2yyy@@";
		msTruth = "int const volatile __based(yyy) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModTailModifier_xxxx1() throws Exception {
		mangled = "?fn@@UAAXXZ";
		msTruth = "public: virtual void __cdecl fn(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCVModTailModifier_xxxx2() throws Exception {
		mangled = "?fn@@UEIFDAXXZ";
		msTruth =
			"public: virtual void __cdecl fn(void)const volatile __unaligned __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Normal $A:
	//$A, Pointer to int
	//$A, Reference to int
	//$A, QuestionModifier to int
	//$A, DollarModifier to int
	@Test
	public void testManagedProperties_DollarA_Pointer() throws Exception {
		mangled = "?var@@3PE$AAHA";
		msTruth = "int ^ __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarA_Reference() throws Exception {
		mangled = "?var@@3AE$AAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarA_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$AAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarA_DollarModifier() throws Exception {
		mangled = "?var@@3$E$AAHA";
		msTruth = "?var@@3$E$AAHA";
		mdTruth = ""; //Should error
		demangleAndTest();
	}

	//Normal $B (Pin Pointer):
	//$B (Pin Pointer), Pointer to int
	//$B (Pin Pointer), Reference to int
	//$B (Pin Pointer), QuestionModifier to int
	//$B (Pin Pointer), DollarModifier to int
	@Test
	public void testManagedProperties_DollarB_Pointer() throws Exception {
		mangled = "?var@@3PE$BAHA";
		msTruth = "cli::pin_ptr<int * __ptr64 var";
		mdTruth = "cli::pin_ptr<int >* __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_Reference() throws Exception {
		mangled = "?var@@3AE$BAHA";
		msTruth = "cli::pin_ptr<int & __ptr64 var";
		mdTruth = "cli::pin_ptr<int >& __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$BAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_DollarModifier() throws Exception {
		mangled = "?var@@3$E$BAHA";
		msTruth = "?var@@3$E$BAHA";
		mdTruth = ""; //Should error
		demangleAndTest();
	}

	//Normal $C:
	//$A, Pointer to int
	//$A, Reference to int
	//$A, QuestionModifier to int
	//$A, DollarModifier to int
	@Test
	public void testManagedProperties_DollarC_Pointer() throws Exception {
		mangled = "?var@@3PE$CAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_Reference() throws Exception {
		mangled = "?var@@3AE$CAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$CAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_DollarModifier() throws Exception {
		mangled = "?var@@3$E$CAHA";
		msTruth = "?var@@3$E$CAHA";
		mdTruth = "";
		demangleAndTest();
	}

	//Normal $0-9 (Array):
	//$2 (Array), Pointer to int
	//$2 (Array), Reference to int
	//$2 (Array), QuestionModifier to int
	//$2 (Array), DollarModifier to int
	@Test
	public void testManagedProperties_CliArray_Pointer() throws Exception {
		mangled = "?var@@3PE$2AAHA";
		msTruth = "cli::array<int ,49>^"; //throws out __ptr64 and var name.
		//mdtruth = "cli::array<int ,49>^ __ptr64 var";
		mdTruth = "cli::array<int ,49>^ var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_CliArray_Reference() throws Exception {
		mangled = "?var@@3AE$2AAHA";
		msTruth = "cli::array<int ,49>^"; //throws out __ptr64 and var name.
		//mdtruth = "cli::array<int ,49>^ __ptr64 var";
		mdTruth = "cli::array<int ,49>^ var";
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_CliArray_QuestionModifier() throws Exception {
		mangled = "?var@@3?E$2AAHA";
		msTruth = "int ,49>^";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_CliArray_DollarModifier() throws Exception {
		mangled = "?var@@3$E$2AAHA";
		msTruth = "?var@@3$E$2AAHA";
		mdTruth = "";
		demangleAndTest();
	}

	//
	//PIN POINTER VARIATIONS....
	//

	//Void $B (Pin Pointer)--no pin pointer to void:
	//$B (Pin Pointer), Pointer to void
	//$B (Pin Pointer), Reference to void
	//$B (Pin Pointer), QuestionModifier to void
	//$B (Pin Pointer), DollarModifier to void
	@Test
	public void testManagedProperties_DollarB_Pointer_Void() throws Exception {
		mangled = "?var@@3PE$BAXA";
		msTruth = "void * __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_Reference_Void() throws Exception {
		mangled = "?var@@3AE$BAXA";
		msTruth = "cli::pin_ptr<void & __ptr64 var";
		mdTruth = "cli::pin_ptr<void >& __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_QuestionModifier_Void() throws Exception {
		mangled = "?var@@3?E$BAXA";
		msTruth = "void __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_DollarModifier_Void() throws Exception {
		mangled = "?var@@3$E$BAXA";
		msTruth = "?var@@3$E$BAXA";
		mdTruth = "";
		demangleAndTest();
	}

	//Out of place?  Modification of one above.
	//$B (Pin Pointer), QuestionModifier to void, with DollarA
	//$B (Pin Pointer), QuestionModifier to void, with DollarC
	@Test
	public void testManagedProperties_DollarA_QuestionModifier_Void() throws Exception {
		mangled = "?var@@3?$AE$BAXA";
		msTruth = "void __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_QuestionModifier_Void() throws Exception {
		mangled = "?var@@3?$CE$BAXA";
		msTruth = "void % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B (Pin Pointer), * (pointer), Double combinations with PinPointer:
	//$B (Pin Pointer), Pointer to int, $A$B
	//$B (Pin Pointer), Pointer to int, $C$B
	//$B (Pin Pointer), Pointer to int, $B$B
	//$B (Pin Pointer), Pointer to int, $B$A
	//$B (Pin Pointer), Pointer to int, $B$C
	@Test
	public void testManagedProperties_PinPtrCombo_DollarADollarB_Pointer() throws Exception {
		mangled = "?var@@3P$AE$BAHA";
		msTruth = "cli::pin_ptr<int ^ __ptr64 var";
		mdTruth = "cli::pin_ptr<int >^ __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarCDollarB_Pointer() throws Exception {
		mangled = "?var@@3P$CE$BAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarB_Pointer() throws Exception {
		mangled = "?var@@3P$BE$BAHA";
		msTruth = "cli::pin_ptr<int * __ptr64 var";
		mdTruth = "cli::pin_ptr<int >* __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarA_Pointer() throws Exception {
		mangled = "?var@@3P$BE$AAHA";
		msTruth = "cli::pin_ptr<int ^ __ptr64 var";
		mdTruth = "cli::pin_ptr<int >^ __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarC_Pointer() throws Exception {
		mangled = "?var@@3P$BE$CAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	//$B (Pin Pointer), & (reference), Double combinations with PinPointer:
	//$B (Pin Pointer), Reference to int, $A$B
	//$B (Pin Pointer), Reference to int, $C$B
	//$B (Pin Pointer), Reference to int, $B$B
	//$B (Pin Pointer), Reference to int, $B$A
	//$B (Pin Pointer), Reference to int, $B$C
	@Test
	public void testManagedProperties_PinPtrCombo_DollarADollarB_Reference() throws Exception {
		mangled = "?var@@3A$AE$BAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarCDollarB_Reference() throws Exception {
		mangled = "?var@@3A$CE$BAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarB_Reference() throws Exception {
		mangled = "?var@@3A$BE$BAHA";
		msTruth = "cli::pin_ptr<int & __ptr64 var";
		mdTruth = "cli::pin_ptr<int >& __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarA_Reference() throws Exception {
		mangled = "?var@@3A$BE$AAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarC_Reference() throws Exception {
		mangled = "?var@@3A$BE$CAHA";
		msTruth = "cli::pin_ptr<int % __ptr64 var";
		mdTruth = "cli::pin_ptr<int >% __ptr64 var";
		demangleAndTest();
	}

	//$B (Pin Pointer), ? (QuestionModifier), Double combinations with PinPointer:
	//$B (Pin Pointer), QuestionModifier to int, $A$B
	//$B (Pin Pointer), QuestionModifier to int, $C$B
	//$B (Pin Pointer), QuestionModifier to int, $B$B
	//$B (Pin Pointer), QuestionModifier to int, $B$A
	//$B (Pin Pointer), QuestionModifier to int, $B$C
	@Test
	public void testManagedProperties_PinPtrCombo_DollarADollarB_QuestionModifier()
			throws Exception {
		mangled = "?var@@3?$AE$BAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarCDollarB_QuestionModifier()
			throws Exception {
		mangled = "?var@@3?$CE$BAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarB_QuestionModifier()
			throws Exception {
		mangled = "?var@@3?$BE$BAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarA_QuestionModifier()
			throws Exception {
		mangled = "?var@@3?$BE$AAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarC_QuestionModifier()
			throws Exception {
		mangled = "?var@@3?$BE$CAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B (Pin Pointer), $ (DollarModifier), Double combinations with PinPointer:
	//$B (Pin Pointer), DollarModifier to int, $A$B
	//$B (Pin Pointer), DollarModifier to int, $C$B
	//$B (Pin Pointer), DollarModifier to int, $B$B
	//$B (Pin Pointer), DollarModifier to int, $B$A
	//$B (Pin Pointer), DollarModifier to int, $B$C
	@Test
	public void testManagedProperties_PinPtrCombo_DollarADollarB_DollarModifier() throws Exception {
		mangled = "?var@@3$$AE$BAHA";
		msTruth = "?var@@3$$AE$BAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarCDollarB_DollarModifier() throws Exception {
		mangled = "?var@@3$$CE$BAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarB_DollarModifier() throws Exception {
		mangled = "?var@@3$$BE$BAHA";
		msTruth = "?var@@3$$BE$BAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarA_DollarModifier() throws Exception {
		mangled = "?var@@3$$BE$AAHA";
		msTruth = "?var@@3$$BE$AAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarC_DollarModifier() throws Exception {
		mangled = "?var@@3$$BE$CAHA";
		msTruth = "?var@@3$$BE$CAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	//Other, $ (DollarModifier), Double combinations:
	//Other, DollarModifier to int, $A$A
	//Other, DollarModifier to int, $A$C
	//Other, DollarModifier to int, $C$A
	//Other, DollarModifier to int, $C$C
	@Test
	public void testManagedProperties_OtherCombo_DollarADollarA_DollarModifier() throws Exception {
		mangled = "?var@@3$$AE$AAHA";
		msTruth = "?var@@3$$AE$AAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_OtherCombo_DollarADollarC_DollarModifier() throws Exception {
		mangled = "?var@@3$$AE$CAHA";
		msTruth = "?var@@3$$AE$CAHA";
		mdTruth = ""; //Should error.  Taken care of if remaingingChars(2) > 0
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_OtherCombo_DollarCDollarA_DollarModifier() throws Exception {
		mangled = "?var@@3$$CE$AAHA";
		msTruth = "int __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_OtherCombo_DollarCDollarC_DollarModifier() throws Exception {
		mangled = "?var@@3$$CE$CAHA";
		msTruth = "int % __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$B (Pin Pointer), $ (DollarModifier), Double combinations with PinPointer--Not doing as is should error due to "?var@@3$E$BAHA" I/O above:

	//$ (TEMPLATE PARAMETER?) VARIATIONS....
	//Similar to I/O outputs above, but eliminating 'E' which seems to be part of the issue
	//Without CV ('A')
	@Test
	public void testManagedProperties_DollarA_NoE_DollarModifier() throws Exception {
		mangled = "?var@@3$$AHA";
		msTruth = "?var@@3$$AHA";
		mdTruth = "";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_NoE_DollarModifier() throws Exception {
		mangled = "?var@@3$$BHA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_NoE_DollarModifier() throws Exception {
		mangled = "?var@@3$$CHA";
		msTruth = " ?? const volatile ?? var";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//With CV ('A')
	@Test
	public void testManagedProperties_DollarA_NoE_WithCVA_DollarModifier() throws Exception {
		mangled = "?var@@3$$AAHA";
		msTruth = "?var@@3$$AAHA";
		mdTruth = "";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarB_NoE_WithCVA_DollarModifier() throws Exception {
		mangled = "?var@@3$$BAHA";
		msTruth = " ?? ::HA ?? var";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_NoE_WithCVA_DollarModifier() throws Exception {
		mangled = "?var@@3$$CAHA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Note: This is actually $$C (MDDataReferenceType). Probably need to modify the test
	// names of this and other tests above it.
	@Test
	public void testManagedProperties_DollarC_NoE_WithCVA_DollarModifier_const() throws Exception {
		mangled = "?var@@3$$CBHA";
		msTruth = "int const var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarC_WithE_WithCVA_DollarModifier_const()
			throws Exception {
		mangled = "?var@@3$$CEBHA";
		msTruth = "int const __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Added Y01 (array) to exercise Override code in MDDataReferenceType.  This
	//  symbol is supposed to fail.
	// Original symbol was: "?var@@3$$CBHA"
	// TODO:
	// Ultimately $$C (MDDataReferenceType) needs to extend MDModifiedType (not MDModifierType), but MDModifiedType
	//  is still under construction.  The MDArrayReferenceType (Y (Y01)) is only to be found in the MDmodifierType.
	//  Note that the EFGHI and ABCD... MDCVMod processing both can be found for $$C (e.g., we could have
	//  "?var@@3$$CEBHA" as a valid symbol). I just added the test for this above (should pass with the current code).
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testDataReferenceType_withArrayFail() throws Exception {
		mangled = "?var@@3$$CBY01HA";
		msTruth = "?var@@3$$CBY01HA";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Modifcation of  testManagedProperties_PinPtrCombo_DollarADollarB_Pointer()
	//TODO: Not sure what the output "should" look like, let alone if this combination should be valid.
	@Test
	public void testManagedProperties_PinPtrCombo_DollarADollarB_Pointer_withArrayModification()
			throws Exception {
		mangled = "?var@@3P$AE$BAY01HA";
		msTruth = "int (^ __ptr64 var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Modifcation of  testManagedProperties_PinPtrCombo_DollarADollarB_Pointer()
	//TODO: Not sure what the output "should" look like, let alone if this combination should be valid.
	@Test
	public void testManagedProperties_PinPtrCombo_DollarBDollarB_Pointer_withArrayModification()
			throws Exception {
		mangled = "?var@@3P$BE$BAY01HA";
		msTruth = "int (* __ptr64 var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Modifcation of  testManagedProperties_PinPtrCombo_DollarADollarB_Pointer()
	//TODO: Not sure what the output "should" look like, let alone if this combination should be valid.
	@Test
	public void testManagedProperties_PinPtrCombo_DollarCDollarB_Pointer_withArrayModification()
			throws Exception {
		mangled = "?var@@3P$CE$BAY01HA";
		msTruth = "int (% __ptr64 var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Modifcation of  testManagedProperties_PinPtrCombo_DollarADollarB_Pointer()
	//TODO: Not sure what the output "should" look like, let alone if this combination should be valid.
	@Test
	public void testManagedProperties_PinPtrCombo_NothingDollarB_Pointer_withArrayModification()
			throws Exception {
		mangled = "?var@@3PE$BAY01HA";
		msTruth = "int (* __ptr64 var)[2]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Extern C:	//TODO: what is $$J
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarJ() throws Exception {
		mangled = "?var@@$$J03HA";
		msTruth = "extern \"C\" int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Extern C:	//TODO: what is $$N
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarN() throws Exception {
		mangled = "?var@@$$N03HA";
		msTruth = "extern \"C\" int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Extern C:	//TODO: what is $$O
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarO() throws Exception {
		mangled = "?var@@$$O03HA";
		msTruth = "extern \"C\" int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: what is $$F
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarF() throws Exception {
		mangled = "?var@@$$F3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: what is $$H
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarH() throws Exception {
		mangled = "?var@@$$H3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: what is $$L
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarL() throws Exception {
		mangled = "?var@@$$L3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: what is $$M
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarM() throws Exception {
		mangled = "?var@@$$M3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: what is $$Q
	//manufactured
	@Test
	public void testAccessLevel_DollarDollarQ() throws Exception {
		mangled = "?var@@$$Q3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$$A6A (see/compare previous non-FN versions)
	//TBD

	//$$Q -- Real world examples only in the triple-Q (???) symbols
	//TBD

	//NEW NEW END

	//$B (Pin Pointer), with 'E' but Without CV ('A')
	@Test
	public void testManagedProperties_DollarB_WithE_WithoutCVA_DollarModifier() throws Exception {
		mangled = "?var@@3$E$BHA";
		msTruth = "?var@@3$E$BHA";
		mdTruth = "";
		demangleAndTest();
	}

	//$B (Pin Pointer) Void, without CV ('A')
	@Test
	public void testManagedProperties_DollarB_WithoutE_WithoutCVA_DollarModifier_Void()
			throws Exception {
		mangled = "?var@@3$$BXA";
		msTruth = "void var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//$A Void, with CV ('A')
	@Test
	public void testManagedProperties_DollarA_WithoutE_WithCVA_DollarModifier_Void()
			throws Exception {
		mangled = "?var@@3$$AAXA";
		msTruth = "?var@@3$$AAXA";
		mdTruth = "";
		demangleAndTest();
	}

	//$C Void, with CV ('A')
	@Test
	public void testManagedProperties_DollarC_WithoutE_WithCVA_DollarModifier_Void()
			throws Exception {
		mangled = "?var@@3$$CAXA";
		msTruth = "void var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//OTHER MODIFIERS (Maybe Access vs. modifiers)....

	//$$F
	//TBD

	//nullptr_t
	//$$T
	//$$TA
	//Others return garbage (bad parsing)
	@Test
	public void testManagedProperties_DollarDollarT_WithCVA() throws Exception {
		mangled = "?var@@3$$TA";
		//mstruth = "?var@@3$$TA";
		//mdtruth = "";
		msTruth = "std::nullptr_t";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_DollarDollarT() throws Exception {
		mangled = "?var@@3$$T";
		msTruth = "std::nullptr_t";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_Pointer_DollarT_WithCVA() throws Exception {
		mangled = "?var@@3P$TA";
		msTruth = " ?? ,593>^ ?? ";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_Reference_DollarT_WithCVA() throws Exception {
		mangled = "?var@@3A$TA";
		msTruth = " ?? ,593>^ ?? ";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_QuestionModifier_DollarT_WithCVA() throws Exception {
		mangled = "?var@@3?$TA";
		msTruth = " ?? ,593>^ ?? ";
		mdTruth = "";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	/////************ END NEW TESTS ***************////

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation000()
			throws Exception {
		mangled = "?vp4@@3PE$BAXA"; //mod... NOTICE WITH X, DOES NOT DO pin_ptr //copied Debug_in_Progress_ag()
		msTruth = "void * __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation001()
			throws Exception {
		mangled = "?vp4@@3P$AE$BAXA"; //mod... NOTICE WITH X, DOES NOT DO pin_ptr
		msTruth = "void ^ __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation002()
			throws Exception {
		mangled = "?vp4@@3PE$BAPAXA"; //mod... NOTICE WITH pointer to X, it does appear
		msTruth = "cli::pin_ptr<void * * __ptr64 vp4";
		mdTruth = "cli::pin_ptr<void * >* __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation003()
			throws Exception {
		mangled = "?vp4@@3P$AE$BAPAXA"; //mod... NOTICE WITH pointer to X, it does appear
		msTruth = "cli::pin_ptr<void * ^ __ptr64 vp4";
		mdTruth = "cli::pin_ptr<void * >^ __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation004()
			throws Exception {
		mangled = "?vp4@@3PE$BAHA";
		msTruth = "cli::pin_ptr<int * __ptr64 vp4";
		mdTruth = "cli::pin_ptr<int >* __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation005()
			throws Exception {
		mangled = "?vp4@@3P$AE$BAHA";
		msTruth = "cli::pin_ptr<int ^ __ptr64 vp4";
		mdTruth = "cli::pin_ptr<int >^ __ptr64 vp4";
		demangleAndTest();
		//BUT mangled = "?vp4@@3P$A$BAHA"; //=> EIF REQUIRED!!!!
		//GARBAGEmstruth = "cli::pin_ptr<int ^ __ptr64 vp4"; //=> "cli::pin_ptr<int> ^ __ptr64 vp4";
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation006()
			throws Exception {
		mangled = "?vp4@@3P$BAHA";
		msTruth = "cli::pin_ptr<int * vp4";
		mdTruth = "cli::pin_ptr<int >* vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation007()
			throws Exception {
		//	All three of these give the same results:
		mangled = "?vp4@@3A$BEIF$BAHA";
		msTruth = "cli::pin_ptr<int __unaligned & __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int >__unaligned & __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation008()
			throws Exception {
		mangled = "?vp4@@3A$BEIFAHA";
		msTruth = "cli::pin_ptr<int __unaligned & __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int >__unaligned & __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation009()
			throws Exception {
		mangled = "?vp4@@3AEIF$BAHA";
		msTruth = "cli::pin_ptr<int __unaligned & __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int >__unaligned & __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation010()
			throws Exception {
		//  These give the same (switching $A and $B locations):
		mangled = "?vp4@@3P$BEIF$AAHA";
		msTruth = "cli::pin_ptr<int __unaligned ^ __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int >__unaligned ^ __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation011()
			throws Exception {
		mangled = "?vp4@@3P$AEIF$BAHA";
		msTruth = "cli::pin_ptr<int __unaligned ^ __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int >__unaligned ^ __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation012()
			throws Exception {
		//  These give the same:
		mangled = "?vp4@@3PEIF$AEIF$BAHA";
		msTruth =
			"cli::pin_ptr<int __unaligned __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int >__unaligned __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation013()
			throws Exception {
		mangled = "?vp4@@3PEIF$BEIF$AAHA";
		msTruth =
			"cli::pin_ptr<int __unaligned __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int >__unaligned __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation014()
			throws Exception {
		//  $C preference over $A:
		mangled = "?vp4@@3PEIF$BEIF$AEIF$CAHA";
		msTruth =
			"cli::pin_ptr<int __unaligned __unaligned __unaligned % __ptr64 __restrict __ptr64 __restrict __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int >__unaligned __unaligned __unaligned % __ptr64 __restrict __ptr64 __restrict __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation015()
			throws Exception {
		mangled = "?vp4@@3PEIF$BEIF$CEIF$AAHA";
		msTruth =
			"cli::pin_ptr<int __unaligned __unaligned __unaligned % __ptr64 __restrict __ptr64 __restrict __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int >__unaligned __unaligned __unaligned % __ptr64 __restrict __ptr64 __restrict __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation016()
			throws Exception {
		// Another variation:
		mangled = "?vp4@@3PEIF$02APAP$AAPAP$AAHA";
		msTruth = "cli::array<int ^ * ^ * ,2>^";
		mdTruth = "cli::array<int ^ * ^ * ,2>^ vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation017()
			throws Exception {
		mangled = "?vp4@@3PEIF$02APAP$AAPAP$CAHA";
		msTruth = "cli::array<int % * ^ * ,2>^";
		mdTruth = "cli::array<int % * ^ * ,2>^ vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore1_variation018()
			throws Exception {
		//TODO: CREATE mstruth output (dispatcher)
		mangled = "?vp4@@3PEIF$02APAP$AAPAP$02AHA";
		msTruth = "cli::array<cli::array<int ,2>^";
		mdTruth = "cli::array<cli::array<int ,2>^ * ^ * ,2>^ vp4";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testX() throws Exception {
		mangled = "?vp4@@3P$02AHA";
		msTruth = "cli::array<int ,2>^";
		mdTruth = "cli::array<int ,2>^ vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation000()
			throws Exception {
		mangled = "?vp4@@3PEIFAPEIF$BAPAP$AAPAP$CAHA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned * __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned * __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation001()
			throws Exception {
		mangled = "?vp4@@3PEIF$BAPAP$AAPAP$CAHA";
		msTruth = "cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict vp4";
		mdTruth = "cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation002()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation003()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __ptr64 vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation004()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation005()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIFA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation006()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$AA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation007()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$BA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation008()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$CA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned % __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned % __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation009()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAH$CA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict % vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict % vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation010()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAH$AA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation011()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAH$BA";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation012()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$CD";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict const volatile __unaligned % __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict const volatile __unaligned % __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation013()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$C";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict ";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __unaligned % __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation014()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$C2BBB@AAA@@0";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based(void) AAA::BBB::__unaligned % __ptr64 __restrict vp4";
//		mdtruth =
//			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based() __unaligned % __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based(void) AAA::BBB::__unaligned % __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation015()
			throws Exception {
		mangled = "?vp4@@3P$AEIFAPEIF$BAPAP$AAPAP$CAHEIF$C2AAA@@0";
		msTruth =
			"cli::pin_ptr<int % * ^ * __unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based(void) AAA::__unaligned % __ptr64 __restrict vp4";
//		mdtruth =
//			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based() __unaligned % __ptr64 __restrict vp4";
		mdTruth =
			"cli::pin_ptr<int % * ^ * >__unaligned * __ptr64 __restrict __unaligned ^ __ptr64 __restrict __based(void) AAA::__unaligned % __ptr64 __restrict vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation016()
			throws Exception {
		mangled = "?vp4@@3P$CAHA";
		msTruth = "int % vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation017()
			throws Exception {
		mangled = "?vp4@@3A$CAHA";
		msTruth = "int % vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation018()
			throws Exception {
		mangled = "?vp4@@3?$CAHA";
		msTruth = "int % vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation019()
			throws Exception {
		mangled = "?vp4@@3$$CAHA";
		msTruth = "int vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation020()
			throws Exception {
		mangled = "?vp4@@3P$AAHA";
		msTruth = "int ^ vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation021()
			throws Exception {
		mangled = "?vp4@@3A$AAHA";
		msTruth = "int % vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation022()
			throws Exception {
		mangled = "?vp4@@3?$AAHA";
		msTruth = "int vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation023()
			throws Exception {
		mangled = "?vp4@@3$$AAHA";
		msTruth = "?vp4@@3$$AAHA";
		mdTruth = "";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation024()
			throws Exception {
		mangled = "?vp4@@3P$BAHA";
		msTruth = "cli::pin_ptr<int * vp4";
		mdTruth = "cli::pin_ptr<int >* vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation025()
			throws Exception {
		mangled = "?vp4@@3A$BAHA";
		msTruth = "cli::pin_ptr<int & vp4";
		mdTruth = "cli::pin_ptr<int >& vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation026()
			throws Exception {
		mangled = "?vp4@@3?$BAHA";
		msTruth = "int vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation027()
			throws Exception {
		mangled = "?vp4@@3$$BAHA";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation028()
			throws Exception {
		//TODO: CREATE mstruth output (dispatcher) ???
		mangled = "?vp4@@3P$02AHA";
		msTruth = "cli::array<int ,2>^";
		mdTruth = "cli::array<int ,2>^ vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation029()
			throws Exception {
		mangled = "?vp4@@3A$02AHA";
		msTruth = "cli::array<int ,2>^";
		mdTruth = "cli::array<int ,2>^ vp4";
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation030()
			throws Exception {
		mangled = "?vp4@@3?$02AHA";
		msTruth = "int, 2>^";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation031()
			throws Exception {
		mangled = "?vp4@@3$$02AHA";
		msTruth = "?vp4@@3$$02AHA"; //represents invalid
		mdTruth = "";
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation032()
			throws Exception {
		mangled = "?vp4@@3P$02AXA"; //test like pin_ptr<void> shows as void *
		msTruth = "void ,2>^";
		mdTruth = "cli::array<void ,2>^"; //Not sure if we should do this or not
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation033()
			throws Exception {
		mangled = "?vp4@@3P$02AXA"; //test like pin_ptr<void> shows as void *
		msTruth = "void >^";
		mdTruth = "cli::array<void >^"; //Not sure if we should do this or not
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation034()
			throws Exception {
		mangled = "?var@@3PE5ClassName@@0HA";
		msTruth = "int const volatile __based(void) ClassName::* __ptr64 var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation035()
			throws Exception {
		mangled = "?var@@3PE5ClassName@@0H5ClassName@@0";
		msTruth =
			"int const volatile __based(void) ClassName::* __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation036()
			throws Exception {
		mangled = "?var@@3PE$A5ClassName@@0H5ClassName@@0";
		msTruth =
			"int const volatile __based(void) ClassName::^ __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation037()
			throws Exception {
		mangled = "?var@@3PE$A5ClassName@@0H$A5ClassName@@0";
		msTruth =
			"int const volatile __based(void) ClassName::^ __ptr64 const volatile __based(void) var"; //No ClassName in tail
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation038()
			throws Exception {
		mangled = "?var@@3PE$B5ClassName@@0H5ClassName@@0";
		msTruth =
			"cli::pin_ptr<int const volatile __based(void) ClassName::* __ptr64 const volatile __based(void) var";
		mdTruth =
			"cli::pin_ptr<int >const volatile __based(void) ClassName::* __ptr64 const volatile __based(void) var";
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation039()
			throws Exception {
		mangled = "?var@@3PE$B5ClassName@@0H$B5ClassName@@0";
		msTruth =
			"cli::pin_ptr<int const volatile __based(void) ClassName::* __ptr64 const volatile __based(void) var"; //No ClassName in tail
		mdTruth =
			"cli::pin_ptr<int >const volatile __based(void) ClassName::* __ptr64 const volatile __based(void) var"; //No ClassName in tail
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation040()
			throws Exception {
		mangled = "?var@@3PE$C5ClassName@@0H5ClassName@@0";
		msTruth =
			"int const volatile __based(void) ClassName::% __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation041()
			throws Exception {
		mangled = "?var@@3PE$C5ClassName@@0H$C5ClassName@@0";
		msTruth =
			"int const volatile __based(void) ClassName::% __ptr64 const volatile __based(void) ClassName::% var"; //Yes ClassName in tail (ClassName only if *&^% there, which it won't be for the tail????)
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation042()
			throws Exception {
		//change P to ? and lose pointer modifiers such as cli::pin_ptr<> and ClassName::, so it acts like tail cvmod, except tail cvmod
		// still doesn't have a referrenced type that is parsed after it (yet it might have a referrenced type (just parsed before it)--look at factory recipe model !!!
		mangled = "?var@@3?E$B5ClassName@@0H5ClassName@@0";
		msTruth = "int const volatile __based(void) __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation043()
			throws Exception {
		mangled = "?var@@3?E$CE$B5ClassName@@0H5ClassName@@0"; //with $C, the ClassName comes back... the pin_ptr did not...
		msTruth =
			"int const volatile __based(void) ClassName::% __ptr64 __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedProperties_And_DollarDollar_Debug_In_Progress_moremoremore2_variation044()
			throws Exception {
		mangled = "?var@@3?E$BE$C5ClassName@@0H5ClassName@@0"; //with $C, the ClassName comes back... the pin_ptr did not... even if I reverse the $C and $B
		msTruth =
			"int const volatile __based(void) ClassName::% __ptr64 __ptr64 const volatile __based(void) var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_aa() throws Exception {
		mangled = "?FN@@QEAM@BE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64 volatile) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ab() throws Exception {
		mangled = "?FN@@QEAM@AE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL & __ptr64) __ptr64"; //MSFT is missing '>'
		//mdtruth = "public: __clrcall FN(cli::pin_ptr<class CL & __ptr64>) __ptr64"; //MSFT is missing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >& __ptr64) __ptr64"; //MSFT is missing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ac() throws Exception {
		mangled = "?FN@@QEAM@AE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ad() throws Exception {
		mangled = "?FN@@QEAM@AE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL & __ptr64) __ptr64"; //MSFT is missing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >& __ptr64) __ptr64"; //Guess as to where '>' belongs
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ae() throws Exception {
		mangled = "?FN@@QEAM@AE$CAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_af() throws Exception {
		mangled = "?FN@@QEAM@PE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL ^ __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ag() throws Exception {
		mangled = "?FN@@QEAM@PE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL * __ptr64) __ptr64"; //MSFT is missing '>'
		//mdtruth = "public: __clrcall FN(cli::pin_ptr<class CL * __ptr64>) __ptr64"; //MSFT is missing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >* __ptr64) __ptr64"; //MSFT is missing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ah() throws Exception {
		mangled = "?FN@@QEAM@PE$CAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ai() throws Exception {
		//NEW HAND-MADE
		mangled = "?FN@@QEAM@BE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64 volatile) __ptr64";
		mdTruth = msTruth;
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_aj() throws Exception {
		mangled = "?FN@@QEAM@SE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL ^ __ptr64 const volatile) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ak() throws Exception {
		mangled = "?FN@@QEAM@AE$AE$AE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(class CL % __ptr64 __ptr64 __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_al() throws Exception {
		mangled = "?FN@@QEAM@AE$AE$AE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL % __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >% __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_am() throws Exception {
		mangled = "?FN@@QEAM@AE$AE$BE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL % __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >% __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_an() throws Exception {
		mangled = "?FN@@QEAM@AE$BE$AE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL % __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >% __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ao() throws Exception {
		mangled = "?FN@@QEAM@AE$BE$BE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL & __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >& __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ap() throws Exception {
		mangled = "?FN@@QEAM@PE$AE$AE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL ^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_aq() throws Exception {
		mangled = "?FN@@QEAM@PE$AE$BE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL ^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ar() throws Exception {
		mangled = "?FN@@QEAM@PE$BE$AE$AAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL ^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >^ __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_as() throws Exception {
		mangled = "?FN@@QEAM@PE$BE$BE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL * __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >* __ptr64 __ptr64 __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_at() throws Exception {
		mangled = "?FN@@QEAM@PE$BAVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::pin_ptr<class CL * __ptr64) __ptr64"; //MSFT is missing a closing '>'
		mdTruth = "public: __clrcall FN(cli::pin_ptr<class CL >* __ptr64) __ptr64"; //MSFT is missing a closing '>'
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_au() throws Exception {
		mangled = "?FN@@QEAM@PE$02AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL ,2>^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_av() throws Exception {
		mangled = "?FN@@QEAM@PE$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_aw() throws Exception {
		mangled = "?FN@@QEAM@QE$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ax() throws Exception {
		mangled = "?FN@@QEAM@RE$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ay() throws Exception {
		mangled = "?FN@@QEAM@SE$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_az() throws Exception {
		mangled = "?FN@@QEAM@BE$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_ba() throws Exception {
		mangled = "?FN@@QEAM@P$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bb() throws Exception {
		mangled = "?FN@@QEAM@Q$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bc() throws Exception {
		mangled = "?FN@@QEAM@R$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bd() throws Exception {
		mangled = "?FN@@QEAM@S$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_be() throws Exception {
		mangled = "?FN@@QEAM@B$01AVCL@@@Z";
		msTruth = "public: __clrcall FN(cli::array<class CL >^) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bf() throws Exception {
		mangled =
			"??1?$name0@PEAUname1@@V?$name2@PEAUname1@@$0A@P6APEAXPEAX@Z$1?name3@@$$FYAPEAX0@ZP6AAEAPEAU1@AEAPEAU1@@Z$1?name4@?$name5@PEAUname1@@@@$$FSAAEAPEAU1@1@Z@@@@$$FUEAA@XZ";
		msTruth =
			"public: virtual __cdecl name0<struct name1 * __ptr64,class name2<struct name1 * __ptr64,0,void * __ptr64 (__cdecl*)(void * __ptr64),&void * __ptr64 __cdecl name3(void * __ptr64),struct name1 * __ptr64 & __ptr64 (__cdecl*)(struct name1 * __ptr64 & __ptr64),&public: static struct name1 * __ptr64 & __ptr64 __cdecl name5<struct name1 * __ptr64>::name4(struct name1 * __ptr64 & __ptr64)> >::~name0<struct name1 * __ptr64,class name2<struct name1 * __ptr64,0,void * __ptr64 (__cdecl*)(void * __ptr64),&void * __ptr64 __cdecl name3(void * __ptr64),struct name1 * __ptr64 & __ptr64 (__cdecl*)(struct name1 * __ptr64 & __ptr64),&public: static struct name1 * __ptr64 & __ptr64 __cdecl name5<struct name1 * __ptr64>::name4(struct name1 * __ptr64 & __ptr64)> >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bg() throws Exception {
		mangled =
			"??0name0@name1@@QEAA@AEBVname2@1@U?$name3@$$A6AXU?$name4@Vname5@name1@@@name1@@@Z@1@AEBU?$name6@Vname7@name1@@@1@@Z";
		msTruth =
			"public: __cdecl name1::name0::name0(class name1::name2 const & __ptr64,struct name1::name3<void __cdecl(struct name1::name4<class name1::name5>)>,struct name1::name6<class name1::name7> const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bh() throws Exception {
		mangled = "?wmain@@$$HYAHXZ"; //This is the only real $$H example we have.
		msTruth = "int __cdecl wmain(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Manufactured --KEEP, Need to add tests for isC and referredToType
	@Test
	public void testManagedProperties_bi() throws Exception {
		mangled = "??0name0@name1@name2@name3@@$$FQE$AAM@XZ";
		msTruth = "public: __clrcall name3::name2::name1::name0::name0(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_Single1() throws Exception {
		mangled = "?get@C@@$$FQ$CAMHXZ";
		msTruth = "public: int __clrcall C::get(void)%";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//hand-made... no longer valid with newer undname
//	@Test
//	public void testManagedExtensions1_Single2() throws Exception {
//		mangled = "?get@C@@$$FQE$AE$BEI$CAMHXZ";
////		mangled = "?get@C@@QE$AAMHXZ";
//		mstruth = "public: int __clrcall C::get(void)% __ptr64 __ptr64 __ptr64 __restrict";
//	mdtruth = mstruth;
//		demangleAndTest();
//	}

	@Test
	public void testManagedExtensions1_Single2xx() throws Exception {
		mangled = "?get@C@@$$FQE$AE$AEI$CDMHXZ";
		msTruth =
			"public: int __clrcall C::get(void)const volatile % __ptr64 __ptr64 __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_Single2xxx() throws Exception {
		mangled = "?get@C@@$$FQEI$AE$AEIF$CDMHXZ";
		msTruth =
			"public: int __clrcall C::get(void)const volatile __unaligned % __ptr64 __restrict __ptr64 __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_Single3() throws Exception {
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_aa() throws Exception {
		mangled =
			"??0name0@name1@name2@name3@name4@@$$FIE$AAM@PE$AAVname5@name6@name7@name8@@Vname9@678@@Z";
		msTruth =
			"protected: __clrcall name4::name3::name2::name1::name0::name0(class name8::name7::name6::name5 ^ __ptr64,class name8::name7::name6::name9) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ab() throws Exception {
		//hand-made... no longer valid with newer undname
//		mangled = "?get@C@@$$FQE$AE$BEI$CAMHXZ";
////		mangled = "?get@C@@QE$AAMHXZ";
//		mstruth = "public: int __clrcall C::get(void)% __ptr64 __ptr64 __ptr64 __restrict";
//		mdtruth = mstruth;
//		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ac() throws Exception {
		mangled = "?get@C@@$$FQE$AAMHXZ";
//		mangled = "?get@C@@QE$AAMHXZ";
		msTruth = "public: int __clrcall C::get(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ad() throws Exception {
		mangled = "?get@C@@$$FQ$CEIAMHXZ"; // manufactured (has $C)
		msTruth = "public: int __clrcall C::get(void)% __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ae() throws Exception {
		mangled = "?get@C@@$$FQEI$AAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ae_addThrow() throws Exception {
		mangled = "?get@C@@$$FQEI$AAMHXHH@"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __ptr64 __restrict throw(int,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_af() throws Exception {
		mangled = "?get@C@@$$FQ$AEIAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ag() throws Exception {
		mangled = "?get@C@@$$FQIE$AAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __restrict __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ah() throws Exception {
		mangled = "?get@C@@$$FQ$AIEAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __restrict __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ai() throws Exception {
		mangled = "?get@C@@$$FQE$AIAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_aj() throws Exception {
		mangled = "?get@C@@$$FQI$AEAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __restrict __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ak() throws Exception {
		mangled = "?get@C@@$$FQE$AEAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __ptr64 __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_al() throws Exception {
		mangled = "?get@C@@$$FQI$AIAMHXZ"; // manufactured
		msTruth = "public: int __clrcall C::get(void) __restrict __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_am() throws Exception {
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_an() throws Exception {
		mangled = "?vp4@@3PECRE$BAXEC";
		msTruth = "void * __ptr64 volatile * __ptr64 volatile __ptr64 vp4";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_an_mod1() throws Exception {
		mangled = "?vp4@@3PECRE$BAHEC";
		msTruth = "cli::pin_ptr<int * __ptr64 volatile * __ptr64 volatile __ptr64 vp4";
		mdTruth = "cli::pin_ptr<int >* __ptr64 volatile * __ptr64 volatile __ptr64 vp4";
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ao() throws Exception {
		mangled = "?get@B@@$$FQEAAHXZ"; // $$F
		msTruth = "public: int __cdecl B::get(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ap() throws Exception {
		mangled = "?get@C@@$$FQE$AAMHXZ";
		msTruth = "public: int __clrcall C::get(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_aq() throws Exception {
		mangled = "?get@C@@$$FQEIF$AFIEFAMHXZ"; // manufactured
		msTruth =
			"public: int __clrcall C::get(void)__unaligned __unaligned __unaligned __ptr64 __restrict __restrict __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ar() throws Exception {
		mangled = "??0C@@$$FQE$AAM@XZ"; // $$F and $ before AA
		msTruth = "public: __clrcall C::C(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_as() throws Exception {
		mangled = "?main@@$$HYAHHQEAPEAD@Z"; // $$H
		msTruth = "int __cdecl main(int,char * __ptr64 * __ptr64 const)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_at() throws Exception {
		mangled = "?useMe@@$$FYAHAEAPE$CAVB@@@Z";
		msTruth = "int __cdecl useMe(class B % __ptr64 & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_au() throws Exception {
		mangled = "?useMe@@YAHAEAPE$CAVB@@@Z";
		msTruth = "int __cdecl useMe(class B % __ptr64 & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_av() throws Exception {
		mangled = "?useMe2@@$$FYAHAE$CAVB@@@Z";
		msTruth = "int __cdecl useMe2(class B % __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_aw() throws Exception {
		mangled = "?useMe2@@YAHAE$CAVB@@@Z";
		msTruth = "int __cdecl useMe2(class B % __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ax() throws Exception {
		mangled = "?GetStream@FileBase@@$$FUE$AAMPEAHXZ";
		msTruth = "public: virtual int * __ptr64 __clrcall FileBase::GetStream(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_ay() throws Exception {
		mangled = "??0FileBase@@$$FQE$AAM@XZ";
		msTruth = "public: __clrcall FileBase::FileBase(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testManagedExtensions1_az() throws Exception {
		mangled = "??0FileDerived@@$$FQE$AAM@XZ";
		msTruth = "public: __clrcall FileDerived::FileDerived(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSCR_10801a() throws Exception {
		mangled =
			"??$name0@V?$name1@GU?$name2@G@name3@@V?$name4@G@2@Vname5@@@name3@@V12@@name3@@YA?AU?$name6@V?$name1@GU?$name2@G@name3@@V?$name4@G@2@Vname5@@@name3@@V12@@0@V?$name1@GU?$name2@G@name3@@V?$name4@G@2@Vname5@@@0@0@Z";
		msTruth =
			"struct name3::name6<class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5>,class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5> > __cdecl name3::name0<class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5>,class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5> >(class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5>,class name3::name1<unsigned short,struct name3::name2<unsigned short>,class name3::name4<unsigned short>,class name5>)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSCR_10801b() throws Exception {
		mangled =
			"??$name0@V?$name1@PEAUname2@@V?$name3@PEAUname2@@@name4@@@name4@@P6A_NPEAUname2@@0@Z@name4@@YA?AU?$name5@V?$name1@PEAUname2@@V?$name3@PEAUname2@@@name4@@@name4@@V12@@0@V?$name1@PEAUname2@@V?$name3@PEAUname2@@@name4@@@0@0P6A_NPEAUname2@@1@Z@Z";
		msTruth =
			"struct name4::name5<class name4::name1<struct name2 * __ptr64,class name4::name3<struct name2 * __ptr64> >,class name4::name1<struct name2 * __ptr64,class name4::name3<struct name2 * __ptr64> > > __cdecl name4::name0<class name4::name1<struct name2 * __ptr64,class name4::name3<struct name2 * __ptr64> >,bool (__cdecl*)(struct name2 * __ptr64,struct name2 * __ptr64)>(class name4::name1<struct name2 * __ptr64,class name4::name3<struct name2 * __ptr64> >,class name4::name1<struct name2 * __ptr64,class name4::name3<struct name2 * __ptr64> >,bool (__cdecl*)(struct name2 * __ptr64,struct name2 * __ptr64))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSCR_10801c() throws Exception {
		mangled =
			"??__Fname0@?1??name1@?$name2@V?$name3@$0GE@Vname4@name5@@@name5@@$03V?$name6@V?$name3@$0GE@Vname4@name5@@@name5@@$03@2@@name5@@KAAEAVname7@2@XZ@YAXXZ";
		msTruth =
			"void __cdecl `protected: static class name2<class name5::name3<100,class name5::name4>,4,class name5::name6<class name5::name3<100,class name5::name4>,4> >::name7 & __ptr64 __cdecl name5::name2<class name5::name3<100,class name5::name4>,4,class name5::name6<class name5::name3<100,class name5::name4>,4> >::name1(void)'::`2'::`dynamic atexit destructor for 'name0''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_aa() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ab() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ac() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ad() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ae() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_af() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ag() throws Exception {
		mangled =
			"?name0@?$name1@Vname2@@Vname3@@@@AEAAXP8name2@@EAAPEAVname3@@XZP82@EAAJPEAV3@@ZPEBGHH@Z";
		msTruth =
			"private: void __cdecl name1<class name2,class name3>::name0(class name3 * __ptr64 (__cdecl name2::*)(void) __ptr64,long (__cdecl name2::*)(class name3 * __ptr64) __ptr64,unsigned short const * __ptr64,int,int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ah() throws Exception {
		mangled =
			"??$?4V?$name0@V?$name1@Uname2@@$1?name3@@3Uname4@@B@@@@@?$name0@V?$name1@Uname5@name6@@$1?name7@@3Uname4@@B@@@@QEAAAEAV0@AEBV?$name0@V?$name1@Uname2@@$1?name3@@3Uname4@@B@@@@@Z";
		msTruth =
			"public: class name0<class name1<struct name6::name5,&struct name4 const name7> > & __ptr64 __cdecl name0<class name1<struct name6::name5,&struct name4 const name7> >::operator=<class name0<class name1<struct name2,&struct name4 const name3> > >(class name0<class name1<struct name2,&struct name4 const name3> > const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ai() throws Exception {
		mangled =
			"??0?$name0@Vname1@@Vname2@@@@QEAA@P8name1@@EAAPEAVname2@@XZP81@EAAJPEAV2@@ZPEBGHZZ";
		msTruth =
			"public: __cdecl name0<class name1,class name2>::name0<class name1,class name2>(class name2 * __ptr64 (__cdecl name1::*)(void) __ptr64,long (__cdecl name1::*)(class name2 * __ptr64) __ptr64,unsigned short const * __ptr64,int,...) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Real symbol: Keep.
	@Test
	public void testMore_aj() throws Exception {
		mangled = "?.cctor@name1@name2@@$$FSMXXZ";
		msTruth = "?.cctor@name1@name2@@$$FSMXXZ"; //undname says: "The system cannot find the file specified."
		mdTruth = "public: static void __clrcall name2::name1::.cctor(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_ak() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_al() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2HA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_am() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_an() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	//Manufactured; Keep.
	@Test
	public void testMore_ao() throws Exception {
		mangled = "?.cctor@@$$FYMXXZ";
		msTruth = "?.cctor@@$$FYMXXZ"; //undname says: "The system cannot find the file specified."
		mdTruth = "void __clrcall .cctor(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_ap() throws Exception {
		mangled = "?.cctor@name1@name2@name3@name4@name5@name6@@$$FSMXXZ";
		msTruth = "?.cctor@name1@name2@name3@name4@name5@name6@@$$FSMXXZ";
		mdTruth =
			"public: static void __clrcall name6::name5::name4::name3::name2::name1::.cctor(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_aq() throws Exception {
		mangled =
			"???__E?name0@name1@name2@@$$Q0V?$name3@PE$AAVname4@name5@@@2@A@@YMXXZ@?A0x09343ef7@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_ar() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2HA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static int name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_as() throws Exception {
		mangled =
			"???__F?name0@name1@name2@@$$Q0V?$name3@PE$AAVname4@name5@@@2@A@@YMXXZ@?A0x09343ef7@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic atexit destructor for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic atexit destructor for 'private: static class name2::name3<class name5::name4 ^ __ptr64> name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_at() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2W4name3@name4@2@A@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static enum name2::name4::name3 name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_au() throws Exception {
		mangled = "???__E?name0@name1@name2@@$$Q2_NA@@YMXXZ@?A0x3d49b2d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static bool name2::name1::name0''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testMore_av() throws Exception {
		mangled = "??_Sname0@@6B@";
		msTruth = "const name0::`local vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_aw() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6APEAXPEAUname2@@_J@ZEA";
		msTruth =
			"void * __ptr64 (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,__int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ax() throws Exception {
		// manufactured data (added "1a@b@")
		mangled = "?name0@?1??name1@@91name2@name3@@4P6APEAXPEAUname4@@_J@ZEA";
		msTruth =
			"void * __ptr64 (__cdecl* __ptr64 name3::name2::name1::`name1'::`2'::name0)(struct name4 * __ptr64,__int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ay() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AHPEAUname2@@HPEAX@ZEA";
		msTruth =
			"int (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,int,void * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_az() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AHPEAUname2@@PEAXHP6AH11_J@Z2I@ZEA";
		msTruth =
			"int (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,void * __ptr64,int,int (__cdecl*)(void * __ptr64,void * __ptr64,__int64),__int64,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_ba() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AJPEAUname2@@PEBGHPEAPEAUname3@@@ZEA";
		msTruth =
			"long (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,unsigned short const * __ptr64,int,struct name3 * __ptr64 * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bb() throws Exception {
		mangled = "?name0@?4??name1@@9@4QBDB";
		msTruth = "char const * const `name1'::`5'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bc() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AHPEAUname2@@@ZEA";
		msTruth = "int (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bd() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6APEAUname2@@H@ZEA";
		msTruth = "struct name2 * __ptr64 (__cdecl* __ptr64 `name1'::`2'::name0)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_be() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6AXPEAUname2@@P6AHPEAX1@Z1@ZEA";
		msTruth =
			"void (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,int (__cdecl*)(void * __ptr64,void * __ptr64),void * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bf() throws Exception {
		mangled = "?name0@?1??name1@@9@4Uname2@@B";
		msTruth = "struct name2 const `name1'::`2'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bg() throws Exception {
		mangled = "?name0@?1??name1@@9@4P6APEAXPEAUname2@@H@ZEA";
		msTruth =
			"void * __ptr64 (__cdecl* __ptr64 `name1'::`2'::name0)(struct name2 * __ptr64,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bh() throws Exception {
		mangled = "?name0@?1??name1@@9@4Uname2@@A";
		msTruth = "struct name2 `name1'::`2'::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bi() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@name3@@@name4@name5@@@?$name6@Vname7@?$name1@Vname2@name3@@@name4@name5@@$0A@@name5@@QEAAXPEBV?$name1@Vname2@name3@@@name4@1@P8231@EBAXPEAVname7@231@@Z@Z";
		msTruth =
			"public: void __cdecl name5::name6<class name5::name4::name1<class name3::name2>::name7,0>::name0<class name5::name4::name1<class name3::name2> >(class name5::name4::name1<class name3::name2> const * __ptr64,void (__cdecl name5::name4::name1<class name3::name2>::*)(class name5::name4::name1<class name3::name2>::name7 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bj() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@?$name3@G@name4@@@name5@name6@@@?$name7@Vname8@?$name1@Vname2@?$name3@G@name4@@@name5@name6@@$0A@@name6@@QEAAXPEBV?$name1@Vname2@?$name3@G@name4@@@name5@1@P8231@EBAXPEAVname8@231@@Z@Z";
		msTruth =
			"public: void __cdecl name6::name7<class name6::name5::name1<class name4::name3<unsigned short>::name2>::name8,0>::name0<class name6::name5::name1<class name4::name3<unsigned short>::name2> >(class name6::name5::name1<class name4::name3<unsigned short>::name2> const * __ptr64,void (__cdecl name6::name5::name1<class name4::name3<unsigned short>::name2>::*)(class name6::name5::name1<class name4::name3<unsigned short>::name2>::name8 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bk() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@name3@@@name4@name5@@@?$name6@Vname7@?$name1@Vname2@name3@@@name4@name5@@$0A@@name5@@QEAAXPEBV?$name1@Vname2@name3@@@name4@1@P8231@EBAXPEAVname7@231@@Z@Z";
		msTruth =
			"public: void __cdecl name5::name6<class name5::name4::name1<class name3::name2>::name7,0>::name0<class name5::name4::name1<class name3::name2> >(class name5::name4::name1<class name3::name2> const * __ptr64,void (__cdecl name5::name4::name1<class name3::name2>::*)(class name5::name4::name1<class name3::name2>::name7 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bl() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@name3@@@name4@name5@@@?$name6@Vname7@?$name1@Vname2@name3@@@name4@name5@@$0A@@name5@@QEAAXPEBV?$name1@Vname2@name3@@@name4@1@P8231@EBAXPEAVname7@231@@Z@Z";
		msTruth =
			"public: void __cdecl name5::name6<class name5::name4::name1<class name3::name2>::name7,0>::name0<class name5::name4::name1<class name3::name2> >(class name5::name4::name1<class name3::name2> const * __ptr64,void (__cdecl name5::name4::name1<class name3::name2>::*)(class name5::name4::name1<class name3::name2>::name7 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bm() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@name3@@@name4@name5@@@?$name6@Vname7@?$name1@Vname2@name3@@@name4@name5@@$0A@@name5@@QEAAXPEBV?$name1@Vname2@name3@@@name4@1@P8231@EBAXPEAVname7@231@@Z@Z";
		msTruth =
			"public: void __cdecl name5::name6<class name5::name4::name1<class name3::name2>::name7,0>::name0<class name5::name4::name1<class name3::name2> >(class name5::name4::name1<class name3::name2> const * __ptr64,void (__cdecl name5::name4::name1<class name3::name2>::*)(class name5::name4::name1<class name3::name2>::name7 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bn() throws Exception {
		mangled =
			"??$name0@V?$name1@Vname2@?$name3@PEBUname4@@@name5@@@name6@name7@@@?$name8@Vname9@?$name1@Vname2@?$name3@PEBUname4@@@name5@@@name6@name7@@$0A@@name7@@QEAAXPEBV?$name1@Vname2@?$name3@PEBUname4@@@name5@@@name6@1@P8231@EBAXPEAVname9@231@@Z@Z";
		msTruth =
			"public: void __cdecl name7::name8<class name7::name6::name1<class name5::name3<struct name4 const * __ptr64>::name2>::name9,0>::name0<class name7::name6::name1<class name5::name3<struct name4 const * __ptr64>::name2> >(class name7::name6::name1<class name5::name3<struct name4 const * __ptr64>::name2> const * __ptr64,void (__cdecl name7::name6::name1<class name5::name3<struct name4 const * __ptr64>::name2>::*)(class name7::name6::name1<class name5::name3<struct name4 const * __ptr64>::name2>::name9 * __ptr64)const __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bo() throws Exception {
		mangled = "??_R17?0A@EC@name0@@8";
		msTruth = "name0::`RTTI Base Class Descriptor at (8,-1,0,66)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bp() throws Exception {
		mangled = "??_R17?0A@EA@name0@name1@@8";
		msTruth = "name1::name0::`RTTI Base Class Descriptor at (8,-1,0,64)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bq() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@1@@name1@@YA?AV?$name3@GU?$name0@G@name1@@V?$name2@G@2@Vname4@@@0@AEBV10@PEBG@Z";
		msTruth =
			"class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short> >(class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> const & __ptr64,unsigned short const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_br() throws Exception {
		mangled = "??$?4Uname0@@@?$name1@Uname2@@@name3@@QEAAPEAUname2@@AEBV?$name1@Uname0@@@1@@Z";
		msTruth =
			"public: struct name2 * __ptr64 __cdecl name3::name1<struct name2>::operator=<struct name0>(class name3::name1<struct name0> const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bs() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@1@@name1@@YA?AV?$name3@GU?$name0@G@name1@@V?$name2@G@2@Vname4@@@0@AEBV10@0@Z";
		msTruth =
			"class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short> >(class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> const & __ptr64,class name1::name3<unsigned short,struct name1::name0<unsigned short>,class name1::name2<unsigned short>,class name4> const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bt() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@name3@name4@@@name1@@YA?AV?$name5@GU?$name0@G@name1@@V?$name2@G@name3@name4@@Vname6@@@0@AEBV10@0@Z";
		msTruth =
			"class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short> >(class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64,class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bu() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@name3@name4@@@name1@@YA?AV?$name5@GU?$name0@G@name1@@V?$name2@G@name3@name4@@Vname6@@@0@AEBV10@PEBG@Z";
		msTruth =
			"class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short> >(class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64,unsigned short const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bv() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@name3@name4@@@name1@@YA?AV?$name5@GU?$name0@G@name1@@V?$name2@G@name3@name4@@Vname6@@@0@AEBV10@0@Z";
		msTruth =
			"class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short> >(class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64,class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bw() throws Exception {
		mangled =
			"??$?HGU?$name0@G@name1@@V?$name2@G@name3@name4@@@name1@@YA?AV?$name5@GU?$name0@G@name1@@V?$name2@G@name3@name4@@Vname6@@@0@AEBV10@PEBG@Z";
		msTruth =
			"class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> __cdecl name1::operator+<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short> >(class name1::name5<unsigned short,struct name1::name0<unsigned short>,class name4::name3::name2<unsigned short>,class name6> const & __ptr64,unsigned short const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bx() throws Exception {
		mangled = "?name0@name1@@AEAAHPEFBG0@Z";
		msTruth =
			"private: int __cdecl name1::name0(unsigned short const __unaligned * __ptr64,unsigned short const __unaligned * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_by() throws Exception {
		mangled = "?name0@?$name1@$0A@@@QEAAJPEFBG@Z";
		msTruth =
			"public: long __cdecl name1<0>::name0(unsigned short const __unaligned * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testMore_bz() throws Exception {
		mangled = "?name0@name1@@QEAAJPEAUname2@@PEFBG@Z";
		msTruth =
			"public: long __cdecl name1::name0(struct name2 * __ptr64,unsigned short const __unaligned * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_a() throws Exception {
		mangled = "??0name0@@QEAA@PEAVname1@@HHHHQEAY01HHHHHHHHH@Z";
		msTruth =
			"public: __cdecl name0::name0(class name1 * __ptr64,int,int,int,int,int (* __ptr64 const)[2],int,int,int,int,int,int,int,int) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_b() throws Exception {
		mangled = "??_7name0@?Aname1@@6Bname2@1@@";
		msTruth = "const `anonymous namespace'::name0::`vftable'{for `Aname1::name2'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_c() throws Exception {
		mangled =
			"??$name0@H$$A6AJPEAUname1@@PEAVname2@name3@@@Z@?$name4@HP6AJPEAUname1@@PEAVname2@name3@@@ZV?$name5@H@@V?$name5@P6AJPEAUname1@@PEAVname2@name3@@@Z@@@@QEAAJAEBHA6AJPEAUname1@@PEAVname2@name3@@@ZPEAVname6@0@@Z";
		msTruth =
			"public: long __cdecl name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name0<int,long __cdecl(struct name1 * __ptr64,class name3::name2 * __ptr64)>(int const & __ptr64,long (__cdecl&)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name4<int,long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64),class name5<int>,class name5<long (__cdecl*)(struct name1 * __ptr64,class name3::name2 * __ptr64)> >::name6 * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_d() throws Exception {
		mangled = "?name0@?Aname1@@YA?AUname2@@AEBU2@PEB_W1@Z";
		msTruth =
			"struct name2 __cdecl `anonymous namespace'::name0(struct name2 const & __ptr64,wchar_t const * __ptr64,wchar_t const * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_e() throws Exception {
		mangled = "??_7?$name0@H$H??_9name1@@$BHI@AAA@@?$name2@Vname1@@@@6B@";
		msTruth =
			"const name2<class name1>::name0<int,{[thunk]: __cdecl name1::`vcall'{120,{flat}}' }',0}>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_f() throws Exception {
		mangled = "??0?$name0@$$BY0BAE@G@@QEAA@PEAY0BAE@G@Z";
		msTruth =
			"public: __cdecl name0<unsigned short [260]>::name0<unsigned short [260]>(unsigned short (* __ptr64)[260]) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_g() throws Exception {
		//These have some sort of ascii hex string on the end, which looks like a UUID of sorts.  Am working backwords, and need to work with the PDB DIA to try to find out more, because even undname cannot handle it.
		mangled =
			"??0?$vector@V?$dynamic_storage@V?$type_list@U?$pair@V?$scope@PEAV?$OpcPartConsumer@VRelationship@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@5490177382edc8c65636dff106076ffc";
		msTruth =
			"??0?$vector@V?$dynamic_storage@V?$type_list@U?$pair@V?$scope@PEAV?$OpcPartConsumer@VRelationship@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@5490177382edc8c65636dff106076ffc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_h() throws Exception {
		mangled =
			"??0?$ByteReceiverCom@V?$scope@PEAV?$FiberStream@V?$FiberStreamClient@V?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@V?$scope@PEAV?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_musl@@@win_musl@@U?$const_policies@Ucom_policies@win_scope@@@win_scope@@@win_scope@@UIByteReceiver@@V?$ReceiverCom@V?$scope@PEAV?$FiberStream@V?$FiberStreamClient@V?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@V?$scope@PEAV?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_musl@@@win_musl@@U?$const_policies@Ucom_policies@win_scope@@@win_scope@@@win_scope@@UIByteReceiver@@V?$ScopeInnerStore@V?$scope@PEAV?$FiberStream@V?$FiberStreamClient@V?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@V?$scope@PEAV?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_musl@@@win_musl@@U?$const_policies@Ucom_policies@win_scope@@@win_scope@@@win_scope@@UIByteReceiver@@Ureport_policy_throw@2@@win_dox@@@win_dox@@@win_dox@@QEAA@V?$scope@PEAV?$FiberStream@V?$FiberStreamClient@V?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@V?$scope@PEAV?$ModelPartReferenceSender@VDiscard@Model@win_musl@@V?$scope@PEAV?$XpsPartReferenceConsumer@VXpsDiscardReceiver@win_dox@@VDiscard@Model@win_musl@@@xps_consumption@win_dox@@U?$const_policies@Ushared_policies@win_scope@@@win_scope@@@win_scope@@@xps_consumption@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_scope@@@win_musl@@@win_musl@@U?$const_policies@Ucom_policies@win_scope@@@win_scope@@@win_scope@@@Z";
		msTruth =
			"public: __cdecl win_dox::ByteReceiverCom<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,class win_dox::ReceiverCom<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,class win_dox::ScopeInnerStore<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,struct win_scope::report_policy_throw> > >::ByteReceiverCom<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >," +
				"class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,class win_dox::ReceiverCom<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,class win_dox::ScopeInnerStore<class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >,struct IByteReceiver,struct win_scope::report_policy_throw> > >(class win_scope::scope<class win_musl::FiberStream<class win_musl::FiberStreamClient<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > >,class win_scope::scope<class win_dox::xps_consumption::ModelPartReferenceSender<class win_musl::Model::Discard,class win_scope::scope<class win_dox::xps_consumption::XpsPartReferenceConsumer<class win_dox::XpsDiscardReceiver,class win_musl::Model::Discard> * __ptr64,struct win_scope::const_policies<struct win_scope::shared_policies> > > * __ptr64,struct win_scope::const_policies<struct win_scope::types_1<struct win_scope::counted_strong<struct win_scope::const_policies<struct win_scope::resource_policies> > > > > > > * __ptr64,struct win_scope::const_policies<struct win_scope::com_policies> >) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_h_genericized() throws Exception {
		mangled =
			"??0?$name0@V?$name1@PEAV?$name2@V?$name3@V?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@V?$name1@PEAV?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@U?$name12@U?$name15@U?$name16@U?$name12@Uname17@name14@@@name14@@@name14@@@name14@@@name14@@@name14@@@name7@@@name7@@U?$name12@Uname18@name14@@@name14@@@name14@@Uname19@@V?$name20@V?$name1@PEAV?$name2@V?$name3@V?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@V?$name1@PEAV?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@U?$name12@U?$name15@U?$name16@U?$name12@Uname17@name14@@@name14@@@name14@@@name14@@@name14@@@name14@@@name7@@@name7@@U?$name12@Uname18@name14@@@name14@@@name14@@Uname19@@V?$name21@V?$name1@PEAV?$name2@V?$name3@V?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@V?$name1@PEAV?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@U?$name12@U?$name15@U?$name16@U?$name12@Uname17@name14@@@name14@@@name14@@@name14@@@name14@@@name14@@@name7@@@name7@@U?$name12@Uname18@name14@@@name14@@@name14@@Uname19@@Uname22@2@@name10@@@name10@@@name10@@QEAA@V?$name1@PEAV?$name2@V?$name3@V?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@V?$name1@PEAV?$name4@Vname5@name6@name7@@V?$name1@PEAV?$name8@Vname9@name10@@Vname5@name6@name7@@@name11@name10@@U?$name12@Uname13@name14@@@name14@@@name14@@@name11@name10@@U?$name12@U?$name15@U?$name16@U?$name12@Uname17@name14@@@name14@@@name14@@@name14@@@name14@@@name14@@@name7@@@name7@@U?$name12@Uname18@name14@@@name14@@@name14@@@Z";
		msTruth =
			"public: __cdecl name10::name0<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,class name10::name20<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,class name10::name21<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,struct name14::name22> > >::name0<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,class name10::name20<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,class name10::name21<class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >,struct name19,struct name14::name22> > >(class name14::name1<class name7::name2<class name7::name3<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > >,class name14::name1<class name10::name11::name4<class name7::name6::name5,class name14::name1<class name10::name11::name8<class name10::name9,class name7::name6::name5> * __ptr64,struct name14::name12<struct name14::name13> > > * __ptr64,struct name14::name12<struct name14::name15<struct name14::name16<struct name14::name12<struct name14::name17> > > > > > > * __ptr64,struct name14::name12<struct name14::name18> >) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFileSamples_i() throws Exception {
		mangled = "??0?$name0@$$CBUname1@@@name2@@QEAA@XZ";
		msTruth =
			"public: __cdecl name2::name0<struct name1 const >::name0<struct name1 const >(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_a() throws Exception {
		mangled = "?VarName@@3PBHB";
		msTruth = "int const * const VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_b() throws Exception {
		mangled = "?VarName@@3PEIFDHEIFD";
		msTruth =
			"int const volatile __unaligned * __ptr64 __restrict const volatile __unaligned __ptr64 __restrict VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_c() throws Exception {
		mangled = "?VarName@@3PEIFDHEIFA";
		msTruth =
			"int const volatile __unaligned * __ptr64 __restrict __unaligned __ptr64 __restrict VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_d() throws Exception {
		mangled = "?VarName@@3P6AHH@ZEA";
		msTruth = "int (__cdecl* __ptr64 VarName)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_e() throws Exception {
		mangled = "?VarName@@3P8ClassName@@EDAHXZED";
		msTruth =
			"int (__cdecl ClassName::*const volatile __ptr64 VarName)(void)const volatile __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_f() throws Exception {
		mangled = "?FnName@@YAXSAH@Z";
		msTruth = "void __cdecl FnName(int * const volatile)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_g() throws Exception {
		mangled = "?VarName@@3HD";
		msTruth = "int const volatile VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_h() throws Exception {
		mangled = "?VarName@@3PBHA";
		msTruth = "int const * VarName";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_i() throws Exception {
		mangled = "?Name@@3CA";
		msTruth = "signed char Name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Temporary, while trying to restructure code.
	@Test
	public void testNewParserStructure_j() throws Exception {
		// $B
		mangled = "??_9name0@@$BBII@AA";
		msTruth = "[thunk]: __cdecl name0::`vcall'{392,{flat}}' }'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing1() throws Exception {
		mangled = "?Var@@3PEAHN5";
		msTruth = "int * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing2() throws Exception {
		mangled = "?Var@@3PEDHN5";
		msTruth = "int const volatile * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing3() throws Exception {
		mangled = "?Var@@3PEDHEIFN5";
		msTruth = "int const volatile * __ptr64 ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing4() throws Exception {
		mangled = "?Var@@3PEN5HA";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing5() throws Exception {
		mangled = "?Var@@3PEN5HD";
		msTruth = "int";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testSpacing6() throws Exception {
		mangled = "?foo@@QEAAXXZ";
		msTruth = "public: void __cdecl foo(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAnonymousNamespaceBackreference_a() throws Exception {
		mangled = "?var@abc@?Axyz@1@3HA";
		msTruth = "int abc::`anonymous namespace'::abc::var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testAnonymousNamespaceBackreference_b() throws Exception {
		mangled = "?var@abc@?Axyz@2@3HA";
		msTruth = "int Axyz::`anonymous namespace'::abc::var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void test_e304() throws Exception {
		mangled =
			"?__abi_name0?$name1@P$AAVname2@name3@@____abi_name4@?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@?$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@2name3@@U$AAGJIPAP$AAVname2@6@@Z";
		msTruth = "unknown";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: Eventually delete.  Need to fix 304_b first, as 304_a uses that construct.
	@Test
	public void test_e304_breakdown_analysis_000() throws Exception {
		mangled = "?name0@?$name1@P$AAVname2@name3@@";
		msTruth = "unknown"; //" ?? ?? :: ?? ::blah"
		mdTruth = "name1<class name3::name2 ^>::name0"; //???
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	//TODO: Eventually delete.  Need to fix 304_b first, as 304_a uses that construct.
	@Test
	public void test_e304_breakdown_analysis_001() throws Exception {
		mangled =
			"?__abi_name4@?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@?$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@2name3@@U$AAGJIPAP$AAVname2@6@@Z";
		msTruth =
			"public: virtual long __stdcall name3::name5::name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >::[name7::name6::name5::name1<class name3::name2 ^>]::__abi_name4(unsigned int,class name3::name2 ^ *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: Eventually delete.  Partial string from 304_a; changed backref from 6 to 0.
	// "?x@Platform" + chars 234-258
	@Test
	public void test_e304_a_breakdown_analysis_002() throws Exception {
		mangled = "?x@name3@@U$AAGJIPAP$AAVname2@0@@Z";
		msTruth = "public: virtual long __stdcall name3::x(unsigned int,class x::name2 ^ *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// "?xxx@yyy@@" + chars 171-194
	@Test
	public void testGDTSD304_a_breakdown_analysis_004() throws Exception {
		mangled = "?xxx@yyy@@U$AAGJIPAP$AAVname2@0@@Z";
		msTruth = "public: virtual long __stdcall yyy::xxx(unsigned int,class xxx::name2 ^ *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// '?' + chars 100-162 + "x@Platform@@"
	@Test
	public void testGDTSD304_a_breakdown_analysis_005() throws Exception {
		mangled = "??$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@x@Platform@@";
		msTruth =
			" ?? Platform::x::name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >";
		mdTruth =
			"Platform::x::name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	// '?' + chars 100-194, replace first backreference with 'x@' and second 6->0
	@Test
	public void testGDTSD304_a_breakdown_analysis_006() throws Exception {
		mangled =
			"??$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@x@name3@@U$AAGJIPAP$AAVname2@0@@Z";
		msTruth =
			"public: virtual long __stdcall name3::x::name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >(unsigned int,class x::name2 ^ *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// '?' + chars 12-37 + '@'
	@Test
	public void testGDTSD304_a_breakdown_analysis_007() throws Exception {
		mangled = "??$name1@P$AAVname2@name3@@@";
		msTruth = " ?? name1<class name3::name2 ^>";
		mdTruth = "name1<class name3::name2 ^>";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	// '?' + chars 40-99
	@Test
	public void testGDTSD304_a_breakdown_analysis_008() throws Exception {
		mangled = "?__abi_name4@?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@";
		msTruth = " ?? ?? ::[name7::name6::name5::name1<class name3::name2 ^>]::__abi_name4";
		mdTruth = "[name7::name6::name5::name1<class name3::name2 ^>]::__abi_name4";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	// '?' + chars 100-162
	@Test
	public void testGDTSD304_a_breakdown_analysis_009() throws Exception {
		mangled = "??$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@";
		msTruth = " ?? name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >";
		mdTruth = "name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >";
		//TODO: Create MDMangVS2015 Specialization for this problem and then remove "mstruth = mdtruth"
		msTruth = mdTruth;
		demangleAndTest();
	}

	// '?' + chars 40-194 (backref 6->0 and 2->0)
	@Test
	public void testGDTSD304_a_breakdown_analysis_010() throws Exception {
		mangled =
			"?__abi_name4@?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@?$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@0name3@@U$AAGJIPAP$AAVname2@0@@Z";
		msTruth =
			"public: virtual long __stdcall name3::__abi_name4::name8<class name3::name2 ^,struct name10::name9<class name3::name2 ^> >::[name7::name6::name5::name1<class name3::name2 ^>]::__abi_name4(unsigned int,class __abi_name4::name2 ^ *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// chars 0-37
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testGDTSD304_a_breakdown_analysis_011() throws Exception {
		mangled = "?__abi_name0?$name1@P$AAVname2@name3@@";
		msTruth = mangled;
		mdTruth = msTruth;
		demangleAndTest();
	}

	// chars 12-37
	@Test
	public void testGDTSD304_a_breakdown_analysis_012() throws Exception {
		mangled = "?$name1@P$AAVname2@name3@@";
		msTruth = "name1<class name3::name2 ^>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: Eventually delete.  Need to fix 304_b first, as 304_a uses that construct.
	@Test
	public void testGDTSD304_a_breakdown_analysis_013() throws Exception {
		mangled =
			"?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@?$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@2name3@@U$AAGJIPAP$AAVname2@6@@Z";
		msTruth = mangled;
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_a() throws Exception {
		mangled = "?name0@?Qname1@name2@@?$Aname3@P$AAVname4@name2@@$00@2@U$AAGJPAKPAPAVname5@2@@Z";
		msTruth =
			"public: virtual long __stdcall name2::Aname3<class name2::name4 ^,1>::[name2::name1]::name0(unsigned long *,class name2::name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_b() throws Exception {
		mangled = "?name0@?Qname1@name2@@?$name3@P$AAVname4@name2@@$00@2@U$AAGJPAKPAPAVname5@2@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name3<class name2::name4 ^,1>::[name2::name1]::name0(unsigned long *,class name2::name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_c() throws Exception {
		mangled = "?name0@?Qname1@name2@@?$Aname3@P$AAVname4@name2@@$00@2@U$AAGJPAPAUname5@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::Aname3<class name2::name4 ^,1>::[name2::name1]::name0(struct name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_d() throws Exception {
		mangled = "?name0@?Qname1@name2@@name3@name4@2@U$AAGJPAPAUname5@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name4::name3::[name2::name1]::name0(struct name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_e() throws Exception {
		mangled = "?name0@?Qname1@name2@@name3@name4@2@U$AAGJPAPAUname5@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name4::name3::[name2::name1]::name0(struct name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_f() throws Exception {
		mangled = "?name0@?Qname1@name2@@name3@name4@2@U$AAGJPAPAUname5@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name4::name3::[name2::name1]::name0(struct name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_g() throws Exception {
		mangled = "?name0@?Qname1@name2@@?$name3@E$00@2@U$AAGJPAPAUname4@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name3<unsigned char,1>::[name2::name1]::name0(struct name4 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_h() throws Exception {
		mangled = "?name0@?Qname1@name2@@?$name3@P$AAVname4@name2@@$00@2@U$AAGJPAPAUname5@@@Z";
		msTruth =
			"public: virtual long __stdcall name2::name3<class name2::name4 ^,1>::[name2::name1]::name0(struct name5 * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_h_mod0() throws Exception {
		mangled = "?name0@?Qname1@1@name2@@3HA";
		msTruth = "int name2::[name1::name1]::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_h_mod1() throws Exception {
		mangled = "?name0@?Qname1@name2@@name3@@3HA";
		msTruth = "int name3::[name2::name1]::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_h_mod2() throws Exception {
		mangled = "?name0@?Qname1@name2@@name3@name4@@3HA";
		msTruth = "int name4::name3::[name2::name1]::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGDTSD304_SysSet_h_mod3() throws Exception {
		mangled = "?name0@?Qname1@name2@name3@@name4@name5@@3HA";
		msTruth = "int name5::name4::[name3::name2::name1]::name0";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testGDTSD304_SysSet_h_mod4() throws Exception {
		mangled = "?name0@?Qname1@name2@@?Qname3@name4@@name5@@3HA";
		msTruth = "int name5::[name4::name3]::name0"; //Strips away one of the objects.
		//mdtruth = "int name5::[name4::name3]::[name2::name1]::name0"; // TODO: we need to mod our program to only allow one.
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: CREATE mstruth output (dispatcher)
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testGDTSD304_SysSet_h_mod5() throws Exception {
		mangled = "?name0@?Qname1@?Qname2@name3@@@name4@@3HA"; //Nested "?Q"
		msTruth = "?name0@?Qname1@?Qname2@name3@@@name4@@3HA"; //Nested "?Q"
		//mdtruth = "int name4::[[name3::name2]::name1]::name0"; // TODO: we need to mod our program to not allow nesting.
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_6769483() throws Exception { //was: testWin10_000
		mangled =
			"??$wrapped_invoke@P6AG_WPEAU_iobuf@@@Z_WPEAU1@G@__crt_state_management@@YAGP6AG_WPEAU_iobuf@@@Z01@Z";
		msTruth =
			"unsigned short __cdecl __crt_state_management::wrapped_invoke<unsigned short (__cdecl*)(wchar_t,struct _iobuf * __ptr64),wchar_t,struct _iobuf * __ptr64,unsigned short>(unsigned short (__cdecl*)(wchar_t,struct _iobuf * __ptr64),wchar_t,struct _iobuf * __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testWin10_1015829() throws Exception { //was: testWin10_001
		mangled =
			"?__abi_Platform_?$IBox@VGuid@Platform@@____abi_get_Value@?Q?$IBox@VGuid@Platform@@@Platform@@?$CustomBox@VGuid@Platform@@@Details@2@UE$AAAJPEAVGuid@2@@Z";
		msTruth = "unknown";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_1129365() throws Exception { //was: testWin10_002
		mangled =
			"?__abi_Windows_Foundation_Collections_IVectorChangedEventArgs____abi_get_Index@?QIVectorChangedEventArgs@Collections@Foundation@Windows@@VectorChangedEventArgs@Details@2Platform@@UE$AAAJPEAI@Z";
		msTruth =
			"public: virtual long __cdecl Platform::Collections::Details::VectorChangedEventArgs::[Windows::Foundation::Collections::IVectorChangedEventArgs]::__abi_Windows_Foundation_Collections_IVectorChangedEventArgs____abi_get_Index(unsigned int * __ptr64) __ptr64"; //ed's truth
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGT196() throws Exception {
		mangled =
			"??$make_pair@V?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@std@@V12@@std@@YA?AU?$pair@V?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@std@@V12@@0@V?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@0@0@Z";
		msTruth =
			"struct std::pair<class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70>,class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70> > __cdecl std::make_pair<class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70>,class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70> >(class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70>,class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short>,class _STL70>)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testJ() throws Exception {
		mangled = "?name0@name1@name2@@SAP$AAV12@HP$AAVname3@2@@Z";
		msTruth =
			"public: static class name2::name1 ^ __cdecl name2::name1::name0(int,class name2::name3 ^)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_00base() throws Exception {
		mangled = "?var@@3HA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_00test() throws Exception {
		mangled = "?@?var@@3HA";
		msTruth = "CV: int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_01base() throws Exception {
		mangled = "?$template@H";
		msTruth = "template<int>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//NOTE: This test is failing (we fail to fail) because we allow $template to be parsed as fragment and don't error when the symbol
	//  is truncated (no typeinfo).
	//Test showing that we cannot have MDTemplateNameAndArgumentsList after CodeView
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testCodeView_Simple_01test() throws Exception {
		mangled = "?@?$template@H";
		msTruth = ""; //GARBAGE
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Test showing that we can have a full typeinfo after (note '$' becomes part of name--not template)
	@Test
	public void testCodeView_Simple_01test_with_typeinfo() throws Exception {
		mangled = "?@?$name@H@@3HA";
		msTruth = "CV: int H::$name";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_02base() throws Exception {
		mangled = "??$template@H@@3HA";
		msTruth = "int template<int>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_02test() throws Exception {
		mangled = "?@??$template@H@@3HA";
		msTruth = "CV: int template<int>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_03base() throws Exception {
		mangled = "?@?var@@3HA";
		msTruth = "CV: int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_03test() throws Exception {
		mangled = "?@?@?var@@3HA";
		msTruth = ""; //GARBAGE
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_04base() throws Exception {
		mangled = "??0abc@@3HA";
		msTruth = "int abc::abc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_04test() throws Exception {
		mangled = "?@??0abc@@3HA";
		msTruth = "CV: int abc::abc";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_05base() throws Exception {
		mangled = "???__Eabc@@3HA";
		msTruth = "int `dynamic initializer for 'abc''";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCodeView_Simple_05test() throws Exception {
		mangled = "?@???__Eabc@@3HA";
		msTruth = "CV: int `dynamic initializer for 'abc''";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testUnknown1() throws Exception {
		mangled =
			"?base@?$ConstReverseBidirectionalIterator@$RTValue@EAAABAAB@@Generic@StlClr@VisualC@Microsoft@@$$FQE$AAMPE$AAU?$IBidirectionalIterator@$RTValue@EAAABAAB@@2345@XZ";
		msTruth =
			"public: struct Microsoft::VisualC::StlClr::Generic::IBidirectionalIterator<TValue> ^ __ptr64 __clrcall Microsoft::VisualC::StlClr::Generic::ConstReverseBidirectionalIterator<TValue>::base(void) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testUnknown2() throws Exception { //Real Symbol from Windows 10
		mangled = "??_C@_00CNPNBAHC@?$AA@FNODOBFM@";
//		mstruth1 = " ?? ?? ::FNODOBFM::`string'";
//	    mstruth2 = " ?? ::FNODOBFM::`string'";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Seems like a pattern where they truncate the symbol and append a 32-character (128-bit) hash code on the end instead.  Not sure what/how we
	// should deal with this (and potentially others--this came from Windows 7): give partial results?  By running with parse info output, we can
	// see that it is a series of nested templates to start, which cuts off during a deep nesting.
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testUnknown3() throws Exception {
		mangled =
			"??$attach@PEAV?$UnknownOnlyLite@V?$OpcCertificateEnumeratorCom@V?$scope@PEAV?$SimpleEnumerator@V?$scope@PEAVOpcCertificateSetImpl@win_dox@@U?$const_policies@U?$types_1@U?$counted_strong@U?$const_policies@Uresource_policies@951f6a2d6e0aeb78808e853e71bf1781";
		msTruth = "?? attach<class ?? :: ?? * __ptr64>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testUnknown4() throws Exception {
		mangled = "?Bid.NotificationsTrace@@0002010O0O";
		msTruth = "?Bid.NotificationsTrace@@0002010O0O";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin7_3979806() throws Exception { //was testFromLongTest_1()
		mangled = "???__E__mpnhHeap@@YMXXZ@?A0x6131f178@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for '__mpnhHeap''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for '__mpnhHeap''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testWin7_3979806_breakdown_a() throws Exception { //was testFromLongTest_1_breakdown_a()
		mangled = "?var@@$$FYMXXZ";
		msTruth = "void __clrcall var(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin7_3979806_breakdown_b() throws Exception { //was testFromLongTest_1_breakdown_b()
		mangled = "?__mpnhHeap@@YMXXZ";
		msTruth = "void __clrcall __mpnhHeap(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin7_3979806_breakdown_c() throws Exception { //was testFromLongTest_1_breakdown_c()
		mangled = "??__E__mpnhHeap@@YMXXZ";
		msTruth = "void __clrcall `dynamic initializer for '__mpnhHeap''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//This test is one where MSFT is not looking for a CVMOD ('A' here) in the CLI Array, such
	// as in the string segment "$01EA"...
	@Test
	public void testWin7_4873434() throws Exception { //was testFromLongTest_2() 
		mangled =
			"?get@Points@GdiGeometryConverter@GDIExporter@Internal@Microsoft@@$$FQE$AAMP$01EAVPointI@345@XZ";
		msTruth = "public: cli::array<Microsoft::Internal::GDIExporter::VPointI >^";
		mdTruth =
			"public: cli::array<class Microsoft::Internal::GDIExporter::PointI >^ __clrcall Microsoft::Internal::GDIExporter::GdiGeometryConverter::Points::get(void) __ptr64";
		demangleAndTest();
	}

	@Test
	public void testWin7_3796308() throws Exception { //was testFromLongTest_3()
		mangled =
			"???__E?A0x041c6180@Control_Table@TtfDelta@Internal@MS@@YMXXZ@?A0x041c6180@@$$FYMXXZ";
		msTruth =
			"void __clrcall `anonymous namespace'::`dynamic initializer for 'void __clrcall MS::Internal::TtfDelta::Control_Table::A0x041c6180(void)''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin7_3796020() throws Exception { //was testFromLongTest_4()
		mangled = "???__E??_7bad_alloc@std@@6B@@@YMXXZ@?A0x39824e8b@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'const std::bad_alloc::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const std::bad_alloc::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testWin7_3796329() throws Exception { //was testFromLongTest_5()
		mangled = "???__E?A0x086113d0@init_clog@std@@YMXXZ@?A0x086113d0@@$$FYMXXZ";
		msTruth =
			"void __clrcall `anonymous namespace'::`dynamic initializer for 'void __clrcall std::init_clog::A0x086113d0(void)''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin7_3807354() throws Exception { //was testFromLongTest_6()
		mangled = "???__E_AtlModule@@YMXXZ@?A0x7a18388b@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for '_AtlModule''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for '_AtlModule''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_Basic_000() throws Exception {
		mangled = "??_7exception@@6B@";
		msTruth = "const exception::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_001() throws Exception {
		mangled = "??_7bad_typeid@@6B@";
		msTruth = "const bad_typeid::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_002() throws Exception {
		mangled = "??_7__non_rtti_object@@6B@";
		msTruth = "const __non_rtti_object::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_003() throws Exception {
		mangled = "??_7bad_cast@@6B@";
		msTruth = "const bad_cast::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_004() throws Exception {
		mangled = "??3@YAXPAX@Z";
		msTruth = "void __cdecl operator delete(void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_005() throws Exception {
		mangled = "??2@YAPAXI@Z";
		msTruth = "void * __cdecl operator new(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_006() throws Exception {
		mangled = "??_V@YAXPAX@Z";
		msTruth = "void __cdecl operator delete[](void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_007() throws Exception {
		mangled = "??_U@YAPAXI@Z";
		msTruth = "void * __cdecl operator new[](unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_008() throws Exception {
		mangled = "?_set_se_translator@@YAP6AXIPAU_EXCEPTION_POINTERS@@@ZP6AXI0@Z@Z";
		msTruth =
			"void (__cdecl*__cdecl _set_se_translator(void (__cdecl*)(unsigned int,struct _EXCEPTION_POINTERS *)))(unsigned int,struct _EXCEPTION_POINTERS *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_009() throws Exception {
		mangled = "??1exception@@UAE@XZ";
		msTruth = "public: virtual __thiscall exception::~exception(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_010() throws Exception {
		mangled = "??0exception@@QAE@XZ";
		msTruth = "public: __thiscall exception::exception(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_011() throws Exception {
		mangled = "??0exception@@QAE@ABQBD@Z";
		msTruth = "public: __thiscall exception::exception(char const * const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_012() throws Exception {
		mangled = "?_set_new_handler@@YAP6AHI@ZP6AHI@Z@Z";
		msTruth =
			"int (__cdecl*__cdecl _set_new_handler(int (__cdecl*)(unsigned int)))(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_013() throws Exception {
		mangled = "?_set_new_mode@@YAHH@Z";
		msTruth = "int __cdecl _set_new_mode(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_014() throws Exception {
		mangled = "?set_terminate@@YAP6AXXZP6AXXZ@Z";
		msTruth = "void (__cdecl*__cdecl set_terminate(void (__cdecl*)(void)))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_015() throws Exception {
		mangled = "??8type_info@@QBEHABV0@@Z";
		msTruth = "public: int __thiscall type_info::operator==(class type_info const &)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_016() throws Exception {
		mangled = "?name@type_info@@QBEPBDXZ";
		msTruth = "public: char const * __thiscall type_info::name(void)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_017() throws Exception {
		mangled = "??0exception@@QAE@ABQBDH@Z";
		msTruth = "public: __thiscall exception::exception(char const * const &,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_018() throws Exception {
		mangled = "??0exception@@QAE@ABV0@@Z";
		msTruth = "public: __thiscall exception::exception(class exception const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_019() throws Exception {
		mangled = "??4exception@@QAEAAV0@ABV0@@Z";
		msTruth =
			"public: class exception & __thiscall exception::operator=(class exception const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_020() throws Exception {
		mangled = "?what@exception@@UBEPBDXZ";
		msTruth = "public: virtual char const * __thiscall exception::what(void)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_021() throws Exception {
		mangled = "??0bad_cast@@QAE@ABV0@@Z";
		msTruth = "public: __thiscall bad_cast::bad_cast(class bad_cast const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_022() throws Exception {
		mangled = "??1bad_cast@@UAE@XZ";
		msTruth = "public: virtual __thiscall bad_cast::~bad_cast(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_023() throws Exception {
		mangled = "??0bad_cast@@QAE@ABQBD@Z";
		msTruth = "public: __thiscall bad_cast::bad_cast(char const * const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_024() throws Exception {
		mangled = "??0bad_cast@@AAE@PBQBD@Z";
		msTruth = "private: __thiscall bad_cast::bad_cast(char const * const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_025() throws Exception {
		mangled = "??0bad_typeid@@QAE@PBD@Z";
		msTruth = "public: __thiscall bad_typeid::bad_typeid(char const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_026() throws Exception {
		mangled = "??0bad_typeid@@QAE@ABV0@@Z";
		msTruth = "public: __thiscall bad_typeid::bad_typeid(class bad_typeid const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_027() throws Exception {
		mangled = "??0__non_rtti_object@@QAE@PBD@Z";
		msTruth = "public: __thiscall __non_rtti_object::__non_rtti_object(char const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_028() throws Exception {
		mangled = "??0__non_rtti_object@@QAE@ABV0@@Z";
		msTruth =
			"public: __thiscall __non_rtti_object::__non_rtti_object(class __non_rtti_object const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_029() throws Exception {
		mangled = "??1bad_typeid@@UAE@XZ";
		msTruth = "public: virtual __thiscall bad_typeid::~bad_typeid(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_030() throws Exception {
		mangled = "??1__non_rtti_object@@UAE@XZ";
		msTruth = "public: virtual __thiscall __non_rtti_object::~__non_rtti_object(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_031() throws Exception {
		mangled = "??_Gexception@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall exception::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_032() throws Exception {
		mangled = "??_Eexception@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall exception::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_033() throws Exception {
		mangled = "??0bad_cast@@QAE@PBD@Z";
		msTruth = "public: __thiscall bad_cast::bad_cast(char const *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_034() throws Exception {
		mangled = "??4bad_typeid@@QAEAAV0@ABV0@@Z";
		msTruth =
			"public: class bad_typeid & __thiscall bad_typeid::operator=(class bad_typeid const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_035() throws Exception {
		mangled = "??4bad_cast@@QAEAAV0@ABV0@@Z";
		msTruth = "public: class bad_cast & __thiscall bad_cast::operator=(class bad_cast const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_036() throws Exception {
		mangled = "??_Fbad_cast@@QAEXXZ";
		msTruth = "public: void __thiscall bad_cast::`default constructor closure'(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_037() throws Exception {
		mangled = "??_Gbad_cast@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall bad_cast::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_038() throws Exception {
		mangled = "??_Ebad_cast@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall bad_cast::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_039() throws Exception {
		mangled = "??_Fbad_typeid@@QAEXXZ";
		msTruth = "public: void __thiscall bad_typeid::`default constructor closure'(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_040() throws Exception {
		mangled = "??_Gbad_typeid@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall bad_typeid::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_041() throws Exception {
		mangled = "??_G__non_rtti_object@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall __non_rtti_object::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_042() throws Exception {
		mangled = "??_Ebad_typeid@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall bad_typeid::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_043() throws Exception {
		mangled = "??_E__non_rtti_object@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall __non_rtti_object::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_044() throws Exception {
		mangled = "??4__non_rtti_object@@QAEAAV0@ABV0@@Z";
		msTruth =
			"public: class __non_rtti_object & __thiscall __non_rtti_object::operator=(class __non_rtti_object const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_045() throws Exception {
		mangled = "?set_unexpected@@YAP6AXXZP6AXXZ@Z";
		msTruth = "void (__cdecl*__cdecl set_unexpected(void (__cdecl*)(void)))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_046() throws Exception {
		mangled = "?terminate@@YAXXZ";
		msTruth = "void __cdecl terminate(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_047() throws Exception {
		mangled = "?unexpected@@YAXXZ";
		msTruth = "void __cdecl unexpected(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_048() throws Exception {
		mangled = "??1type_info@@UAE@XZ";
		msTruth = "public: virtual __thiscall type_info::~type_info(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_049() throws Exception {
		mangled = "??9type_info@@QBEHABV0@@Z";
		msTruth = "public: int __thiscall type_info::operator!=(class type_info const &)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_050() throws Exception {
		mangled = "?before@type_info@@QBEHABV1@@Z";
		msTruth = "public: int __thiscall type_info::before(class type_info const &)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_051() throws Exception {
		mangled = "?raw_name@type_info@@QBEPBDXZ";
		msTruth = "public: char const * __thiscall type_info::raw_name(void)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_052() throws Exception {
		mangled = "?_query_new_handler@@YAP6AHI@ZXZ";
		msTruth = "int (__cdecl*__cdecl _query_new_handler(void))(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_053() throws Exception {
		mangled = "?_query_new_mode@@YAHXZ";
		msTruth = "int __cdecl _query_new_mode(void)";
		mdTruth = msTruth;
	}

	@Test
	public void testGhidraFileInfo_Basic_054() throws Exception {
		mangled = "?set_new_handler@@YAP6AXXZP6AXXZ@Z";
		msTruth = "void (__cdecl*__cdecl set_new_handler(void (__cdecl*)(void)))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_055() throws Exception {
		mangled = "??_U@YAPAXIHPBDH@Z";
		msTruth = "void * __cdecl operator new[](unsigned int,int,char const *,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Basic_056() throws Exception {
		mangled = "??2@YAPAXIHPBDH@Z";
		msTruth = "void * __cdecl operator new(unsigned int,int,char const *,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# GLOBAL OPERATORS

	@Test
	public void testGhidraFileInfo_GlobalOperators_001() throws Exception {
		mangled = "??2@YAPAXI@Z";
		msTruth = "void * __cdecl operator new(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalOperators_002() throws Exception {
		mangled = "??3@YAXPAX@Z";
		msTruth = "void __cdecl operator delete(void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalOperators_003() throws Exception {
		mangled = "??_U@YAPEAX_K@Z";
		msTruth = "void * __ptr64 __cdecl operator new[](unsigned __int64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# STRINGS

	@Test
	public void testGhidraFileInfo_Strings_001() throws Exception {
		mangled = "??_C@_08JCCMCCIL@HH?3mm?3ss?$AA@";
		msTruth = "`string'";
		mdTruth = "HH:mm:ss";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_002() throws Exception {
		mangled = "??_C@_08EDHMEBNP@December?$AA@";
		msTruth = "`string'";
		mdTruth = "December";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_003() throws Exception {
		mangled = "??_C@_08HCHEGEOA@November?$AA@";
		msTruth = "`string'";
		mdTruth = "November";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_004() throws Exception {
		mangled = "??_C@_04MIEPOIFP@July?$AA@";
		msTruth = "`string'";
		mdTruth = "July";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_005() throws Exception {
		mangled = "??_C@_03LBGABGKK@Jul?$AA@";
		msTruth = "`string'";
		mdTruth = "Jul";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_006() throws Exception {
		mangled = "??_C@_0M@IDPNJOFL@TlsGetValue?$AA@";
		msTruth = "`string'";
		mdTruth = "TlsGetValue";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_007() throws Exception {
		mangled = "??_C@_1BA@KFOBIOMM@?$AAT?$AAY?$AAP?$AAE?$AAL?$AAI?$AAB?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "TYPELIB";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_008() throws Exception {
		mangled = "??_C@_1M@KANJNLFF@?$AAC?$AAL?$AAS?$AAI?$AAD?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "CLSID";
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Strings_009() throws Exception {
		mangled = "??_C@_1O@JDLOHAN@?$AAD?$AAe?$AAl?$AAe?$AAt?$AAe?$AA?$AA@";
		msTruth = "`string'";
		mdTruth = "Delete";
		demangleAndTest();
	}

	//# OVERRIDDEN OPERATORS

	@Test
	public void testGhidraFileInfo_OverriddenOperator_001() throws Exception {
		mangled = "??5@YGAAVCArchive@@AAV0@AAPAVCGWTelMenuData@@@Z";
		msTruth =
			"class CArchive & __stdcall operator>>(class CArchive &,class CGWTelMenuData * &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_002() throws Exception {
		mangled = "??_ECGWISUPInformation@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall CGWISUPInformation::`vector deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_003() throws Exception {
		mangled = "??0CMuLawCodec@@QAE@XZ";
		msTruth = "public: __thiscall CMuLawCodec::CMuLawCodec(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_004() throws Exception {
		mangled = "??1CMuLawCodec@@UAE@XZ";
		msTruth = "public: virtual __thiscall CMuLawCodec::~CMuLawCodec(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_005() throws Exception {
		mangled = "??_GCGWCodec@@UAEPAXI@Z";
		msTruth =
			"public: virtual void * __thiscall CGWCodec::`scalar deleting destructor'(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_006() throws Exception {
		mangled = "??HFoo@@QAE?AV0@V0@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator+(class Foo)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_007() throws Exception {
		mangled = "??HFoo@@QAE?AV0@H@Z";
		msTruth = "public: class Foo __thiscall Foo::operator+(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_008() throws Exception {
		mangled = "??HFoo@@QAE?AV0@VBar@@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator+(class Bar)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_009() throws Exception {
		mangled = "??HFoo@@QAE?AV0@PAU_RECTANGLE@@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator+(struct _RECTANGLE *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_010() throws Exception {
		mangled = "??HFoo@@QAE?AV0@U_RECTANGLE@@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator+(struct _RECTANGLE)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_011() throws Exception {
		mangled = "??GFoo@@QAE?AV0@V0@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator-(class Foo)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_012() throws Exception {
		mangled = "??GFoo@@QAE?AV0@H@Z";
		msTruth = "public: class Foo __thiscall Foo::operator-(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_013() throws Exception {
		mangled = "??GFoo@@QAE?AV0@W4MYENUM@@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator-(enum MYENUM)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_014() throws Exception {
		mangled = "??KFoo@@QAE?AV0@V0@@Z";
		msTruth = "public: class Foo __thiscall Foo::operator/(class Foo)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_015() throws Exception {
		mangled = "??KFoo@@QAE?AV0@H@Z";
		msTruth = "public: class Foo __thiscall Foo::operator/(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_016() throws Exception {
		mangled = "??8Foo@@QAE_NV0@@Z";
		msTruth = "public: bool __thiscall Foo::operator==(class Foo)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_017() throws Exception {
		mangled = "??4Foo@@QAE?AV0@H@Z";
		msTruth = "public: class Foo __thiscall Foo::operator=(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_018() throws Exception {
		mangled = "??4Foo@@QAEAAV0@ABV0@@Z";
		msTruth = "public: class Foo & __thiscall Foo::operator=(class Foo const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_019() throws Exception {
		mangled = "??4Bar@@QAEAAV0@ABV0@@Z";
		msTruth = "public: class Bar & __thiscall Bar::operator=(class Bar const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_020() throws Exception {
		mangled = "??6Foo@@QAEHH@Z";
		msTruth = "public: int __thiscall Foo::operator<<(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_021() throws Exception {
		mangled = "??6Foo@@QAEHV0@@Z";
		msTruth = "public: int __thiscall Foo::operator<<(class Foo)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_022() throws Exception {
		mangled = "??0Foo@@QAE@H@Z";
		msTruth = "public: __thiscall Foo::Foo(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_OverriddenOperator_023() throws Exception {
		mangled = "??0CFileDialog@@QAE@HPBG0K0PAVCWnd@@@Z";
		msTruth =
			"public: __thiscall CFileDialog::CFileDialog(int,unsigned short const *,unsigned short const *,unsigned long,unsigned short const *,class CWnd *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//##################################

	@Test
	public void testGhidraFileInfo_VFVB_000() throws Exception {
		mangled = "??_7CComClassFactory@ATL@@6B@";
		msTruth = "const ATL::CComClassFactory::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_VFVB_001() throws Exception {
		mangled = "??_7CGWLineDirectorBase@@6B@";
		msTruth = "const CGWLineDirectorBase::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_VFVB_002() throws Exception {
		mangled = "??_8CGWTelMenuData@@7BCGWTelSelectionData@@@";
		msTruth = "const CGWTelMenuData::`vbtable'{for `CGWTelSelectionData'}";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_VFVB_003() throws Exception {
		mangled = "??_8CWebDVDComp@@7B@";
		msTruth = "const CWebDVDComp::`vbtable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# CLASS METHODS

	@Test
	public void testGhidraFileInfo_ClassMethods_000() throws Exception {
		mangled = "?getFoo@Foo@@QAE?AV1@XZ";
		msTruth = "public: class Foo __thiscall Foo::getFoo(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_001() throws Exception {
		mangled = "?getBar@Foo@@QAE?AVBar@@XZ";
		msTruth = "public: class Bar __thiscall Foo::getBar(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_002() throws Exception {
		mangled = "?getMyStruct@Foo@@QAE?AU_S@@XZ";
		msTruth = "public: struct _S __thiscall Foo::getMyStruct(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_003() throws Exception {
		mangled = "?getPMyStruct@Foo@@QAEPAU_S@@XZ";
		msTruth = "public: struct _S * __thiscall Foo::getPMyStruct(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_004() throws Exception {
		mangled = "?getMyEnum@Foo@@QAE?AW4MYENUM@@XZ";
		msTruth = "public: enum MYENUM __thiscall Foo::getMyEnum(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_005() throws Exception {
		mangled = "?getPMyEnum@Foo@@QAEPAW4MYENUM@@XZ";
		msTruth = "public: enum MYENUM * __thiscall Foo::getPMyEnum(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_006() throws Exception {
		mangled = "?getMyUnion@Foo@@QAE?AT_U@@XZ";
		msTruth = "public: union _U __thiscall Foo::getMyUnion(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_007() throws Exception {
		mangled = "?getPMyUnion@Foo@@QAEPAT_U@@XZ";
		msTruth = "public: union _U * __thiscall Foo::getPMyUnion(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_008() throws Exception {
		mangled = "?what@exception@@UBEPBDXZ";
		msTruth = "public: virtual char const * __thiscall exception::what(void)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_009() throws Exception {
		mangled = "?Init@CMuLawCodec@@UAEHH@Z";
		msTruth = "public: virtual int __thiscall CMuLawCodec::Init(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_010() throws Exception {
		mangled = "?GetSamplesPerFrame@CGWCodec@@SAHD@Z";
		msTruth = "public: static int __cdecl CGWCodec::GetSamplesPerFrame(char)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_011() throws Exception {
		mangled = "?getFloater@MyClass@@QAEPAPAPAPAMXZ";
		msTruth = "public: float * * * * __thiscall MyClass::getFloater(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassMethods_012() throws Exception {
		mangled = "?OnGetCheckPosition@CCheckListBox@@UAE?AVCRect@@V2@0@Z";
		msTruth =
			"public: virtual class CRect __thiscall CCheckListBox::OnGetCheckPosition(class CRect,class CRect)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//##################################

	@Test
	public void testGhidraFileInfo_Other_000() throws Exception {
		mangled = "??1MESSAGE_PROCESSOR_ID@CClarentMessageProcessor@@QAE@XZ";
		msTruth =
			"public: __thiscall CClarentMessageProcessor::MESSAGE_PROCESSOR_ID::~MESSAGE_PROCESSOR_ID(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Other_001() throws Exception {
		mangled =
			"?ProcessClarentVersionCheckerAcknowledge@CClarentMessageProcessor@@UAE_NPAVCClarentVersionCheckerMessage@@@Z";
		msTruth =
			"public: virtual bool __thiscall CClarentMessageProcessor::ProcessClarentVersionCheckerAcknowledge(class CClarentVersionCheckerMessage *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Other_002() throws Exception {
		mangled =
			"??0CEndpointDlg@@QAE@VMESSAGE_PROCESSOR_ID@CClarentMessageProcessor@@PAVCMSSRemoveDialogRecipient@@@Z";
		msTruth =
			"public: __thiscall CEndpointDlg::CEndpointDlg(class CClarentMessageProcessor::MESSAGE_PROCESSOR_ID,class CMSSRemoveDialogRecipient *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# MANGLED STATIC FUNCTIONS

	@Test
	public void testGhidraFileInfo_StaticFunctions_000() throws Exception {
		mangled = "?printError@@YAXXZ";
		msTruth = "void __cdecl printError(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_001() throws Exception {
		mangled = "?SpAlloc@@YAXHPAK0@Z";
		msTruth = "void __cdecl SpAlloc(int,unsigned long *,unsigned long *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_002() throws Exception {
		mangled = "?SpClearHBreakpoint@@YAXIIKH@Z";
		msTruth = "void __cdecl SpClearHBreakpoint(unsigned int,unsigned int,unsigned long,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_003() throws Exception {
		mangled = "?SpClearSBreakpoint@@YAXIIKPAEHEE@Z";
		msTruth =
			"void __cdecl SpClearSBreakpoint(unsigned int,unsigned int,unsigned long,unsigned char *,int,unsigned char,unsigned char)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_004() throws Exception {
		mangled = "?SpClearSingleStep@@YAXIIPAI@Z";
		msTruth = "void __cdecl SpClearSingleStep(unsigned int,unsigned int,unsigned int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_005() throws Exception {
		mangled = "?SpCtrlSetFlags@@YAXII@Z";
		msTruth = "void __cdecl SpCtrlSetFlags(unsigned int,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_006() throws Exception {
		mangled = "?SpDetachTarget@@YAJI@Z";
		msTruth = "long __cdecl SpDetachTarget(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_007() throws Exception {
		mangled = "?SpFree@@YAXHPAK0@Z";
		msTruth = "void __cdecl SpFree(int,unsigned long *,unsigned long *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_008() throws Exception {
		mangled = "?SpGetContextThread@@YAXIIIPAU_CONTEXT@NT@@I@Z";
		msTruth =
			"void __cdecl SpGetContextThread(unsigned int,unsigned int,unsigned int,struct NT::_CONTEXT *,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_009() throws Exception {
		mangled = "?SpGetProcesses@@YAPAU_SYSTEM_PROCESS_INFORMATION@NT@@PAH@Z";
		msTruth = "struct NT::_SYSTEM_PROCESS_INFORMATION * __cdecl SpGetProcesses(int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_010() throws Exception {
		mangled = "?SpGetProcessHandle@@YAXKPAPAX@Z";
		msTruth = "void __cdecl SpGetProcessHandle(unsigned long,void * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_011() throws Exception {
		mangled = "?SpGetProcessName@@YAXKPAXPAE@Z";
		msTruth = "void __cdecl SpGetProcessName(unsigned long,void *,unsigned char *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_012() throws Exception {
		mangled = "?SpGetProcessNameHandle@@YAXPAU_SYSTEM_PROCESS_INFORMATION@NT@@PAGPAPAX@Z";
		msTruth =
			"void __cdecl SpGetProcessNameHandle(struct NT::_SYSTEM_PROCESS_INFORMATION *,unsigned short *,void * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_013() throws Exception {
		mangled = "?SpGetRegSys@@YAXIHPAT_LARGE_INTEGER@@I@Z";
		msTruth = "void __cdecl SpGetRegSys(unsigned int,int,union _LARGE_INTEGER *,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_014() throws Exception {
		mangled = "?SpGetThreadHandle@@YAXKKPAPAX@Z";
		msTruth = "void __cdecl SpGetThreadHandle(unsigned long,unsigned long,void * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_015() throws Exception {
		mangled = "?SpInitTargetAsDLL@@YAJI@Z";
		msTruth = "long __cdecl SpInitTargetAsDLL(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_016() throws Exception {
		mangled = "?SpKillTarget@@YAJI@Z";
		msTruth = "long __cdecl SpKillTarget(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_017() throws Exception {
		mangled = "?SpReadMemory@@YAHHKPAEH@Z";
		msTruth = "int __cdecl SpReadMemory(int,unsigned long,unsigned char *,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_018() throws Exception {
		mangled = "?SpSetContextThread@@YAXIIIPAU_CONTEXT@NT@@I@Z";
		msTruth =
			"void __cdecl SpSetContextThread(unsigned int,unsigned int,unsigned int,struct NT::_CONTEXT *,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_019() throws Exception {
		mangled = "?SpSetHBreakpoint@@YAXIIKHHHH@Z";
		msTruth =
			"void __cdecl SpSetHBreakpoint(unsigned int,unsigned int,unsigned long,int,int,int,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_020() throws Exception {
		mangled = "?SpSetRegSys@@YAXIHPAT_LARGE_INTEGER@@I@Z";
		msTruth = "void __cdecl SpSetRegSys(unsigned int,int,union _LARGE_INTEGER *,unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_021() throws Exception {
		mangled = "?SpSetSBreakpoint@@YAXIIKKPAE0HEE@Z";
		msTruth =
			"void __cdecl SpSetSBreakpoint(unsigned int,unsigned int,unsigned long,unsigned long,unsigned char *,unsigned char *,int,unsigned char,unsigned char)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_022() throws Exception {
		mangled = "?SpSetSingleStep@@YAXIIPAI@Z";
		msTruth = "void __cdecl SpSetSingleStep(unsigned int,unsigned int,unsigned int *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_023() throws Exception {
		mangled = "?SpWriteMemory@@YAHHKPAEH@Z";
		msTruth = "int __cdecl SpWriteMemory(int,unsigned long,unsigned char *,int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_024() throws Exception {
		mangled = "?SpGetProcessHandle@@YAXKPAPAX@Z";
		msTruth = "void __cdecl SpGetProcessHandle(unsigned long,void * *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_025() throws Exception {
		mangled = "?DftSetPid@@YAXH@Z";
		msTruth = "void __cdecl DftSetPid(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_StaticFunctions_026() throws Exception {
		mangled = "?fseal@@YAKKKK@Z";
		msTruth = "unsigned long __cdecl fseal(unsigned long,unsigned long,unsigned long)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# CLASS VARIABLES

	@Test
	public void testGhidraFileInfo_ClassVariables_000() throws Exception {
		mangled = "?_pModule@ATL@@3PAVCComModule@1@A";
		msTruth = "class ATL::CComModule * ATL::_pModule";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_ClassVariables_001() throws Exception {
		mangled = "?wndTop@CWnd@@2V1@B";
		msTruth = "public: static class CWnd const CWnd::wndTop";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# GLOBAL VARIABLES

	@Test
	public void testGhidraFileInfo_GlobalVariables_000() throws Exception {

		mangled = "?gl@@1JA";
		msTruth = "protected: static long gl";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_001() throws Exception {
		mangled = "?foo@@3JA";
		msTruth = "long foo";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_002() throws Exception {
		mangled = "?gl@@3JA";
		msTruth = "long gl";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_003() throws Exception {
		mangled = "?bar@@3EA";
		msTruth = "unsigned char bar";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_004() throws Exception {
		mangled = "?roundconst@@3KA";
		msTruth = "unsigned long roundconst";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_005() throws Exception {
		mangled = "?weak_key_lsb@@3PAEA";
		msTruth = "unsigned char * weak_key_lsb";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_GlobalVariables_006() throws Exception {
		mangled = "?m_libid@CComModule@ATL@@2U_GUID@@A";
		msTruth = "public: static struct _GUID ATL::CComModule::m_libid";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# RTTI

	@Test
	public void testGhidraFileInfo_FTTI_000() throws Exception {
		mangled = "??_R0PAX@8";
		msTruth = "void * `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_001() throws Exception {
		mangled = "??_R0PAVCException@BOB@@@8";
		msTruth = "class BOB::CException * `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_002() throws Exception {
		mangled = "??_R0?PAVCOleException@@@8";
		msTruth = "class COleException const volatile __based() `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_003() throws Exception {
		mangled = "??_R0?AVCToolBarCtrl@@@8";
		msTruth = "class CToolBarCtrl `RTTI Type Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_004() throws Exception {
		mangled = "??_R1ABCP@?40A@A@_AFX_CTL3D_STATE@@8";
		msTruth = "_AFX_CTL3D_STATE::A::`RTTI Base Class Descriptor at (303,-5,1,0)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_005() throws Exception {
		mangled = "??_R1A@?0A@A@_AFX_CTL3D_STATE@@8";
		msTruth = "_AFX_CTL3D_STATE::`RTTI Base Class Descriptor at (0,-1,0,0)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_006() throws Exception {
		mangled = "??_R1ABCP@?0A@A@_AFX_CTL3D_STATE@@8";
		msTruth = "_AFX_CTL3D_STATE::`RTTI Base Class Descriptor at (303,-1,0,0)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_007() throws Exception {
		mangled = "??_R1ABCP@?0FGHJKL@A@_AFX_CTL3D_STATE@@8";
		msTruth = "_AFX_CTL3D_STATE::`RTTI Base Class Descriptor at (303,-1,5667243,0)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_008() throws Exception {
		mangled = "??_R1ABCP@?0FGHJKL@MNOP@_AFX_CTL3D_STATE@@8";
		msTruth = "_AFX_CTL3D_STATE::`RTTI Base Class Descriptor at (303,-1,5667243,52719)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_009() throws Exception {
		mangled = "??_R1A@?0A@A@CEnumUnknown@@8";
		msTruth = "CEnumUnknown::`RTTI Base Class Descriptor at (0,-1,0,0)'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_010() throws Exception {
		mangled = "??_R2CStatic@@8";
		msTruth = "CStatic::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_011() throws Exception {
		mangled = "??_R2CTabCtrl@@8";
		msTruth = "CTabCtrl::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_012() throws Exception {
		mangled = "??_R2CTreeCtrl@@8";
		msTruth = "CTreeCtrl::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_013() throws Exception {
		mangled = "??_R2XOleIPFrame@COleControlContainer@@8";
		msTruth = "COleControlContainer::XOleIPFrame::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_014() throws Exception {
		mangled = "??_R2XRowsetNotify@COleControlSite@@8";
		msTruth = "COleControlSite::XRowsetNotify::`RTTI Base Class Array'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_015() throws Exception {
		mangled = "??_R3_AFX_THREAD_STATE@@8";
		msTruth = "_AFX_THREAD_STATE::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_016() throws Exception {
		mangled = "??_R3CClientDC@@8";
		msTruth = "CClientDC::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_017() throws Exception {
		mangled = "??_R3CMenu@@8";
		msTruth = "CMenu::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_019() throws Exception {
		mangled = "??_R3XOleClientSite@COleControlSite@@8";
		msTruth = "COleControlSite::XOleClientSite::`RTTI Class Hierarchy Descriptor'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_020() throws Exception {
		mangled = "??_R4_AFX_CTL3D_THREAD@@6B@";
		msTruth = "const _AFX_CTL3D_THREAD::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_021() throws Exception {
		mangled = "??_R4CDocManager@@6B@";
		msTruth = "const CDocManager::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_022() throws Exception {
		mangled = "??_R4istream_withassign@@6B@";
		msTruth = "const istream_withassign::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_023() throws Exception {
		mangled = "??_R4XAmbientProps@COleControlSite@@6B@";
		msTruth = "const COleControlSite::XAmbientProps::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_RTTI_024() throws Exception {
		mangled = "??_R4XNotifyDBEvents@COleControlSite@@6B@";
		msTruth = "const COleControlSite::XNotifyDBEvents::`RTTI Complete Object Locator'";
		mdTruth = msTruth;
		demangleAndTest();

		//# FUNCTION POINTERS
	}

	@Test
	public void testGhidraFileInfo_FunctionPointers_000() throws Exception {
		mangled = "?_query_new_handler@@YAP6AHI@ZXZ";
		msTruth = "int (__cdecl*__cdecl _query_new_handler(void))(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_FunctionPointers_001() throws Exception {
		mangled = "?_pnhHeap@@3P6AHI@ZA";
		msTruth = "int (__cdecl* _pnhHeap)(unsigned int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_FunctionPointers_002() throws Exception {
		mangled = "?__pInconsistency@@3P6AXXZA";
		msTruth = "void (__cdecl* __pInconsistency)(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//#### Can't Handle Arrays yet.

	@Test
	public void testGhidraFileInfo_Arrays_000() throws Exception {
		mangled = "?FirstRxPacket@@3PAY0IA@EA";
		msTruth = "unsigned char (* FirstRxPacket)[128]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Arrays_001() throws Exception {
		mangled = "?acTPSTNCallContextsArray@@3PAY11BAA@UacTPSTNCallContext@@A";
		msTruth = "struct acTPSTNCallContext (* acTPSTNCallContextsArray)[2][256]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Arrays_002() throws Exception {
		mangled = "??_L@YGXPAXIHP6EX0@Z1@Z";
		msTruth =
			"void __stdcall `eh vector constructor iterator'(void *,unsigned int,int,void (__thiscall*)(void *),void (__thiscall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Arrays_003() throws Exception {
		mangled = "??_M@YGXPAXIHP6EX0@Z@Z";
		msTruth =
			"void __stdcall `eh vector destructor iterator'(void *,unsigned int,int,void (__thiscall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Arrays_004() throws Exception {
		mangled = "?GetSuperWndProcAddr@CWnd@@MAEPAP6GJPAUHWND__@@IIJ@ZXZ";
		msTruth =
			"protected: virtual long (__stdcall** __thiscall CWnd::GetSuperWndProcAddr(void))(struct HWND__ *,unsigned int,unsigned int,long)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# METHODS WITH A FUNCTION POINTER AS A PARAMETER

	@Test
	public void testGhidraFileInfo_FunctionPointerParameter_000() throws Exception {
		mangled = "??0CWinThread@@QAE@P6AIPAX@Z0@Z";
		msTruth =
			"public: __thiscall CWinThread::CWinThread(unsigned int (__cdecl*)(void *),void *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_FunctionPointerParameter_001() throws Exception {
		mangled = "?register_callback@ios_base@std@@QAEXP6AXW4event@12@AAV12@H@ZH@Z";
		msTruth =
			"public: void __thiscall std::ios_base::register_callback(void (__cdecl*)(enum std::ios_base::event,class std::ios_base &,int),int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_FunctionPointerParameter_002() throws Exception {
		mangled = "?__ArrayUnwind@@YGXPAXIHP6EX0@Z@Z";
		msTruth =
			"void __stdcall __ArrayUnwind(void *,unsigned int,int,void (__thiscall*)(void *))";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//# TEMPLATES

	@Test
	public void testGhidraFileInfo_Templates_000() throws Exception {
		mangled = "??4?$_CIP@UIBindHost@@$1?IID_IBindHost@@3U_GUID@@B@@QAEAAV0@PAUIBindHost@@@Z";
		msTruth =
			"public: class _CIP<struct IBindHost,&struct _GUID const IID_IBindHost> & __thiscall _CIP<struct IBindHost,&struct _GUID const IID_IBindHost>::operator=(struct IBindHost *)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Templates_001() throws Exception {
		mangled = "?_Clocptr@_Locimp@locale@std@@0PAV123@A";
		msTruth = "private: static class std::locale::_Locimp * std::locale::_Locimp::_Clocptr";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testGhidraFileInfo_Templates_002() throws Exception {
		mangled = "??0_Locinfo@std@@QAE@ABV01@@Z";
		msTruth = "public: __thiscall std::_Locinfo::_Locinfo(class std::_Locinfo const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//====================================================================================================
	//====================================================================================================
	@Test
	public void testThisPointerModifiers_A() throws Exception {
		mangled = "?fn@@AAAHH@Z";
		msTruth = "private: int __cdecl fn(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_B() throws Exception {
		mangled = "?fn@@ABAHH@Z";
		msTruth = "private: int __cdecl fn(int)const ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_C() throws Exception {
		mangled = "?fn@@ACAHH@Z";
		msTruth = "private: int __cdecl fn(int)volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_D() throws Exception {
		mangled = "?fn@@ADAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_ED() throws Exception {
		mangled = "?fn@@AEDAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_ID() throws Exception {
		mangled = "?fn@@AFDAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile __unaligned ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_FD() throws Exception {
		mangled = "?fn@@AIDAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_EFID() throws Exception {
		mangled = "?fn@@AEFIDAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile __unaligned __ptr64 __restrict";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_GA() throws Exception {
		mangled = "?fn@@AGAAHH@Z";
		msTruth = "private: int __cdecl fn(int)& ";
		ms2013Truth = "private: int const volatile & __cdecl fn()volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_HA() throws Exception {
		mangled = "?fn@@AHAAHH@Z";
		msTruth = "private: int __cdecl fn(int)&& ";
		ms2013Truth = "private: int const volatile & __cdecl fn()const volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_GHA() throws Exception {
		mangled = "?fn@@AGHAAHH@Z";
		msTruth = "private: int __cdecl fn(int)& && ";
		ms2013Truth = "private: int & __stdcall fn(int)volatile ";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_EFGHID() throws Exception {
		mangled = "?fn@@AEFGHIDAHH@Z";
		msTruth = "private: int __cdecl fn(int)const volatile __unaligned __ptr64 __restrict& && ";
		ms2013Truth =
			"private: unsigned int __stdcall fn(char,int const volatile &)volatile __unaligned __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_EEFFGGHHIID() throws Exception {
		mangled = "?fn@@AEEFFGGHHIIDAHH@Z";
		msTruth =
			"private: int __cdecl fn(int)const volatile __unaligned __unaligned __ptr64 __ptr64 __restrict __restrict& && ";
		ms2013Truth =
			"private: int __stdcall fn(int,unsigned int,unsigned int,char,int const volatile &)volatile __unaligned __unaligned __ptr64 __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testThisPointerModifiers_EEFFGGHHIIDollarCD() throws Exception {
		mangled = "?fn@@AEEFFGGHHII$CDAHH@Z";
		msTruth =
			"private: int __cdecl fn(int)const volatile __unaligned __unaligned % __ptr64 __ptr64 __restrict __restrict& && ";
		ms2013Truth = "?fn@@AEEFFGGHHII$CDAHH@Z";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//====================================================================================================
	//====================================================================================================

	// Has $$$
	@Test
	public void testWin10_0000297() throws Exception {
		mangled =
			"??0?$__abi_FunctorCapture@V?$function@$$A6AXXZ@std@@X$$$V@Details@Platform@@QEAA@V?$function@$$A6AXXZ@std@@@Z";
		msTruth =
			"public: __cdecl Platform::Details::__abi_FunctorCapture<class std::function<void __cdecl(void)>,void>::__abi_FunctorCapture<class std::function<void __cdecl(void)>,void>(class std::function<void __cdecl(void)>) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testEmail20170118_RTTI0_DatatypeString() throws Exception {
		mangled = ".?AV?$name1@Vname2@@Uname3@name4@@@name4@@";
		mdTruth = "class name4::name1<class name2,struct name4::name3>";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testEmail20170118_RTTI0_DatatypeString_mod1() throws Exception {
		mangled = ".?AV?$name1@Vname2@@Uname3@name4@@@name4@@";
		//Removed the "." at the front end, replace "A" with a name "xxx@@3" and gave "A" terminating "const" to complete a valid symbol.
		mangled = "?name0@@3V?$name1@Vname2@@Uname3@name4@@@name4@@A";
		mdTruth = "class name4::name1<class name2,struct name4::name3> name0";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testEmail20170118_RTTI0_DatatypeString_mod_struct() throws Exception {
		mangled = ".?AU?$name1@Vname2@@Uname3@name4@@@name4@@";
		mdTruth = "struct name4::name1<class name2,struct name4::name3>";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testEmail20170118_RTTI0_DatatypeString_mod_union() throws Exception {
		mangled = ".?AT?$name1@Vname2@@Uname3@name4@@@name4@@";
		mdTruth = "union name4::name1<class name2,struct name4::name3>";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void test_RTTI0_DatatypeString_char_pointer() throws Exception {
		mangled = ".PEAD";
		mdTruth = "char * __ptr64";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void test_RTTI0_DatatypeString_int() throws Exception {
		mangled = ".H";
		mdTruth = "int";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void test_RTTI0_DatatypeString_class_pointer() throws Exception {
		mangled = ".PAVBugaboo@@";
		mdTruth = "class Bugaboo *";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testCStyleName() throws Exception {
		mangled = "name";
		mdTruth = "name";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	//Fixed 20170330
	@Test
	public void testWin10_0001140() throws Exception {
		mangled = "??0?$ActivityBase@$00$0A@$04@wil@@QEAA@$$QEAV01@_N@Z";
		msTruth =
			"public: __cdecl wil::ActivityBase<1,0,5>::ActivityBase<1,0,5>(class wil::ActivityBase<1,0,5> && __ptr64,bool) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	//Fixed 20170330
	@Test
	public void testWin10_0001140_withDollarA() throws Exception {
		mangled = "??0?$ActivityBase@$00$0A@$04@wil@@QEAA@$$QE$AAV01@_N@Z";
		msTruth =
			"public: __cdecl wil::ActivityBase<1,0,5>::ActivityBase<1,0,5>(class wil::ActivityBase<1,0,5> % __ptr64,bool) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	//Fixed 20170330
	@Test
	public void testWin10_0001140_withDollarB() throws Exception {
		mangled = "??0?$ActivityBase@$00$0A@$04@wil@@QEAA@$$QE$BAV01@_N@Z";
		msTruth =
			"public: __cdecl wil::ActivityBase<1,0,5>::ActivityBase<1,0,5>(cli::pin_ptr<class wil::ActivityBase<1,0,5> && __ptr64,bool) __ptr64";
		//Still as guess as to where '>' goes and what spacing is needed.
		mdTruth =
			"public: __cdecl wil::ActivityBase<1,0,5>::ActivityBase<1,0,5>(cli::pin_ptr<class wil::ActivityBase<1,0,5> >&& __ptr64,bool) __ptr64";
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	//Fixed 20170330
	@Test
	public void testWin10_0001140_withDollarC() throws Exception {
		mangled = "??0?$ActivityBase@$00$0A@$04@wil@@QEAA@$$QE$CAV01@_N@Z";
		msTruth =
			"public: __cdecl wil::ActivityBase<1,0,5>::ActivityBase<1,0,5>(class wil::ActivityBase<1,0,5> % __ptr64,bool) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	@Test
	public void testDollarDollarQwithDollarA() throws Exception {
		mangled = "?var@@3$$Q$AAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	@Test
	public void testDollarDollarQwithDollarB() throws Exception {
		mangled = "?var@@3$$Q$BAHA";
		msTruth = "cli::pin_ptr<int && var";
		mdTruth = "cli::pin_ptr<int >&& var";
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	@Test
	public void testDollarDollarQwithDollarC() throws Exception {
		mangled = "?var@@3$$Q$CAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" data type (kind of like a reference)
	@Test
	public void testDollarDollarQwithFunctionType() throws Exception {
		mangled = "?fn@@3$$Q6AHH@ZA";
		msTruth = "int (__cdecl&& fn)(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" MDDataReferenceType as regular type.
	@Test
	public void testDollarDollarQAsRegularType() throws Exception {
		mangled = "?var@@3$$QAHA";
		msTruth = "int && var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$R" MDDataReferenceType as regular type.
	@Test
	public void testDollarDollarRAsRegularType() throws Exception {
		mangled = "?var@@3$$RAHA";
		msTruth = "int && var"; //DOES NOT output "volatile"
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" MDDataReferenceType as regular type.
	@Test
	public void testDollarDollarQAsRegularType_withConstVolatileConstVolatile() throws Exception {
		mangled = "?var@@3$$QDHD";
		msTruth = "int const volatile && const volatile var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$R" MDDataReferenceType as regular type.
	@Test
	public void testDollarDollarRAsRegularType_withConstVolatileConstVolatile() throws Exception {
		mangled = "?var@@3$$RDHD";
		msTruth = "int const volatile && const volatile var"; //DOES NOT output "volatile" for $$R (does output others)
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" MDDataReferenceType as function arg.
	@Test
	public void testDollarDollarQAsFunctionArg() throws Exception {
		mangled = "?fn@@YAH$$QAH@Z";
		msTruth = "int __cdecl fn(int &&)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$R" MDDataReferenceType as function arg.
	@Test
	public void testDollarDollarRAsFunctionArg() throws Exception {
		mangled = "?fn@@YAH$$RAH@Z";
		msTruth = "int __cdecl fn(int && volatile)"; //DOES output "volatile"
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$Q" MDDataReferenceType as function arg.
	@Test
	public void testDollarDollarQAsFunctionArg_withConstVolatile() throws Exception {
		mangled = "?fn@@YAH$$QDH@Z";
		msTruth = "int __cdecl fn(int const volatile &&)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$R" MDDataReferenceType as function arg.
	@Test
	public void testDollarDollarRAsFunctionArg_withConstVolatile() throws Exception {
		mangled = "?fn@@YAH$$RDH@Z";
		msTruth = "int __cdecl fn(int const volatile && volatile)"; //DOES output "volatile"
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerwithDollarA() throws Exception {
		mangled = "?var@@3P$AAHA";
		msTruth = "int ^ var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testPointerwithDollarB() throws Exception {
		mangled = "?var@@3P$BAHA";
		msTruth = "cli::pin_ptr<int * var";
		mdTruth = "cli::pin_ptr<int >* var";
		demangleAndTest();
	}

	@Test
	public void testPointerwithDollarC() throws Exception {
		mangled = "?var@@3P$CAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferencewithDollarA() throws Exception {
		mangled = "?var@@3A$AAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testReferencewithDollarB() throws Exception {
		mangled = "?var@@3A$BAHA";
		msTruth = "cli::pin_ptr<int & var";
		mdTruth = "cli::pin_ptr<int >& var";
		demangleAndTest();
	}

	@Test
	public void testReferencewithDollarC() throws Exception {
		mangled = "?var@@3A$CAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionwithDollarA() throws Exception {
		mangled = "?var@@3?$AAHA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionwithDollarB() throws Exception {
		mangled = "?var@@3?$BAHA";
		msTruth = "int var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testQuestionwithDollarC() throws Exception {
		mangled = "?var@@3?$CAHA";
		msTruth = "int % var";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArraywithDollarA() throws Exception {
		mangled = "?var@@3_O$AAHA";
		msTruth = "int var[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testArraywithDollarB() throws Exception {
		mangled = "?var@@3_O$BAHA";
		msTruth = "cli::pin_ptr<int var[]";
		//TODO: This cannot be correct, can it?  Having "var" inside of <> (however it works that way for things such as (int *var)[]
		//mdtruth = "cli::pin_ptr<int var[] >";
		mdTruth = "cli::pin_ptr<int[] > var";
		demangleAndTest();
	}

	@Test
	public void testArraywithDollarC() throws Exception {
		mangled = "?var@@3_O$CAHA";
		msTruth = "int var[]";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$$V" sequence for the last Template Parameter
	//Fixed 20170330
	@Test
	public void testWin10_0002481() throws Exception {
		mangled =
			"??$?0AEBUUnwinderErrorContractFunctor@detail@errcntrctlib@@@?$_Func_impl@U?$_Callable_obj@UUnwinderErrorContractFunctor@detail@errcntrctlib@@$0A@@std@@V?$allocator@V?$_Func_class@X$$$V@std@@@2@X$$$V@std@@QEAA@AEBUUnwinderErrorContractFunctor@detail@errcntrctlib@@AEBV?$allocator@V?$_Func_impl@U?$_Callable_obj@UUnwinderErrorContractFunctor@detail@errcntrctlib@@$0A@@std@@V?$allocator@V?$_Func_class@X$$$V@std@@@2@X$$$V@std@@@1@@Z";
		msTruth =
			"public: __cdecl std::_Func_impl<struct std::_Callable_obj<struct errcntrctlib::detail::UnwinderErrorContractFunctor,0>,class std::allocator<class std::_Func_class<void> >,void>::_Func_impl<struct std::_Callable_obj<struct errcntrctlib::detail::UnwinderErrorContractFunctor,0>,class std::allocator<class std::_Func_class<void> >,void><struct errcntrctlib::detail::UnwinderErrorContractFunctor const & __ptr64>(struct errcntrctlib::detail::UnwinderErrorContractFunctor const & __ptr64,class std::allocator<class std::_Func_impl<struct std::_Callable_obj<struct errcntrctlib::detail::UnwinderErrorContractFunctor,0>,class std::allocator<class std::_Func_class<void> >,void> > const & __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Has "$$$V" sequence for MDTemplateParameter, but it a different position than for testWin10_0002481.
	//Currently getting: demangled = "class rx::observable<> __cdecl rx::attach<class std::shared_ptr<struct ITimerCallback> >(class rx::observable_<>,class std::shared_ptr<struct ITimerCallback>)";
	@Test
	public void testWin10_1435301() throws Exception {
		mangled =
			"??$attach@$$$VV?$shared_ptr@UITimerCallback@@@std@@@rx@@YA?AV?$observable@$$$V@0@V?$observable_@$$$V@0@V?$shared_ptr@UITimerCallback@@@std@@@Z";
		msTruth =
			"class rx::observable<> __cdecl rx::attach<,class std::shared_ptr<struct ITimerCallback> >(class rx::observable_<>,class std::shared_ptr<struct ITimerCallback>)";
		mdTruth =
			"class rx::observable<> __cdecl rx::attach<class std::shared_ptr<struct ITimerCallback> >(class rx::observable_<>,class std::shared_ptr<struct ITimerCallback>)";
		demangleAndTest();
	}

	//Has "$$V" sequence (supposed MS2015 version of "$$$V" and comes from github issue #1220
	@Test
	public void testDollarDollarV_Issue1220() throws Exception {
		mangled =
			"??$Make@VProjectorViewFormats@Output@Host@DataModel@Debugger@@$$V@Details@WRL@Microsoft@@YA?AV?$ComPtr@VProjectorViewFormats@Output@Host@DataModel@Debugger@@@12@XZ";
		msTruth =
			"class Microsoft::WRL::ComPtr<class Debugger::DataModel::Host::Output::ProjectorViewFormats> __cdecl Microsoft::WRL::Details::Make<class Debugger::DataModel::Host::Output::ProjectorViewFormats>(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: Need to do dispatcher for VS2017? vs. VS2015?  We do not have VS2017 yet to see what it does.
	//TODO (20170331): Need to do some testing/fuzzing with something more up-to-date than VS2015.
	//Problem is at location 29-31 where we have a '?' followed by a 'C', which is trying to determine the encoded number, but the 'C'
	// is followed by an invalid character 'i' for an encoded number.  This sequence is repeated later.
	//20170522 BEST GUESS (see MDQualification): Get some sort of result if we replace "?CimDisableDedupVolume" with "CimDisableDedupVolume@" in two places.
	// Perhaps "?C" means literal string, up to, but not including the next invalid char in the sequence (so a missing '@' can be tolerated)
	// --so would also need to strip the 'C' in the results.
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testWin10_0358058() throws Exception {
		mangled =
			"??1?$vector@UVolumeWarning@?9?CimDisableDedupVolume@V?$allocator@UVolumeWarning@?9?CimDisableDedupVolume@@std@@@std@@QEAA@XZ";
		msTruth =
			"public: __cdecl std::vector<,mDisableDedupVolume,td>::~vector<,mDisableDedupVolume,td>(void) __ptr64";
		//mdtruth = mstruth;
		mdTruth =
			"public: __cdecl std::vector<struct imDisableDedupVolume::`10'::VolumeWarning,class std::allocator<struct imDisableDedupVolume::`10'::VolumeWarning> >::~vector<struct imDisableDedupVolume::`10'::VolumeWarning,class std::allocator<struct imDisableDedupVolume::`10'::VolumeWarning> >(void) __ptr64";
		demangleAndTest();
	}

	//Was getting two negative signs: "--9223372036854775808"
	//Fixed 20170330
	@Test
	public void testWin10_0532164() throws Exception {
		mangled = "??_7?$CNetvmOpcodeConvOvf@_J_J_J$0?IAAAAAAAAAAAAAAA@$0HPPPPPPPPPPPPPPP@@@6B@";
		msTruth =
			"const CNetvmOpcodeConvOvf<__int64,__int64,__int64,-9223372036854775808,9223372036854775807>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Added 1 to the first number to make sure the solution in the above test works.
	//Fixed 20170330
	@Test
	public void testWin10_0532164_mod_add1() throws Exception {
		mangled = "??_7?$CNetvmOpcodeConvOvf@_J_J_J$0?IAAAAAAAAAAAAAAB@$0HPPPPPPPPPPPPPPP@@@6B@";
		msTruth =
			"const CNetvmOpcodeConvOvf<__int64,__int64,__int64,-9223372036854775809,9223372036854775807>::`vftable'";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// TODO: CONSIDER pulling template names (from MDQual, but not from MDBasicName) into
	//   MDReusableNames (these full template names get back-referenced)
	//Was getting the following, with incorrect backreferences:
	// demangled = "public: virtual class MapChanged::Windows::EventRegistrationToken __cdecl Platform::Foundation::Map<int,int,struct std::less<int> >::MapChanged::[Windows::Foundation::Collections::IObservableMap<int,int>]::add(class MapChanged::Windows::Foundation::MapChangedEventHandler<int,int> ^ __ptr64) __ptr64";
	//Fixed 20170330 (changed $Q within MDQualification to be MDQualification instead of MDQualifiedName).
	@Test
	public void testWin10_1234581() throws Exception {
		mangled =
			"?add@?Q?$IObservableMap@HH@Collections@Foundation@Windows@@MapChanged@?$Map@HHU?$less@H@std@@@2Platform@@UE$AAA?AVEventRegistrationToken@34@PE$AAV?$MapChangedEventHandler@HH@234@@Z";
		msTruth =
			"public: virtual class Windows::Foundation::EventRegistrationToken __cdecl Platform::Collections::Map<int,int,struct std::less<int> >::MapChanged::[Windows::Foundation::Collections::IObservableMap<int,int>]::add(class Windows::Foundation::Collections::MapChangedEventHandler<int,int> ^ __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Return type for type cast is also a high type that honors ABPQRS.
	//Fixed 20170331
	@Test
	public void testWin10_1445394() throws Exception {
		mangled = "??B?$CAutoCleanupBase@PEAD@RAII@@UEBAQEADXZ";
		msTruth =
			"public: virtual __cdecl RAII::CAutoCleanupBase<char * __ptr64>::operator char * __ptr64 const(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Return type for type cast is also a high type that honors ABPQRS.
	//Fixed 20170331
	@Test
	public void testWin10_1445394_simplified() throws Exception {
		mangled = "??BClassName@@YAQAHXZ";
		msTruth = "__cdecl ClassName::operator int * const(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Return type for type cast is also a high type that honors ABPQRS.
	//Fixed 20170331
	@Test
	public void testWin10_1445394_simplified_then_extended() throws Exception {
		mangled = "??BClassName@@YASEIFDHXZ";
		msTruth =
			"__cdecl ClassName::operator int const volatile __unaligned * __ptr64 __restrict const volatile(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Return type for type cast is also a high type that honors ABPQRS.
	//Fixed 20170331
	@Test
	public void testWin10_1473110() throws Exception {
		mangled = "??$?BPEAVFrsEvent@@@null_t@@QEBAQEAVFrsEvent@@XZ";
		msTruth =
			"public: __cdecl null_t::operator<class FrsEvent * __ptr64> class FrsEvent * __ptr64 const(void)const __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Template parameter "$S" (creating needsMSFTcommas as well)
	//Fixed 20170331
	@Test
	public void testWin10_2997194() throws Exception {
		mangled =
			"??$ConstructImpl@VShutdownWorkerProcessOperation@@U?$Tuple@$$$V@Common@WEX@@$S@?$Operation@VShutdownWorkerProcessOperation@@$$A6AJXZ@Communication@WEX@@CA?AV?$shared_ptr@VShutdownWorkerProcessOperation@@@tr1@std@@AEAU?$Tuple@$$$V@Common@2@U?$IntHolder@$S@72@@Z";
		msTruth =
			"private: static class std::tr1::shared_ptr<class ShutdownWorkerProcessOperation> __cdecl WEX::Communication::Operation<class ShutdownWorkerProcessOperation,long __cdecl(void)>::ConstructImpl<class ShutdownWorkerProcessOperation,struct WEX::Common::Tuple<> >(struct WEX::Common::Tuple<> & __ptr64,struct WEX::Common::IntHolder<>)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//Template parameter "$S" (creating needsMSFTcommas as well)
	//MSFT bug, gives comma before first parameter because MSFT thinks it needs one for the empty parameter encoded by $S (see notes within code)
	//Fixed 20170331
	@Test
	public void testWin10_2997194_fuzz1_forMSFTbug() throws Exception {
		mangled =
			"??$ConstructImpl@VShutdownWorkerProcessOperation@@U?$Tuple@$$$V@Common@WEX@@$S@?$Operation@VShutdownWorkerProcessOperation@@$$A6AJXZ@Communication@WEX@@CA?AV?$shared_ptr@VShutdownWorkerProcessOperation@@@tr1@std@@AEAU?$Tuple@$$$V@Common@2@U?$IntHolder@$SH@72@@Z";
		msTruth =
			"private: static class std::tr1::shared_ptr<class ShutdownWorkerProcessOperation> __cdecl WEX::Communication::Operation<class ShutdownWorkerProcessOperation,long __cdecl(void)>::ConstructImpl<class ShutdownWorkerProcessOperation,struct WEX::Common::Tuple<> >(struct WEX::Common::Tuple<> & __ptr64,struct WEX::Common::IntHolder<,int>)";
		mdTruth =
			"private: static class std::tr1::shared_ptr<class ShutdownWorkerProcessOperation> __cdecl WEX::Communication::Operation<class ShutdownWorkerProcessOperation,long __cdecl(void)>::ConstructImpl<class ShutdownWorkerProcessOperation,struct WEX::Common::Tuple<> >(struct WEX::Common::Tuple<> & __ptr64,struct WEX::Common::IntHolder<int>)";
		demangleAndTest();
	}

	//MSFT problem
	@Test
	public void testWin10_4791561() throws Exception {
		mangled = "?KdsmGenerateXmlFromCustodian@@$$FYMP$01EAEPEBU_MSFT_HgsGuardian@@@Z";
		msTruth = "cli::array<EPEBU_MSFT_HgsGuardian >^";
		mdTruth =
			"cli::array<unsigned char >^ __clrcall KdsmGenerateXmlFromCustodian(struct _MSFT_HgsGuardian const * __ptr64)";
		demangleAndTest();
	}

	//MSFT problem
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testWin10_0356843() throws Exception {
		mangled =
			"??1?$vector@UFileWarning@?6?CimUnoptimizeDedupFile@V?$allocator@UFileWarning@?6?CimUnoptimizeDedupFile@@std@@@std@@QEAA@XZ";
		msTruth =
			"public: __cdecl std::vector<,mUnoptimizeDedupFile,td>::~vector<,mUnoptimizeDedupFile,td>(void) __ptr64";
		mdTruth =
			"public: __cdecl std::vector<struct imUnoptimizeDedupFile::`7'::FileWarning,class std::allocator<struct imUnoptimizeDedupFile::`7'::FileWarning> >::~vector<struct imUnoptimizeDedupFile::`7'::FileWarning,class std::allocator<struct imUnoptimizeDedupFile::`7'::FileWarning> >(void) __ptr64";
		demangleAndTest();
	}

	@Test
	public void testWin10_3331869() throws Exception {
		mangled = "???__E??_7bad_alloc@std@@6B@@@YMXXZ@?A0x647dec29@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'const std::bad_alloc::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const std::bad_alloc::`vftable'''(void)(void)";
		demangleAndTest();
	}

	@Test
	public void testWin10_3331979() throws Exception {
		mangled = "???__E?A0x00c9e646@initlocks@@YMXXZ@?A0x00c9e646@@$$FYMXXZ";
		msTruth =
			"void __clrcall `anonymous namespace'::`dynamic initializer for 'void __clrcall initlocks::A0x00c9e646(void)''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_0022127() throws Exception {
		mangled =
			"??0?$CComObject@VImplSpecialization___LINE__@?CA@??CreateJob@@YAJKAEBU_SNASRequestData@@W4_SNJobType@@PEAU_SNJob@@PEAPEAVIJob@@@Z@@ATL@@QEAA@PEAX@Z";
		msTruth =
			"public: __cdecl ATL::CComObject<class `long __cdecl CreateJob(unsigned long,struct _SNASRequestData const & __ptr64,enum _SNJobType,struct _SNJob * __ptr64,class IJob * __ptr64 * __ptr64)'::`32'::ImplSpecialization___LINE__>::CComObject<class `long __cdecl CreateJob(unsigned long,struct _SNASRequestData const & __ptr64,enum _SNJobType,struct _SNJob * __ptr64,class IJob * __ptr64 * __ptr64)'::`32'::ImplSpecialization___LINE__>(void * __ptr64) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testJanGray_0() throws Exception {
		mangled = "__ehhandler$?test_except_f@@YAXH@Z";
		msTruth = "__ehhandler$?test_except_f@@YAXH@Z";
		mdTruth = "[EHHandler]{void __cdecl test_except_f(int)}";
		demangleAndTest();
	}

	@Test
	public void testJanGray_0_breakdown1() throws Exception {
		mangled = "?test_except_f@@YAXH@Z";
		msTruth = "void __cdecl test_except_f(int)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testJanGray_1() throws Exception {
		mangled = "__unwindfunclet$?test_except_f@@YAXH@Z$1";
		msTruth = "__unwindfunclet$?test_except_f@@YAXH@Z$1";
		mdTruth = "[UnwindFunclet,1]{void __cdecl test_except_f(int)}";
		demangleAndTest();
	}

	//Added this test for allowMDTypeInfoDefault() specialization method.
	@Test
	public void testWin10_3331871() throws Exception {
		mangled = "???__E??_7bad_cast@@6B@@@YMXXZ@?A0x6f83ba7f@@$$FYMXXZ";
		msTruth = "void __clrcall `dynamic initializer for 'const bad_cast::`vftable'''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'const bad_cast::`vftable'''(void)(void)";
		demangleAndTest();
	}

	//Added this test for allowMDTypeInfoDefault() specialization method.
	//Note, however, that the test is still not processed correctly for mdtruth, which
	// is only a guess.  A fix to process it (an MDMANG SPECIALIZATION used in MDQual)
	// causes a different test to fail: testWin10_0022127(). TODO: figure this out.
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testWin10_6798753() throws Exception {
		mangled =
			"?_Xlen@?$vector@UVolumeWarning@?BL@?CimStartDedupJob@V?$allocator@UVolumeWarning@?BL@?CimStartDedupJob@@std@@@std@@KAXXZ";
		//MSFT real truth (below) is garbage that we haven't modeled yet, so we are setting an MSFT truth of ""
		//mstruth = "protected: static void __cdecl std::vector<,mStartDedupJob,td>::_Xlen(void)";
		msTruth = ""; //Not what MSFT really produces.
		//Best guess for now:
		mdTruth =
			"protected: static void __cdecl std::vector<struct imStartDedupJob::`27'::VolumeWarning,class std::allocator<struct imStartDedupJob::`27'::VolumeWarning> >::_Xlen(void)";
		demangleAndTest();
	}

	@Test
	public void testWin10_6798753_breakdown1() throws Exception {
		mangled = "?_Xlen@?$vector@X@std@@KAXXZ";
		msTruth = "protected: static void __cdecl std::vector<void>::_Xlen(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_6798753_breakdown2() throws Exception {
		mangled = "?_Xlen@?$vector@UVolumeWarning@@V?$allocator@UVolumeWarning@@@std@@@std@@KAXXZ";
		msTruth =
			"protected: static void __cdecl std::vector<struct VolumeWarning,class std::allocator<struct VolumeWarning> >::_Xlen(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_6798753_breakdown3() throws Exception {
		mangled = "?$vector@UVolumeWarning@@";
		msTruth = "vector<struct VolumeWarning>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWin10_6798753_breakdown4() throws Exception {
		mangled = "?$vector@UVolumeWarning@?BL@@";
		msTruth = "vector<struct `27'::VolumeWarning>";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//I haven't determined what the true output should be yet.
	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testWin10_6798753_breakdown5() throws Exception {
		mangled = "?$vector@UVolumeWarning@?BL@?CimStartDedupJob@@";
		msTruth = "vector<,mStartDedupJob>"; //wrong
		mdTruth = "unknown";
		demangleAndTest();
	}

	@Test
	public void testExtra_for_String_Integration() throws Exception {
		mangled = "??_C@_00CNPNBAHC@?$AA@";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testVcamp110msvc_1() throws Exception {
		mangled =
			"??$_Uninit_move@PEAU?$pair@PEAU_View_info@details@Concurrency@@_N@std@@PEAU12@V?$allocator@U?$pair@PEAU_View_info@details@Concurrency@@_N@std@@@2@U12@@std@@YAPEAU?$pair@PEAU_View_info@details@Concurrency@@_N@0@PEAU10@00AEAU?$_Wrap_alloc@V?$allocator@U?$pair@PEAU_View_info@details@Concurrency@@_N@std@@@std@@@0@0U_Nonscalar_ptr_iterator_tag@0@@Z";
		msTruth =
			"struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64 __cdecl std::_Uninit_move<struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,class std::allocator<struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> >,struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> >(struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,struct std::_Wrap_alloc<class std::allocator<struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> > > & __ptr64,struct std::pair<struct Concurrency::details::_View_info * __ptr64,bool> * __ptr64,struct std::_Nonscalar_ptr_iterator_tag)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	//This is a real symbol that undname says is incomplete; we also say it is incomplete.  See
	// next test where we complete it with a 'Z' for the throw.  We might consider allowing
	// the process to interpret a truncated throw in some way.  Not sure in if it should be
	// interpreted with or without a throw, however.  Needs investigations.
	public void testWordpad_1() throws Exception {
		mangled = "?CreateObject@?$CProcessLocal@V_AFX_EXTDLL_STATE@@@@SGPAVCNoTrackObject@@X";
		//msTruth = "public: static class CNoTrackObject * __stdcall CProcessLocal<class _AFX_EXTDLL_STATE>::CreateObject(void) throw( ?? )";
		msTruth = "";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testWordpad_1_mod() throws Exception {
		mangled = "?CreateObject@?$CProcessLocal@V_AFX_EXTDLL_STATE@@@@SGPAVCNoTrackObject@@XZ";
		msTruth =
			"public: static class CNoTrackObject * __stdcall CProcessLocal<class _AFX_EXTDLL_STATE>::CreateObject(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_cn2_1232Z7_1() throws Exception {
		mangled = "?fn4@Bar2@Foo2c@@QAE?AVBar1@2@XZ";
		msTruth = "public: class Foo2c::Bar1 __thiscall Foo2c::Bar2::fn4(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_cn2_1232Z7_2() throws Exception {
		mangled = "?fn2@Bar1@?6??Bar3@Foo6@@SAHXZ@SAHXZ";
		msTruth =
			"public: static int __cdecl `public: static int __cdecl Foo6::Bar3(void)'::`7'::Bar1::fn2(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_cn3_1232Z7_1() throws Exception {
		mangled = "?fn3@?2??Bar3@Foo2b@@SAHXZ@4HA";
		msTruth = "int `public: static int __cdecl Foo2b::Bar3(void)'::`3'::fn3";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	//This should be the nexted name for the previous test.
	public void test_cn3_1232Z7_2() throws Exception {
		mangled = "?Bar3@Foo2b@@SAHXZ";
		msTruth = "public: static int __cdecl Foo2b::Bar3(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void test_temp_1() throws Exception {
		mangled = "?filt$0@?0??__ArrayUnwind@@YAXPEAX_KHP6AX0@Z@Z@4HA";
		msTruth = "";
		mdTruth =
			"int `void __cdecl __ArrayUnwind(void * __ptr64,unsigned __int64,int,void (__cdecl*)(void * __ptr64))'::`1'::filt$0";
		demangleAndTest();
	}

	//This requires work, as we are making up the mdTruth.
	//We get no output from undname or dumpbin for this.
	//Interestingly, the 64-bit version of gray.exe
	// only has one underscore in the beginning.  How do we
	// reconcile this.  Perhaps these are much different
	// than the __MEP and __T2M prefixes that we see from
	// dumpbin.
	//This is ThrowInfo type
//	@Ignore
	@Test
	public void testThrowInfo_1a() throws Exception {
		mangled = "__TI1?AUX@@";
		msTruth = "__TI1?AUX@@";
		mdTruth = "[ThrowInfo,1]{struct X}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testThrowInfo_1b() throws Exception {
		mangled = "_TI1?AUX@@";
		msTruth = "_TI1?AUX@@";
		mdTruth = "[ThrowInfo,1]{struct X}";
		demangleAndTest();
	}

//	@Ignore
	@Test
	public void testThrowInfo_2a() throws Exception {
		mangled = "__TI2PAVCircle3@@";
		msTruth = "__TI2PAVCircle3@@";
		mdTruth = "[ThrowInfo,2]{class Circle3 *}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testThrowInfo_2b() throws Exception {
		mangled = "_TI2PAVCircle3@@";
		msTruth = "_TI2PAVCircle3@@";
		mdTruth = "[ThrowInfo,2]{class Circle3 *}";
		demangleAndTest();
	}

	//This requires work, as we are making up the mdTruth.
	//We get no output from undname or dumpbin for this.
	//Interestingly, the 64-bit version of gray.exe
	// only has one underscore in the beginning.  How do we
	// reconcile this.  Perhaps these are much different
	// than the __MEP and __T2M prefixes that we see from
	// dumpbin.
	//This is CatchableTypeArray
//	@Ignore
	@Test
	public void testCatchableTypeArray_1a() throws Exception {
		mangled = "__CTA1?AUX@@";
		msTruth = "__CTA1?AUX@@";
		mdTruth = "[CatchableTypeArray,1]{struct X}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableTypeArray_1b() throws Exception {
		mangled = "_CTA1?AUX@@";
		msTruth = "_CTA1?AUX@@";
		mdTruth = "[CatchableTypeArray,1]{struct X}";
		demangleAndTest();
	}

//	@Ignore
	@Test
	public void testCatchableTypeArray_2a() throws Exception {
		mangled = "__CTA2PAVCircle3@@";
		msTruth = "__CTA2PAVCircle3@@";
		mdTruth = "[CatchableTypeArray,2]{class Circle3 *}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableTypeArray_2b() throws Exception {
		mangled = "_CTA2PAVCircle3@@";
		msTruth = "_CTA2PAVCircle3@@";
		mdTruth = "[CatchableTypeArray,2]{class Circle3 *}";
		demangleAndTest();
	}

	//This requires work, as we are making up the mdTruth.
	//We get no output from undname or dumpbin for this.
	//Interestingly, the 64-bit version of gray.exe
	// only has one underscore in the beginning.  How do we
	// reconcile this.  Perhaps these are much different
	// than the __MEP and __T2M prefixes that we see from
	// dumpbin.
	//Currently ignoring this test because we do not know
	// how to process all of the characters.  The last
	// character '1' remains with what we currently have.
	//This is CatchableType
//	@Ignore
	@Test
	public void testCatchableType_1a() throws Exception {
		mangled = "__CT??_R0?AUX@@@81";
		msTruth = "__CT??_R0?AUX@@@81";
		mdTruth = "[CatchableType,1]{struct X `RTTI Type Descriptor'}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableType_1b() throws Exception {
		mangled = "_CT??_R0?AUX@@@81";
		msTruth = "_CT??_R0?AUX@@@81";
		mdTruth = "[CatchableType,1]{struct X `RTTI Type Descriptor'}";
		demangleAndTest();
	}

//	@Ignore
	@Test
	public void testCatchableType_2a() throws Exception {
		mangled = "__CT??_R0PAVCircle3@@@84";
		msTruth = "__CT??_R0PAVCircle3@@@84";
		mdTruth = "[CatchableType,4]{class Circle3 * `RTTI Type Descriptor'}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableType_2b() throws Exception {
		mangled = "_CT??_R0PAVCircle3@@@84";
		msTruth = "_CT??_R0PAVCircle3@@@84";
		mdTruth = "[CatchableType,4]{class Circle3 * `RTTI Type Descriptor'}";
		demangleAndTest();
	}

	// Only one underscore
	// Has two embedded objects
	@Test
	public void testCatchableType_from_cn3_64bit_1() throws Exception {
		mangled =
			"_CT??_R0?AVExceptClassAsClassInExceptStructAsStructInNamespace@ExceptStructAsStructInNamespaceContainingExceptClassAsClass@ExceptNamespace@@@8??0ExceptClassAsClassInExceptStructAsStructInNamespace@ExceptStructAsStructInNamespaceContainingExceptClassAsClass@ExceptNamespace@@QEAA@AEBV012@@Z16";
		msTruth =
			"_CT??_R0?AVExceptClassAsClassInExceptStructAsStructInNamespace@ExceptStructAsStructInNamespaceContainingExceptClassAsClass@ExceptNamespace@@@8??0ExceptClassAsClassInExceptStructAsStructInNamespace@ExceptStructAsStructInNamespaceContainingExceptClassAsClass@ExceptNamespace@@QEAA@AEBV012@@Z16";
		mdTruth =
			"[CatchableType,16]{class ExceptNamespace::ExceptStructAsStructInNamespaceContainingExceptClassAsClass::ExceptClassAsClassInExceptStructAsStructInNamespace `RTTI Type Descriptor'}{public: __cdecl ExceptNamespace::ExceptStructAsStructInNamespaceContainingExceptClassAsClass::ExceptClassAsClassInExceptStructAsStructInNamespace::ExceptClassAsClassInExceptStructAsStructInNamespace(class ExceptNamespace::ExceptStructAsStructInNamespaceContainingExceptClassAsClass::ExceptClassAsClassInExceptStructAsStructInNamespace const & __ptr64) __ptr64}";
		demangleAndTest();
	}

	// Only one underscore
	// Has two embedded objects
	@Test
	public void testCatchableType_from_cn3_64bit_2() throws Exception {
		mangled = "_CT??_R0?AVBase2@BN2@@@8??0Base2@BN2@@QEAA@AEBV01@@Z8";
		msTruth = "_CT??_R0?AVBase2@BN2@@@8??0Base2@BN2@@QEAA@AEBV01@@Z8";
		mdTruth =
			"[CatchableType,8]{class BN2::Base2 `RTTI Type Descriptor'}{public: __cdecl BN2::Base2::Base2(class BN2::Base2 const & __ptr64) __ptr64}";
		demangleAndTest();
	}

	@Test
	public void testCatchableType_from_cn3_64bit_2_partB() throws Exception {
		mangled = "??_R0?AVBase2@BN2@@@8";
		//msTruth = "??_R0?AVBase2@BN2@@@8";
		mdTruth = "class BN2::Base2 `RTTI Type Descriptor'";
		msTruth = mdTruth;
		demangleAndTest();
	}

	@Test
	public void testCatchableType_from_cn3_64bit_2_partC() throws Exception {
		mangled = "??0Base2@BN2@@QEAA@AEBV01@@Z";
		//msTruth = "??0Base2@BN2@@QEAA@AEBV01@@Z";
		mdTruth = "public: __cdecl BN2::Base2::Base2(class BN2::Base2 const & __ptr64) __ptr64";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableType_from_cn3_64bit_3() throws Exception {
		mangled = "_CT??_R0?AVbad_alloc@std@@@8??0bad_alloc@std@@QEAA@AEBV01@@Z24";
		msTruth = "_CT??_R0?AVbad_alloc@std@@@8??0bad_alloc@std@@QEAA@AEBV01@@Z24";
		mdTruth =
			"[CatchableType,24]{class std::bad_alloc `RTTI Type Descriptor'}{public: __cdecl std::bad_alloc::bad_alloc(class std::bad_alloc const & __ptr64) __ptr64}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableType_from_cn3_64bit_4() throws Exception {
		mangled = "_CT??_R0?AVexception@std@@@8??0exception@std@@QEAA@AEBV01@@Z24";
		msTruth = "_CT??_R0?AVexception@std@@@8??0exception@std@@QEAA@AEBV01@@Z24";
		mdTruth =
			"[CatchableType,24]{class std::exception `RTTI Type Descriptor'}{public: __cdecl std::exception::exception(class std::exception const & __ptr64) __ptr64}";
		demangleAndTest();
	}

	//Only one underscore
	@Test
	public void testCatchableType_from_cn3_64bit_5() throws Exception {
		mangled = "_CT??_R0?AVbad_exception@std@@@8??0bad_exception@std@@QEAA@AEBV01@@Z24";
		msTruth = "_CT??_R0?AVbad_exception@std@@@8??0bad_exception@std@@QEAA@AEBV01@@Z24";
		mdTruth =
			"[CatchableType,24]{class std::bad_exception `RTTI Type Descriptor'}{public: __cdecl std::bad_exception::bad_exception(class std::bad_exception const & __ptr64) __ptr64}";
		demangleAndTest();
	}

	//From sourceP8.cpp
	@Test
	public void testBracketObject_m2mep_1() throws Exception {
		mangled = "__m2mep@?access@B@@$$FUEAAHXZ";
		//msTruth = "__m2mep@?access@B@@$$FUEAAHXZ";
		dbTruth = "[M2MEP] public: virtual int __cdecl B::access(void)";
		mdTruth = "[M2MEP] public: virtual int __cdecl B::access(void) __ptr64";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//From sourceP8.cpp
	@Test
	public void testBracketObject_unep_1() throws Exception {
		mangled = "__unep@?fnpro@testAccessLevel@@$$FIEAAHH@Z";
		msTruth = "__unep@?fnpro@testAccessLevel@@$$FIEAAHH@Z";
		mdTruth = "[UNEP] protected: int __cdecl testAccessLevel::fnpro(int) __ptr64";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testCatch_1() throws Exception {
		mangled = "__catch$?test_eh1@@YAHXZ$0";
		msTruth = "__catch$?test_eh1@@YAHXZ$0";
		mdTruth = "[Catch,0]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From gray.cpp
	@Ignore
	//@Test
	public void testCatch_2() throws Exception {
		mangled = "__catch$_main$0";
		msTruth = "__catch$_main$0";
		mdTruth = "[Catch,0]{main}";
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testCatchSym_1() throws Exception {
		mangled = "__catchsym$?test_eh1@@YAHXZ$9";
		msTruth = "__catchsym$?test_eh1@@YAHXZ$9";
		mdTruth = "[CatchSym,9]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From cn3.cpp
	//This one has two digits after the $ sign.
	@Test
	public void testCatchSym_2() throws Exception {
		mangled = "__catchsym$?test_eh1@@YAHXZ$10";
		msTruth = "__catchsym$?test_eh1@@YAHXZ$10";
		mdTruth = "[CatchSym,10]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testUnwindFunclet_1() throws Exception {
		mangled = "__unwindfunclet$?test_eh1@@YAHXZ$4";
		msTruth = "__unwindfunclet$?test_eh1@@YAHXZ$4";
		mdTruth = "[UnwindFunclet,4]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testTryblockTable_1() throws Exception {
		mangled = "__tryblocktable$?test_eh1@@YAHXZ";
		msTruth = "__tryblocktable$?test_eh1@@YAHXZ";
		mdTruth = "[TryblockTable]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testUnwindTable_1() throws Exception {
		mangled = "__unwindtable$?test_eh1@@YAHXZ";
		msTruth = "__unwindtable$?test_eh1@@YAHXZ";
		mdTruth = "[UnwindTable]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testEHHandler_1() throws Exception {
		mangled = "__ehhandler$?test_eh1@@YAHXZ";
		msTruth = "__ehhandler$?test_eh1@@YAHXZ";
		mdTruth = "[EHHandler]{int __cdecl test_eh1(void)}";
		demangleAndTest();
	}

	//From sourceP8.cpp
	@Test
	public void testMEP_1() throws Exception {
		mangled = "__mep@???__EPBBBMbr@@YMXXZ@?A0x640237ab@@$$FYMXXZ";
		dbTruth = "[MEP] void __clrcall `dynamic initializer for 'PBBBMbr''(void)";
		mdTruth =
			"[MEP] void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'PBBBMbr''(void)(void)";
		msTruth = dbTruth;
		demangleAndTest();
	}

	//From source9.cpp
	@Test
	public void testMEP_2() throws Exception {
		mangled = "__mep@?PrintHexBytes@@$$FYMXP$01EAE@Z";
		dbTruth =
			"[MEP] void __clrcall PrintHexBytes(cli::array< ?? :: ?? ::Z::E >^, ?? ) throw( ?? ))"; //obviously wrong
		mdTruth = "[MEP] void __clrcall PrintHexBytes(cli::array<unsigned char >^)";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//From source9.cpp
	@Test
	public void testMEP_3() throws Exception {
		mangled =
			"__mep@?PrintCountsAndBytes_e1@@$$FYMXPEAPE$AAVChar@System@@PE$AAVEncoding@Text@2@@Z";
		dbTruth =
			"[MEP] void __clrcall PrintCountsAndBytes_e1(class System::Char ^ *,class System::Text::Encoding ^))";
		mdTruth =
			"[MEP] void __clrcall PrintCountsAndBytes_e1(class System::Char ^ __ptr64 * __ptr64,class System::Text::Encoding ^ __ptr64)";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//From source9.cpp
	@Test
	public void testMEP_4() throws Exception {
		mangled = "__mep@?PrintCountsAndBytes_e2@@$$FYMXP$01EA_WPE$AAVEncoding@Text@System@@@Z";
		dbTruth =
			"[MEP] void __clrcall PrintCountsAndBytes_e2(cli::array<System::Text::_WPE$AAVEncoding >^))";
		mdTruth =
			"[MEP] void __clrcall PrintCountsAndBytes_e2(cli::array<wchar_t >^,class System::Text::Encoding ^ __ptr64)";
		msTruth = mdTruth;
		demangleAndTest();
	}

	//From Win10
	@Test
	public void testTemplatedOperator_0() throws Exception {
		mangled = "??$?6$0BE@@TextWriter@cxl@@QEAAAEAV01@AEAY0BE@$$CB_W@Z";
		msTruth =
			"public: class cxl::TextWriter & __ptr64 __cdecl cxl::TextWriter::operator<<<20>(wchar_t const (& __ptr64)[20]) __ptr64";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//From Win10
	@Test
	public void testTemplatedOperator_1() throws Exception {
		mangled =
			"??$?NDU?$char_traits@D@std@@V?$allocator@D@1@@std@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@0@Z";
		msTruth =
			"bool __cdecl std::operator<=<char,struct std::char_traits<char>,class std::allocator<char> >(class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > const & __ptr64,class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > const & __ptr64)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testTemplatedOperator_2() throws Exception {
		mangled = "??$?6N@?$myContainer@H@@QAE_NN@Z";
		msTruth = "public: bool __thiscall myContainer<int>::operator<<<double>(double)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//From cn3.cpp
	@Test
	public void testTemplatedOperator_3() throws Exception {
		mangled = "??$?MV?$myContainer@H@@@@YA_NABV?$myContainer@H@@0@Z";
		msTruth =
			"bool __cdecl operator<<class myContainer<int> >(class myContainer<int> const &,class myContainer<int> const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: considering for Issue 1162
	@Ignore
	public void testThreadSafeStaticGuard_1() throws Exception {
		mangled =
			"?$TSS0@?1??GetCategoryMap@CDynamicRegistrationInfoSource@XPerfAddIn@@SAPEBU_ATL_CATMAP_ENTRY@ATL@@XZ@4HA";
//		mangled =
//			"?xTSS0@?1??GetCategoryMap@CDynamicRegistrationInfoSource@XPerfAddIn@@SAPEBU_ATL_CATMAP_ENTRY@ATL@@XZ@4HA";
		//TODO: investigate and consider what we should have as outputs.
		msTruth = "";
		mdTruth =
			"int `public: static struct ATL::_ATL_CATMAP_ENTRY const * __ptr64 __cdecl XPerfAddIn::CDynamicRegistrationInfoSource::GetCategoryMap(void)'::`2'::`thread safe local static guard'";
		demangleAndTest();
	}

	//Issue 1344: Long symbols get MD5-hashed.
	// We have made up the output format.  Nothing is sacrosanct about this output.
	@Test
	public void testHashedSymbolComponentsLongerThan5096_1() throws Exception {
		mangled = "??@f4873c94f485cd6716c2319fc51ac714@";
		msTruth = "";
		mdTruth = "`f4873c94f485cd6716c2319fc51ac714'";
		demangleAndTest();
	}

	//Issue 1344: Long symbols get MD5-hashed.
	// We have made up the output format.  Nothing is sacrosanct about this output.
	@Test
	public void testHashedSymbolComponentsLongerThan5096_2() throws Exception {
		mangled = "?catch$0@?0???@f4873c94f485cd6716c2319fc51ac714@@4HA";
		msTruth = "";
		mdTruth = "int ``f4873c94f485cd6716c2319fc51ac714''::`1'::catch$0";
		demangleAndTest();
	}

	// Contrived example to make sure that the nameModifier (pushed into MDBasicName) and
	//  the recent addition, castTypeString (pushed to MDBasicName and below), play well
	//  together.  It also shows, that they should probably both be considered separate
	//  (i.e., do not use nameModifier to push in the castTypeString... we would have to
	//  manage merging and multiple calls... does not make sense to even consider it).
	// Note: the cast operator used to have the cast-to type emitted in MDFunctionType,
	//  and me moved it to MDSpecialName.
	@Test
	public void testCastOperatorWithAdjustorModifier() throws Exception {
		mangled = "??Bname@@O7AAHXZ";
		msTruth = "[thunk]:protected: virtual __cdecl name::operator int`adjustor{8}' (void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Contrived example.
	@Test
	public void testCastOperatorToFunctionPointer() throws Exception {
		mangled = "??BClassName@@YAP6KXP6KXH@Z@ZXZ";
		msTruth = "__cdecl ClassName::operator void (*)(void (*)(int))(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Contrived example.
	@Test
	public void testReferenceToConstMemberPointerOfTypeFloatAsFunctionParameter() throws Exception {
		mangled = "?FnName@FnSpace@@YKXABPUClassName@@M@Z";
		msTruth = "void FnSpace::FnName(float ClassName::* const &)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testFunctionIndirectWithBlankCallingConvention() throws Exception {
		mangled = "?FN@@QAAH$$A6KH@Z@Z";
		msTruth = "public: int __cdecl FN(int ())";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	public void testCPPManagedILMain_1() throws Exception {
		mangled = "?main@@$$HYAHXZ";
		msTruth = "int __cdecl main(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	@Test
	// Not happy with this next thing.... might be CPPManagedILDLLImporData, but not yet sure.
	public void testCPPManagedILDLLImportData_1() throws Exception {
		mangled =
			"???__E?Initialized@CurrentDomain@<CrtImplementationDetails>@@$$Q2HA@@YMXXZ@?A0x1ed4f156@@$$FYMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static int <CrtImplementationDetails>::CurrentDomain::Initialized''(void)";
		mdTruth =
			"void __clrcall `anonymous namespace'::void __clrcall `dynamic initializer for 'public: static int <CrtImplementationDetails>::CurrentDomain::Initialized''(void)(void)";
		demangleAndTest();
	}

	@Category(MDMangFailingTestCategory.class)
	@Test
	public void testCPPManagedILFunction_1() throws Exception {
		mangled =
			"?A0x1ed4f156.??__E?Initialized@CurrentDomain@<CrtImplementationDetails>@@$$Q2HA@@YMXXZ";
		msTruth = "unknown";
		mdTruth = msTruth;
		demangleAndTest();
	}

	// Temporary counterpoint in trying to figure out the above.
	@Test
	public void testXXXCounterpoint2() throws Exception {
		mangled = ".?AV?$name1@Vname2@@Uname3@name4@@@name4@@";
		mdTruth = "class name4::name1<class name2,struct name4::name3>";
		msTruth = mdTruth;
		demangleAndTest();
	}

	// Temporary test for trying to fuzz solutions for the above.
	@Test
	public void testXXXFuzz() throws Exception {
		mangled = "??__E?Initialized@CurrentDomain@<CrtImplementationDetails>@@$$Q2HA@@YMXXZ";
		msTruth =
			"void __clrcall `dynamic initializer for 'public: static int <CrtImplementationDetails>::CurrentDomain::Initialized''(void)";
		mdTruth = msTruth;
		demangleAndTest();
	}

	//TODO: ignore for now.
	@Ignore
	public void testFuzzyFit() throws Exception {
		MDFuzzyFit ff = new MDFuzzyFit();
		//from: testWin10_0358058()
		//mangled =
		//	"??1?$vector@UVolumeWarning@?9?CimDisableDedupVolume@V?$allocator@UVolumeWarning@?9?CimDisableDedupVolume@@std@@@std@@QEAA@XZ";
		//from: test_e304()
		//mangled =
		//	"?__abi_name0?$name1@P$AAVname2@name3@@____abi_name4@?Q?$name1@P$AAVname2@name3@@@name5@name6@name7@@?$name8@P$AAVname2@name3@@U?$name9@P$AAVname2@name3@@@name10@@@2name3@@U$AAGJIPAP$AAVname2@6@@Z";
		mangled = "?var@@3HA";
		ff.fuzz(mangled);
	}
}
