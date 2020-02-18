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
package ghidra.app.util.demangler;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.gnu.*;

public class GnuDemanglerParserTest extends AbstractGenericTest {

	private GnuDemanglerNativeProcess process;
	private GnuDemanglerParser parser;

	@Before
	public void setUp() throws Exception {
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_33_1);
		parser = new GnuDemanglerParser(process);
	}

	@Test
	public void test() throws Exception {
		long start = System.currentTimeMillis();

		demangle("_ZTVN6Magick21DrawableTextAntialiasE");
		demangle("_ZGVZN10KDirLister11emitChangesEvE3dot");//guard variables

		demangle("_ZZ18__gthread_active_pvE20__gthread_active_ptr");

		demangle("_ZNSt10_List_baseIN6Magick5VPathESaIS1_EE5clearEv");
		demangle("_ZTISt14unary_functionIPN9MagickLib12_DrawContextEvE");
		demangle("_ZTSSt14unary_functionIPN9MagickLib12_DrawContextEvE");
		demangle("_ZTCN4Arts17StdoutWriter_implE68_NS_11Object_skelE");
		demangle("_ZN6Magick5ImageD1Ev");
		demangle(
			"_ZN6Magick19matteFloodfillImageC2ERKNS_5ColorEjiiN9MagickLib11PaintMethodE");
		demangle("_ZThn8_N14nsPrintSession6AddRefEv");// non-virtual thunk
		demangle(
			"_ZTv0_n24_NSt19basic_ostringstreamIcSt11char_traitsIcE14pool_allocatorIcEED0Ev");// virtual thunk
		demangle("_ZTch0_h16_NK8KHotKeys13WindowTrigger4copyEPNS_10ActionDataE");// covariant return thunk

		demangle("_ZNK2cc14ScrollSnapTypeneERKS0_");

		List<String> list = loadTextResource(GnuDemanglerParserTest.class, "libMagick.symbols.txt");
		for (String mangled : list) {
			if (mangled == null) {
				break;
			}
			demangle(mangled);
		}

		System.out.println("Elapsed Time: " + (System.currentTimeMillis() - start));
	}

	private void demangle(String mangled) throws IOException {
		String demangled = process.demangle(mangled);
		assertNotNull(demangled);
		assertNotEquals(mangled, demangled);
		//System.out.println(parser.parse(mangled, demangled));
		assertNotNull(parser.parse(mangled, demangled));
	}

	@Test
	public void testOverloadedShiftOperatorParsingBug() {
		parser = new GnuDemanglerParser(null);
		DemangledObject object = parser.parse(null,
			"std::basic_istream<char, std::char_traits<char> >& " +
				"std::operator>><char, std::char_traits<char> >" +
				"(std::basic_istream<char, std::char_traits<char> >&, char&)");
		String name = object.getName();
		assertEquals("operator>><char,std--char_traits<char>>", name);
	}

	@Test
	public void testParsing() throws Exception {

		DemangledObject parse = parser.parse(null, "__gthread_active_p()::__gthread_active_ptr");
		assertTrue(parse instanceof DemangledVariable);
		assertName(parse, "__gthread_active_ptr", "__gthread_active_p()");

		parse = parser.parse(null, "typeinfo name for Magick::Blob");
		assertTrue(parse instanceof DemangledString);
		assertEquals("Magick::Blob", ((DemangledString) parse).getString());
		assertName(parse, "typeinfo_name", "Magick", "Blob");

		parse = parser.parse(null, "Bob::operator_new[](float, double, Bob::Fred &)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "operator_new[]", "Bob");

		parse = parser.parse(null,
			"Magick::pageImage::operator()(Magick::pageImage::Image::abc&) const");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "operator()", "Magick", "pageImage");

		parse = parser.parse(null,
			"std::__default_alloc_template<(bool)1, (int)0>::allocate(unsigned)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "allocate", "std", "__default_alloc_template<(bool)1,(int)0>");

		parse = parser.parse(null,
			"XpsMap<long, CORBA_TypeCode *>::XpsMap(unsigned long (*)(long const &), unsigned long, unsigned long, float)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "XpsMap", "XpsMap<long,CORBA_TypeCode*>");

		parse = parser.parse(null, "Bar::Foo::getX(float)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "getX", "Bar", "Foo");

		parse = parser.parse(null, "toChar(int)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "toChar");

		parse = parser.parse(null, "toFloat(int, double, char, long, short)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "toFloat");

		parse = parser.parse(null, "toFloat(int**, double**, char**, long**, short**)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "toFloat");

		parse = parser.parse(null, "Foo::operator<<(int)");
		assertTrue(parse instanceof DemangledMethod);
		assertName(parse, "operator<<", "Foo");

		parse = parser.parse(null, "Foo::getX(Bob::Fred<int>,double, Martha)");
		assertTrue(parse instanceof DemangledMethod);

		parse = parser.parse("_ZThn8_N14nsPrintSession14QueryInterfaceERK4nsIDPPv",
			"non-virtual thunk [nv:-8] to nsPrintSession::QueryInterface(nsID const&, void**)");
		assertTrue(parse instanceof DemangledThunk);
		assertName(parse, "QueryInterface", "nsPrintSession");

		parse = parser.parse(
			"_ZTv0_n24_NSt19basic_ostringstreamIcSt11char_traitsIcE14pool_allocatorIcEED1Ev",
			"virtual thunk [v:0,-24] to std::basic_ostringstream<char, std::char_traits<char>, pool_allocator<char> >::~basic_ostringstream [in-charge]()");
		assertTrue(parse instanceof DemangledThunk);
		assertName(parse, "~basic_ostringstream", "std",
			"basic_ostringstream<char,std--char_traits<char>,pool_allocator<char>>");

		parse = parser.parse("_ZTch0_h16_NK8KHotKeys13WindowTrigger4copyEPNS_10ActionDataE",
			"covariant return thunk [nv:0] [nv:16] to KHotKeys::WindowTrigger::copy(KHotKeys::ActionData*) const");
		assertTrue(parse instanceof DemangledThunk);
		assertName(parse, "copy", "KHotKeys", "WindowTrigger");

		try {
			parse = parser.parse(
				"_ZZN12GrGLFunctionIFPKhjEEC1IZN13skia_bindings28CreateGLES2InterfaceBindingsEPN3gpu5gles214GLES2InterfaceEPNS6_14ContextSupportEE3$_0EET_ENUlPKvjE_8__invokeESF_j",
				"GrGLFunction<unsigned char const* (unsigned int)>::GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0)::{lambda(void const*, unsigned int)#1}::__invoke(void const*, unsigned int)");
			assertNull("Shouldn't have parsed", parser);
		}
		catch (Exception exc) {
			// should get an exception
		}
	}

	private void assertName(DemangledObject demangledObj, String name, String... namespaces) {
//		String label = demangledObj.getName();
//		if (demangledObj instanceof DemangledString) {
//			label = ((DemangledString) demangledObj).getString();
//		}

		assertEquals("Unexpected demangled name", name, demangledObj.getName());
		DemangledType namespace = demangledObj.getNamespace();
		for (int i = namespaces.length - 1; i >= 0; i--) {
			String n = namespaces[i];
			assertNotNull("Namespace mismatch", namespace);
			assertEquals(n, namespace.getName());
			namespace = namespace.getNamespace();
		}
		assertNull("Namespace mismatch", namespace);
	}

	@Test
	public void testDataTypeParameters() throws Exception {
		String mangled = "_Z8glob_fn9cilxjmfdebPvPS_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);

		assertEquals("undefined glob_fn9(" +
			"char,int,long,long long,unsigned int,unsigned long,float,double,long double,bool,void *,void * *)",
			object.getSignature(false));
	}

	@Test
	public void testFunctionPointers() throws Exception {
		String mangled = "__t6XpsMap2ZlZP14CORBA_TypeCodePFRCl_UlUlUlf";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "XpsMap", "XpsMap<long,CORBA_TypeCode*>");

		assertEquals(
			"undefined XpsMap<long,CORBA_TypeCode*>::XpsMap(" +
				"unsigned long ()(long const &),unsigned long,unsigned long,float)",
			object.getSignature(false));

		DemangledMethod method = (DemangledMethod) object;

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(4, parameters.size());
		assertEquals("unsigned long ()(long const &)", parameters.get(0).toSignature());
		assertEquals("unsigned long", parameters.get(1).toSignature());
		assertEquals("unsigned long", parameters.get(2).toSignature());
		assertEquals("float", parameters.get(3).toSignature());
	}

	@Test
	public void testTemplates() throws Exception {
		String mangled =
			"_ZNKSt8_Rb_treeI8LocationS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE4findERKS0_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "find", "std",
			"_Rb_tree<Location,Location,std--_Identity<Location>,std--less<Location>,std--allocator<Location>>");

		DemangledMethod method = (DemangledMethod) object;
		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("Location const &", parameters.get(0).toSignature());

		mangled =
			"_ZSt16__insertion_sortIN9__gnu_cxx17__normal_iteratorIPSt4pairImP7PcodeOpESt6vectorIS5_SaIS5_EEEEPFbRKS5_SC_EEvT_SF_T0_";
		demangled = process.demangle(mangled);
		object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);

		method = (DemangledMethod) object;
		parameters = method.getParameters();

		assertEquals(
			"__insertion_sort<__gnu_cxx--__normal_iterator<std--pair<unsigned_long,PcodeOp*>*,std--vector<std--pair<unsigned_long,PcodeOp*>,std--allocator<std--pair<unsigned_long,PcodeOp*>>>>,bool(*)(std--pair<unsigned_long,PcodeOp*>const&,std--pair<unsigned_long,PcodeOp*>const&)>",
			method.getName());
		assertEquals("std", method.getNamespace().getName());

		// TODO: in the original, it was "bool (*)...."  now is "bool ()"  it still comes out as a function pointer
		assertEquals(
			"__gnu_cxx::__normal_iterator<std::pair<unsigned long,PcodeOp *> *,std::vector<std::pair<unsigned long,PcodeOp *>,std::allocator<std::pair<unsigned long,PcodeOp *>>>>",
			parameters.get(0).toString());
		assertEquals(
			"__gnu_cxx::__normal_iterator<std::pair<unsigned long,PcodeOp *> *,std::vector<std::pair<unsigned long,PcodeOp *>,std::allocator<std::pair<unsigned long,PcodeOp *>>>>",
			parameters.get(1).toString());
		assertEquals(
			"bool ()(std::pair<unsigned long,PcodeOp *> const &,std::pair<unsigned long,PcodeOp *> const &)",
			parameters.get(2).toString());

		assertTrue(parameters.get(2) instanceof DemangledFunctionPointer);

		DemangledFunctionPointer fptr = (DemangledFunctionPointer) parameters.get(2);

		assertEquals("bool", fptr.getReturnType().getName());

	}

	@Test
	public void testTemplatedConstructor() throws Exception {
		String mangled = "_ZNSt3setIP6bbnodeSt4lessIS1_ESaIS1_EE6insertERKS1_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "insert", "std",
			"set<bbnode*,std--less<bbnode*>,std--allocator<bbnode*>>");

		DemangledMethod method = (DemangledMethod) object;
		assertEquals(
			"undefined std::set<bbnode*,std--less<bbnode*>,std--allocator<bbnode*>>::insert(bbnode const * &)",
			method.getSignature(false));
		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("bbnode const * &", parameters.get(0).toSignature());
	}

	@Test
	public void testConstructor() throws Exception {
		String mangled = "_ZN3Bar4FredC1Ei";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "Fred", "Bar", "Fred");

		DemangledMethod method = (DemangledMethod) object;
		assertEquals("undefined Bar::Fred::Fred(int)", method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("int", parameters.get(0).toSignature());
	}

	@Test
	public void testMethods() throws Exception {
		String mangled = "_ZN3Foo7getBoolEf";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "getBool", "Foo");

		DemangledMethod method = (DemangledMethod) object;
		assertEquals("undefined Foo::getBool(float)", method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("float", parameters.get(0).toSignature());
	}

	@Test
	public void testFunctions() throws Exception {
		String mangled = "_Z7toFloatidcls";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "toFloat");

		assertEquals("undefined toFloat(int,double,char,long,short)", object.getSignature(false));

		DemangledFunction function = (DemangledFunction) object;

		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(5, parameters.size());
		assertEquals("int", parameters.get(0).toSignature());
		assertEquals("double", parameters.get(1).toSignature());
		assertEquals("char", parameters.get(2).toSignature());
		assertEquals("long", parameters.get(3).toSignature());
		assertEquals("short", parameters.get(4).toSignature());
	}

	@Test
	public void testVariables() throws Exception {
		String mangled = "_ZN6Magick18magickCleanUpGuardE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledVariable);
		assertName(object, "magickCleanUpGuard", "Magick");

		assertEquals("Magick::magickCleanUpGuard", object.getSignature(false));

		DemangledVariable variable = (DemangledVariable) object;

		assertNull(variable.getDataType()); // no type information provided
	}

	@Test
	public void testVTables() throws Exception {
		String mangled = "_ZTVN6Magick21DrawableTextAntialiasE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledAddressTable);
		assertName(object, "vtable", "Magick", "DrawableTextAntialias");

		assertEquals("Magick::DrawableTextAntialias::vtable", object.getSignature(false));

	}

	@Test
	public void testTypeInfo() throws Exception {
		String mangled = "_ZTIN4Arts28FileInputStream_impl_FactoryE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledAddressTable);
		assertName(object, "typeinfo", "Arts", "FileInputStream_impl_Factory");

		assertEquals("Arts::FileInputStream_impl_Factory::typeinfo", object.getSignature(false));
	}

	@Test
	public void testGuardVariables() throws Exception {

		String mangled = "_ZZ18__gthread_active_pvE20__gthread_active_ptr";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledVariable);
		assertName(object, "__gthread_active_ptr", "__gthread_active_p()");

		assertEquals("__gthread_active_p()::__gthread_active_ptr", object.getSignature(false));

		DemangledVariable variable = (DemangledVariable) object;
		assertEquals("__gthread_active_ptr", variable.getName());
		assertEquals("__gthread_active_p()", variable.getNamespace().getName());
		assertNull(variable.getDataType()); // no type information provided
	}

	@Test
	public void testConstFunction() throws Exception {
		//
		// The below demangles to LScrollerView::CalcPortExposedRect( const(Rect &, bool))
		// note the const() syntax
		//
		String mangled = "CalcPortExposedRect__13LScrollerViewCFR4Rectb";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "CalcPortExposedRect", "LScrollerView");

		assertEquals("undefined LScrollerView::CalcPortExposedRect(Rect &,bool)",
			object.getSignature(false));
	}

	@Test
	public void testVoidParameter() throws Exception {

		//
		// The below demangles to MsoDAL::VertFrame::__dt( (void))
		// note the (void) syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "__dt__Q26MsoDAL9VertFrameFv";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "__dt", "MsoDAL", "VertFrame");

		assertEquals("undefined MsoDAL::VertFrame::__dt(void)", object.getSignature(false));
	}

	@Test
	public void testStaticLocalVariable() throws Exception {
		//
		// The below demangles to DDDSaveOptionsCB(_WidgetRec*, void*, void*)::dialog [#1]
		//
		// from program ddd
		//
		String mangled = "_ZZ16DDDSaveOptionsCBP10_WidgetRecPvS1_E6dialog_0";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledVariable);
		assertName(object, "dialog", "DDDSaveOptionsCB(_WidgetRec*,void*,void*)");

		assertEquals("DDDSaveOptionsCB(_WidgetRec *,void *,void *)::dialog",
			object.getSignature(false));
	}

	@Test
	public void testArrayReferenceWithSize() throws Exception {

		//
		// The below demangles to CDataRenderer::GetColWidths( const(short (&)[7]))
		// note the short (&)[7] syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "GetColWidths__13CDataRendererCFRA7_s";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "GetColWidths", "CDataRenderer");

		assertEquals("undefined CDataRenderer::GetColWidths(short &[])",
			object.getSignature(false));
	}

	@Test
	public void testArrayPointerWithSize() throws Exception {

		//
		// The below demangles to CDataRenderer::GetColWidths( const(short (*)[7]))
		// note the short (*)[7] syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "GetColWidths__13CDataRendererCFPA7_s";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "GetColWidths", "CDataRenderer");

		assertEquals("undefined CDataRenderer::GetColWidths(short *[])",
			object.getSignature(false));
	}

	@Test
	public void testPointerToArrayPointer() throws Exception {
		//
		// The below demangled to Layout::graphNew(_GRAPH* (*) [41], char*)
		//

		String mangled = "_ZN6Layout8graphNewEPA41_P6_GRAPHPc";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "graphNew", "Layout");

		// note: the two pointers were condensed to one (I think this is correct, but not sure)
		assertEquals("undefined Layout::graphNew(_GRAPH *[],char *)", object.getSignature(false));
	}

	@Test
	public void testPointerToArrayWithSpace() throws Exception {
		//
		// A fabricated example test space between the pointer and the array syntax
		//

		String mangled = "fake";
		String demangled = "Layout::graphNew(short (*) [41], char*)";

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "graphNew", "Layout");

		assertEquals("undefined Layout::graphNew(short *[],char *)", object.getSignature(false));
	}

	@Test
	public void testArrayPointerWithSize_TrailedByAnotherParamter() throws Exception {

		//
		// This is testing a bug where we were 'off by one' when the array pointer syntax was
		// followed by another parameter.
		//
		// The below demangles to _gmStage2(SECTION_INFO *, int *, int (*)[12], int, short const *) 
		//
		String mangled = "_gmStage2__FP12SECTION_INFOPiPA12_iiPCs";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "_gmStage2");

		assertEquals("undefined _gmStage2(SECTION_INFO *,int *,int *[],int,short const *)",
			object.getSignature(false));

		DemangledMethod method = (DemangledMethod) object;

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(5, parameters.size());
		assertEquals("SECTION_INFO *", parameters.get(0).toSignature());
		assertEquals("int *", parameters.get(1).toSignature());
		assertEquals("int *[]", parameters.get(2).toSignature());
		assertEquals("int", parameters.get(3).toSignature());
		assertEquals("short const *", parameters.get(4).toSignature());
	}

	@Test
	public void testUnnecessaryParentheses() throws Exception {

		//
		// The below demangles to CStr::Buffer::__ct( (CStr &, unsigned long))
		// note the ((...)) syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "__ct__Q24CStr6BufferFR4CStrUl";

		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "__ct", "CStr", "Buffer");

		assertEquals("undefined CStr::Buffer::__ct(CStr &,unsigned long)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatedParametersWithAssignment() throws Exception {
		//
		// This tests templates that have default values, which look something like this:
		// 		template <class T=char, int N=100>
		//
		// with a demangled symbol looking like this:
		// 		classname<char,(int)100>
		//
		// note the casting, which is not always there
		//

		//
		// Variable
		//
		String mangled = "_Z3aaaILN3bbb3cccE120E3dddE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledVariable);
		assertName(object, "aaa<(bbb--ccc)120,ddd>");

		assertEquals("aaa<(bbb--ccc)120,ddd>", object.getSignature(false));

		//
		// Functions
		//

		// template with cast
		mangled = "_ZN10mysequenceIiLi5EE9setmemberEii";

		demangled = process.demangle(mangled);

		object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "setmember", "mysequence<int,5>");

		assertEquals("undefined mysequence<int,5>::setmember(int,int)", object.getSignature(false));

		//
		// Class
		//

		// constructor with template (this was broken once during changes--here now for regression)
		mangled = "_ZN6Magick5ImageC1ERKSs";

		demangled = process.demangle(mangled);

		object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "Image", "Magick", "Image");

		assertEquals(
			"undefined Magick::Image::Image(" +
				"std::basic_string<char,std::char_traits<char>,std::allocator<char>> const &)",
			object.getSignature(false));
	}

	@Test
	public void testOperator() throws Exception {
		String mangled = "_ZN6MagickltERKNS_10CoordinateES2_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledMethod);
		assertName(object, "operator<", "Magick");

		DemangledMethod method = (DemangledMethod) object;
		assertEquals(
			"undefined Magick::operator<(Magick::Coordinate const &,Magick::Coordinate const &)",
			method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(2, parameters.size());
		assertEquals("Magick::Coordinate const &", parameters.get(0).toSignature());
		assertEquals("Magick::Coordinate const &", parameters.get(1).toSignature());
	}

	@Test
	public void testOperatorCastTo() throws Exception {
		//
		// Mangled: _ZNKSt17integral_constantIbLb0EEcvbEv
		// 
		// Demangled: std::integral_constant<bool, false>::operator bool() const

		String mangled = "_ZNKSt17integral_constantIbLb0EEcvbEv";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertTrue(object instanceof DemangledFunction);

		String signature = object.getSignature(false);
		assertEquals(
			"bool std::integral_constant::operator.cast.to.bool(void)",
			signature);
	}

	@Test
	public void testConversionOperator() throws Exception {

		//
		// Converts the object upon which it is overridden to the given value.
		// 
		// Format: operator std::string() const { return "bob"; }
		//
		//

		String mangled = "_ZNK6Magick5ColorcvSsEv";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator.cast.to.basic_string", "Magick", "Color");

		assertEquals("std::basic_string<char,std::char_traits<char>,std::allocator<char>> " +
			"Magick::Color::operator.cast.to.basic_string(void)", object.getSignature(false));
	}

	@Test
	public void testConversionOperatorWithConst() throws Exception {

		// 
		//
		// Mangled: _ZN12_GLOBAL__N_120decode_charset_iconvEPKc
		//
		// Demangled: GCC_IndicationPDU::operator GCC_ApplicationInvokeIndication const&() const
		//

		//
		// Converts the object upon which it is overridden to the given value.
		// 
		// Format: operator std::string() const { return "bob"; }
		//
		//

		String mangled = "_ZNK17GCC_IndicationPDUcvRK31GCC_ApplicationInvokeIndicationEv";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator.cast.to.GCC_ApplicationInvokeIndication&",
			"GCC_IndicationPDU");

		assertEquals(
			"GCC_ApplicationInvokeIndication const & GCC_IndicationPDU::operator.cast.to.GCC_ApplicationInvokeIndication&(void)",
			object.getSignature(false));
	}

	@Test
	public void testOperatorDelete() throws Exception {

		//
		// Converts the object upon which it is overridden to the given value.
		// 
		// Format: operator delete(void*)
		//

		String mangled = "_ZdlPv";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator.delete");

		assertEquals("void operator.delete(void *)", object.getSignature(false));
	}

	@Test
	public void testOperatorDeleteWithArraySyntax() throws Exception {

		//
		// Converts the object upon which it is overridden to the given value.
		// 
		// Format: operator delete[](void*)
		//

		DemangledObject object = parser.parse("mangled", "operator delete[](void*)");
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator.delete[]");

		assertEquals("void operator.delete[](void *)", object.getSignature(false));
	}

	@Test
	public void testOperatorNew() throws Exception {

		//
		// Converts the object upon which it is overridden to the given value.
		// 
		// Format: operator new(unsigned long)
		//

		String mangled = "_Znwm";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator.new");

		assertEquals("void * operator.new(unsigned long)", object.getSignature(false));
	}

	@Test
	public void testFunctorOperator() throws Exception {
		String mangled = "_ZNK6Magick9viewImageclERNS_5ImageE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "operator()", "Magick", "viewImage");

		assertEquals("undefined Magick::viewImage::operator()(Magick::Image &)",
			object.getSignature(false));
		//c++filt results: "undefined Magick::viewImage::operator()(Magick::Image&) const"
	}

	@Test
	public void testAnonymousNamespace() throws Exception {
		//
		// Mangled: _ZN12_GLOBAL__N_120decode_charset_iconvEPKc
		//
		// Demangled: (anonymous namespace)::decode_charset_iconv(char const*)
		//
		String mangled = "_ZN12_GLOBAL__N_120decode_charset_iconvEPKc";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "decode_charset_iconv", "anonymous_namespace");

		assertEquals("undefined anonymous_namespace::decode_charset_iconv(char const *)",
			object.getSignature(false));
	}

	@Test
	public void testEmbeddedAnonymousNamespace() throws Exception {
		//
		// Mangled: _ZN5MeCab12_GLOBAL__N_18mystrdupEPKc
		//
		// Demangled: MeCab::(anonymous namespace)::mystrdup(char const*)
		//
		String mangled = "_ZN5MeCab12_GLOBAL__N_18mystrdupEPKc";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "mystrdup", "MeCab", "anonymous_namespace");

		assertEquals("undefined MeCab::anonymous_namespace::mystrdup(char const *)",
			object.getSignature(false));
	}

	@Test
	public void testAnonymousNamespaceInTemplatesAndReturnTypeAndParameters() throws Exception {
		//
		// Mangled: _ZSt24__uninitialized_copy_auxIPN5MeCab12_GLOBAL__N_15RangeES3_ET0_T_S5_S4_St12__false_type
		//
		// Demangled: MeCab::(anonymous namespace)::Range* std::__uninitialized_copy_aux<MeCab::(anonymous namespace)::Range*, MeCab::(anonymous namespace)::Range*>(MeCab::(anonymous namespace)::Range*, MeCab::(anonymous namespace)::Range*, MeCab::(anonymous namespace)::Range*, std::__false_type)
		//
		String mangled =
			"_ZSt24__uninitialized_copy_auxIPN5MeCab12_GLOBAL__N_15RangeES3_ET0_T_S5_S4_St12__false_type";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object,
			"__uninitialized_copy_aux<MeCab--anonymous_namespace--Range*,MeCab--anonymous_namespace--Range*>",
			"std");

		assertEquals(
			"MeCab::anonymous_namespace::Range * std::__uninitialized_copy_aux<MeCab--anonymous_namespace--Range*,MeCab--anonymous_namespace--Range*>(MeCab::anonymous_namespace::Range *,MeCab::anonymous_namespace::Range *,MeCab::anonymous_namespace::Range *,std::__false_type)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatedParametersWithCast() throws Exception {
		//
		// Mangled: _ZN2Dr15ClipboardHelper17FTransferGvmlDataERN3Art11TransactionERKN3Ofc13TReferringPtrINS_10DrawingE2oEEEbNS4_7TCntPtrI11IDataObjectEERNS_18IClientDataCreatorERNS4_7TVectorINS4_8TWeakPtrINS_14DrawingElementEEELj0ELj4294967295EEERNS1_6Rect64E
		//
		// Demangled: Ofc::TSimpleTypeHelper<Art::Percentage>::ToString(Art::Percentage const&, Ofc::TFixedVarStr<(int)2085>&)
		//		
		String mangled =
			"_ZN2Dr15ClipboardHelper17FTransferGvmlDataERN3Art11TransactionERKN3Ofc13TReferringPtrINS_10DrawingE2oEEEbNS4_7TCntPtrI11IDataObjectEERNS_18IClientDataCreatorERNS4_7TVectorINS4_8TWeakPtrINS_14DrawingElementEEELj0ELj4294967295EEERNS1_6Rect64E";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "FTransferGvmlData", "Dr", "ClipboardHelper");

		assertEquals(
			"undefined Dr::ClipboardHelper::FTransferGvmlData(Art::Transaction &,Ofc::TReferringPtr<Dr::DrawingE2o> const &,bool,Ofc::TCntPtr<IDataObject>,Dr::IClientDataCreator &,Ofc::TVector<Ofc::TWeakPtr<Dr::DrawingElement>,0u,4294967295u> &,Art::Rect64 &)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatedNameSpaces() throws Exception {
		//
		// Mangled: _ZN4Core9AsyncFile7performEON3WTF1FIFNS2_IFvRNS_10FileClientEEEERNS_4FileEEEE
		//
		// Demangled: Core::AsyncFile::perform(WTF::F<WTF::F<void (Core::FileClient&)> (Core::File&)>&&)
		//		
		String mangled =
			"_ZN4Core9AsyncFile7performEON3WTF1FIFNS2_IFvRNS_10FileClientEEEERNS_4FileEEEE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue("Parsed a function", object instanceof DemangledFunction);
		assertName(object, "perform", "Core", "AsyncFile");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		assertEquals("Name of type parsed", "F", parameters.get(0).getName());
		assertEquals("Param Type Name parsed", "WTF::",
			parameters.get(0).getNamespace().toString());
		assertEquals("Param Template was parsed",
			"<WTF::F<void (Core::FileClient &)> (Core::File &)>",
			parameters.get(0).getTemplate().toString());

		assertEquals(
			"undefined Core::AsyncFile::perform(WTF::F<WTF::F<void (Core::FileClient &)> (Core::File &)> * &)",
			object.getSignature(false));

	}

	@Test
	public void testFunctionInsideOfTemplates_NoArguments_NoPointerParens() throws Exception {
		//
		// Mangled: _ZN15LogLevelMonitor27registerKeysChangedCallbackERKN5boost8functionIFvvEEE
		// 
		// Demangled: LogLevelMonitor::registerKeysChangedCallback(boost::function<void ()> const&)

		String mangled =
			"_ZN15LogLevelMonitor27registerKeysChangedCallbackERKN5boost8functionIFvvEEE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);

		assertName(object, "registerKeysChangedCallback", "LogLevelMonitor");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		DemangledDataType demangParamDT = parameters.get(0);

		assertEquals("Name of type parsed", "function", demangParamDT.getName());
		assertEquals("Param Type Name parsed", "boost::", demangParamDT.getNamespace().toString());
		assertEquals("Param Template parsed", "<void ()>", demangParamDT.getTemplate().toString());
		assertTrue("Is referent", demangParamDT.isReference());

		assertEquals(
			"undefined LogLevelMonitor::registerKeysChangedCallback(boost::function<void ()> const &)",
			object.getSignature(false));
	}

	@Test
	public void testFunctionInsideOfTemplates_WithArguments_NoPointerParens() throws Exception {
		//
		// Mangled: _ZN9DnsThread32set_mutate_ares_options_callbackERKN5boost8functionIFvP12ares_optionsPiEEE
		// 
		// Demangled: DnsThread::set_mutate_ares_options_callback(boost::function<void (ares_options*, int*)> const&)

		String mangled =
			"_ZN9DnsThread32set_mutate_ares_options_callbackERKN5boost8functionIFvP12ares_optionsPiEEE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "set_mutate_ares_options_callback", "DnsThread");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		DemangledDataType demangParamDT = parameters.get(0);

		assertEquals("Name of type parsed", "function", demangParamDT.getName());
		assertEquals("Param Type Name parsed", "boost::", demangParamDT.getNamespace().toString());
		assertEquals("Param Template parsed", "<void (ares_options *,int *)>",
			demangParamDT.getTemplate().toString());
		assertTrue("Is referent", demangParamDT.isReference());
		assertTrue("Is Const", demangParamDT.isConst());

		assertEquals(
			"undefined DnsThread::set_mutate_ares_options_callback(boost::function<void (ares_options *,int *)> const &)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatesThatContainFunctionSignatures() throws Exception {
		//
		// Mangled: _ZNSt6vectorIN5boost8functionIFvvEEESaIS3_EE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPS3_S5_EERKS3_
		// 
		// Demangled: std::vector<boost::function<void ()>, std::allocator<boost::function<void ()> > >::_M_insert_aux(__gnu_cxx::__normal_iterator<boost::function<void ()>*, std::vector<boost::function<void ()>, std::allocator<boost::function<void ()> > > >, boost::function<void ()> const&)

		String mangled =
			"_ZNSt6vectorIN5boost8functionIFvvEEESaIS3_EE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPS3_S5_EERKS3_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledFunction);
		assertName(object, "_M_insert_aux", "std",
			"vector<boost--function<void()>,std--allocator<boost--function<void()>>>");

		assertEquals(
			"undefined std::vector<boost--function<void()>,std--allocator<boost--function<void()>>>::_M_insert_aux(__gnu_cxx::__normal_iterator<boost::function<void ()> *,std::vector<boost::function<void ()>,std::allocator<boost::function<void ()>>>>,boost::function<void ()> const &)",
			object.getSignature(false));
	}

	@Test
	public void testVtableParsingError_NoSpaceBeforeTrailingDigits() throws Exception {
		//
		// Mangled: _ZTCN6Crypto10HmacSha256E0_NS_3MacE
		// 
		// Demangled: 

		String mangled = "_ZTCN6Crypto10HmacSha256E0_NS_3MacE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertTrue(object instanceof DemangledAddressTable);
		assertName(object, "construction-vtable", "Crypto", "Mac-in-Crypto", "HmacSha");

		assertEquals("Crypto::Mac-in-Crypto::HmacSha::construction-vtable",
			object.getSignature(false));
	}

	@Test
	public void testVarArgs() throws Exception {
		//
		// Mangled: _Z11testVarArgsiz
		// 
		// Demangled: testVarArgs(int, ...)

		String mangled = "_Z11testVarArgsiz";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertTrue(object instanceof DemangledFunction);

		DemangledFunction function = (DemangledFunction) object;
		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(2, parameters.size());
		assertTrue(parameters.get(1).isVarArgs());

		assertEquals("undefined testVarArgs(int,...)", object.getSignature(false));
	}

	@Test
	public void testMultidimensionalArrayFunctionParameter() throws Exception {
		//
		// Mangled: _ZN12uavcan_stm329CanDriverC1ILj64EEERA2_AT__NS_9CanRxItemE
		// 
		// Demangled: uavcan_stm32::CanDriver::CanDriver<64u>(uavcan_stm32::CanRxItem (&) [2][64u])
		//

		String mangled = "_ZN12uavcan_stm329CanDriverC1ILj64EEERA2_AT__NS_9CanRxItemE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertTrue(object instanceof DemangledFunction);

		String signature = object.getSignature(false);
		assertEquals(
			"undefined uavcan_stm32::CanDriver::CanDriver<64u>(uavcan_stm32::CanRxItem &[][])",
			signature);
	}

	@Test
	public void testInvalidMangledSymbol() throws Exception {
		//
		// This is a function name that the native demangler tries to demangle, but should not:
		// Input: uv__dup
		// Incorrect Native Output: uv(double,  *__restrict)
		// 
		String mangled = "uv__dup";

		GnuDemangler demangler = new GnuDemangler();
		DemangledObject res = demangler.demangle(mangled);
		assertNull(res);
	}

	// @Test TODO upcoming fix for GT-3545
	public void testFunctionWithLambda_WrappingAnotherFunctionCall() throws Exception {

		//
		// Mangled: _Z11wrap_360_cdIiEDTcl8wrap_360fp_Lf42c80000EEET_
		// 
		// Demangled: (wrap_360({parm#1}, (float)[42c80000])) wrap_360_cd<int>(int)
		//

		String mangled = "_Z11wrap_360_cdIiEDTcl8wrap_360fp_Lf42c80000EEET_";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertTrue(object instanceof DemangledFunction);

		// TODO maybe put full output in setUtilDemangled()
		String signature = object.getSignature(false);
		assertEquals("undefined wrap_360_cd<int>(int)", signature);
	}
}
