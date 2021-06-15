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
		parser = new GnuDemanglerParser();
	}

	@Test
	public void testParse_ArrayPointerReferencePattern_ConstArray() throws Exception {

		// bob(int const[8] (*) [12])

		//
		// Note: it is not clear whether the this demangled string is valid modern demangler output.
		//       We are creating a constant array pointer from this construct, but is this what
		//       we should be creating?
		//

		String demangled = "bob(int const[8] (*) [12])";
		DemangledObject object = parser.parse("fake", demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "bob");

		DemangledFunction function = (DemangledFunction) object;
		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(1, parameters.size());
		DemangledDataType p1 = parameters.get(0);
		assertEquals("bob(int const[8] (*) [12])", p1.getOriginalDemangled());
		assertEquals("undefined bob(int const *[])", object.getSignature(false));
	}

	@Test
	public void testParse_ArrayPointerReferencePattern_ConstPointerToArrayReference()
			throws Exception {

		// _S_ptr(entt::sparse_set<EntityId> const * &[])

		String mangled =
			"_ZNSt14__array_traitsIPKN4entt10sparse_setI8EntityIdEELm3EE6_S_ptrERA3_KS5_";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"undefined std::__array_traits<entt::sparse_set<EntityId>const*,3ul>::_S_ptr(entt::sparse_set<EntityId> const * &[])",
			signature);
	}

	@Test
	public void testParse_CastInTemplates() throws Exception {

		String demangled = "std::__default_alloc_template<(bool)1, (int)0>::allocate(unsigned)";
		DemangledObject object = parser.parse("fake", demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "allocate", "std", "__default_alloc_template<(bool)1,(int)0>");

		assertEquals("undefined std::__default_alloc_template<(bool)1,(int)0>::allocate(unsigned)",
			object.getSignature(false));
	}

	@Test
	public void testParse_CastInTemplates_WithNegativeNumber() throws Exception {

		String demangled =
			"A::B::C<int, (int)-2147483648>::Foo::Foo(A::B::Bar*, A::B::C<int, (int)-2147483648>::Foo*)";
		DemangledObject object = parser.parse("fake", demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "Foo", "A", "B", "C<int,(int)-2147483648>", "Foo");

		assertEquals(
			"undefined A::B::C<int,(int)-2147483648>::Foo::Foo(A::B::Bar *,A::B::C<int,(int)-2147483648>::Foo *)",
			object.getSignature(false));
	}

	@Test
	public void testParse_MultiDimensionalArray() throws Exception {

		DemangledObject object = parser.parse("fake", "Layout::graphNew(short[][][][], char*)");
		assertType(object, DemangledFunction.class);
		DemangledFunction function = (DemangledFunction) object;
		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(2, parameters.size());
		DemangledDataType p1 = parameters.get(0);
		assertEquals(4, p1.getArrayDimensions());
	}

	@Test
	public void testDataTypeParameters() throws Exception {
		String mangled = "_Z8glob_fn9cilxjmfdebPvPS_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);

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
		assertType(object, DemangledFunction.class);
		assertName(object, "XpsMap", "XpsMap<long,CORBA_TypeCode*>");

		assertEquals(
			"undefined XpsMap<long,CORBA_TypeCode*>::XpsMap(" +
				"unsigned long (*)(long const &),unsigned long,unsigned long,float)",
			object.getSignature(false));

		DemangledFunction method = (DemangledFunction) object;

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(4, parameters.size());
		assertEquals("unsigned long (*)(long const &)", parameters.get(0).getSignature());
		assertEquals("unsigned long", parameters.get(1).getSignature());
		assertEquals("unsigned long", parameters.get(2).getSignature());
		assertEquals("float", parameters.get(3).getSignature());
	}

	@Test
	public void testTemplates_TemplatedType() throws Exception {
		String mangled =
			"_ZNKSt8_Rb_treeI8LocationS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE4findERKS0_";
		String demangled = process.demangle(mangled);
		assertEquals("std" + "::" +
			"_Rb_tree<Location, Location, std::_Identity<Location>, std::less<Location>, std::allocator<Location> >" +
			"::" + "find(Location const&) const", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "find", "std",
			"_Rb_tree<Location,Location,std::_Identity<Location>,std::less<Location>,std::allocator<Location>>");

		DemangledFunction function = (DemangledFunction) object;
		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("Location const &", parameters.get(0).getSignature());
	}

	@Test
	public void testTemplates_TemplatedInsertionSort() throws Exception {

		String mangled =
			"_ZSt16__insertion_sortIN9__gnu_cxx17__normal_iteratorIPSt4pairImP7PcodeOpESt6vectorIS5_SaIS5_EEEEPFbRKS5_SC_EEvT_SF_T0_";
		String demangled = process.demangle(mangled);
		assertEquals(
			"void std::__insertion_sort<__gnu_cxx::__normal_iterator<std::pair<unsigned long, PcodeOp*>*, std::vector<std::pair<unsigned long, PcodeOp*>, std::allocator<std::pair<unsigned long, PcodeOp*> > > >, bool (*)(std::pair<unsigned long, PcodeOp*> const&, std::pair<unsigned long, PcodeOp*> const&)>(__gnu_cxx::__normal_iterator<std::pair<unsigned long, PcodeOp*>*, std::vector<std::pair<unsigned long, PcodeOp*>, std::allocator<std::pair<unsigned long, PcodeOp*> > > >, __gnu_cxx::__normal_iterator<std::pair<unsigned long, PcodeOp*>*, std::vector<std::pair<unsigned long, PcodeOp*>, std::allocator<std::pair<unsigned long, PcodeOp*> > > >, bool (*)(std::pair<unsigned long, PcodeOp*> const&, std::pair<unsigned long, PcodeOp*> const&))",
			demangled);
		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);

		DemangledFunction function = (DemangledFunction) object;
		List<DemangledDataType> parameters = function.getParameters();

		assertEquals(
			"__insertion_sort<__gnu_cxx::__normal_iterator<std::pair<unsigned_long,PcodeOp*>*,std::vector<std::pair<unsigned_long,PcodeOp*>,std::allocator<std::pair<unsigned_long,PcodeOp*>>>>,bool(*)(std::pair<unsigned_long,PcodeOp*>const&,std::pair<unsigned_long,PcodeOp*>const&)>",
			function.getName());
		assertEquals("std", function.getNamespace().getName());

		assertEquals(
			"__gnu_cxx::__normal_iterator<std::pair<unsigned long,PcodeOp *> *,std::vector<std::pair<unsigned long,PcodeOp *>,std::allocator<std::pair<unsigned long,PcodeOp *>>>>",
			parameters.get(0).toString());
		assertEquals(
			"__gnu_cxx::__normal_iterator<std::pair<unsigned long,PcodeOp *> *,std::vector<std::pair<unsigned long,PcodeOp *>,std::allocator<std::pair<unsigned long,PcodeOp *>>>>",
			parameters.get(1).toString());
		assertEquals(
			"bool (*)(std::pair<unsigned long,PcodeOp *> const &,std::pair<unsigned long,PcodeOp *> const &)",
			parameters.get(2).toString());

		assertType(parameters.get(2), DemangledFunctionPointer.class);

		DemangledFunctionPointer fptr = (DemangledFunctionPointer) parameters.get(2);

		assertEquals("bool", fptr.getReturnType().getName());

	}

	@Test
	public void testTemplatedConstructor() throws Exception {
		String mangled = "_ZNSt3setIP6bbnodeSt4lessIS1_ESaIS1_EE6insertERKS1_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "insert", "std",
			"set<bbnode*,std::less<bbnode*>,std::allocator<bbnode*>>");

		DemangledFunction method = (DemangledFunction) object;
		assertEquals(
			"undefined std::set<bbnode*,std::less<bbnode*>,std::allocator<bbnode*>>::insert(bbnode const * &)",
			method.getSignature(false));
		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("bbnode const * &", parameters.get(0).getSignature());
	}

	@Test
	public void testConstructor() throws Exception {
		String mangled = "_ZN3Bar4FredC1Ei";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "Fred", "Bar", "Fred");

		DemangledFunction method = (DemangledFunction) object;
		assertEquals("undefined Bar::Fred::Fred(int)", method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("int", parameters.get(0).getSignature());
	}

	@Test
	public void testDestructor() throws Exception {

		String mangled = "_ZN6Magick5ImageD1Ev";
		String demangled = process.demangle(mangled);
		assertEquals("Magick::Image::~Image()", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "~Image", "Magick", "Image");

		assertEquals("undefined Magick::Image::~Image(void)", object.getSignature(false));
	}

	@Test
	public void testThunk_Virtual() throws Exception {

		String mangled =
			"_ZTv0_n24_NSt19basic_ostringstreamIcSt11char_traitsIcE14pool_allocatorIcEED0Ev";
		String demangled = process.demangle(mangled);
		assertEquals(
			"virtual thunk to std::basic_ostringstream<char, std::char_traits<char>, pool_allocator<char> >::~basic_ostringstream()",
			demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledThunk.class);
		assertName(object, "~basic_ostringstream", "std",
			"basic_ostringstream<char,std::char_traits<char>,pool_allocator<char>>");

		assertEquals(
			"virtual thunk to undefined __thiscall std::basic_ostringstream<char,std::char_traits<char>,pool_allocator<char>>::~basic_ostringstream(void)",
			object.getSignature(false));
	}

	@Test
	public void testThunk_NonVirtual() throws Exception {

		String mangled = "_ZThn8_N14nsPrintSession6AddRefEv";
		String demangled = process.demangle(mangled);
		assertEquals("non-virtual thunk to nsPrintSession::AddRef()", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledThunk.class);
		assertName(object, "AddRef", "nsPrintSession");

		assertEquals("non-virtual thunk to undefined __thiscall nsPrintSession::AddRef(void)",
			object.getSignature(false));
	}

	@Test
	public void testParse_Thunk_NonVirtual_WithExtraInfo() throws Exception {

		String mangled = "_ZThn8_N14nsPrintSession14QueryInterfaceERK4nsIDPPv";

		// this is an older format
		String demangled =
			"non-virtual thunk [nv:-8] to nsPrintSession::QueryInterface(nsID const&, void**)";
		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledThunk.class);
		assertName(object, "QueryInterface", "nsPrintSession");

		// for now we preserve the extra stuff between 'thunk' and 'to' in the signature
		assertEquals(
			"non-virtual thunk [nv:-8] to undefined __thiscall nsPrintSession::QueryInterface(nsID const &,void * *)",
			object.getSignature(false));
	}

	@Test
	public void testThunk_CovariantReturn() throws Exception {

		String mangled = "_ZTch0_h16_NK8KHotKeys13WindowTrigger4copyEPNS_10ActionDataE";
		String demangled = process.demangle(mangled);
		assertEquals(
			"covariant return thunk to KHotKeys::WindowTrigger::copy(KHotKeys::ActionData*) const",
			demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledThunk.class);
		assertName(object, "copy", "KHotKeys", "WindowTrigger");

		assertEquals(
			"covariant return thunk to undefined __thiscall KHotKeys::WindowTrigger::copy(KHotKeys::ActionData *)",
			object.getSignature(false));
	}

	@Test
	public void testParse_Thunk_testThunk_CovariantReturn_WithExtraInfo() throws Exception {

		String mangled = "_ZTch0_h16_NK8KHotKeys13WindowTrigger4copyEPNS_10ActionDataE";

		// this is an older format
		String demangled =
			"covariant return thunk [nv:0] [nv:16] to KHotKeys::WindowTrigger::copy(KHotKeys::ActionData*) const";
		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledThunk.class);
		assertName(object, "copy", "KHotKeys", "WindowTrigger");

		// for now we preserve the extra stuff between 'thunk' and 'to' in the signature
		assertEquals(
			"covariant return thunk [nv:0] [nv:16] to undefined __thiscall KHotKeys::WindowTrigger::copy(KHotKeys::ActionData *)",
			object.getSignature(false));
	}

	@Test
	public void testParse_DefaultArg() throws Exception {

		//
		// The demangled string contains this string: {default arg#1}
		//
		String mangled =
			"_ZZN12PackManifest18CapabilityRegistry18registerCapabilityEN3gsl17basic_string_spanIKcLln1EEEbSt8functionIFbRS_R10PackReportbEEEd_NKUlS6_S8_bE_clES6_S8_b";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"PackManifest::CapabilityRegistry::registerCapability(gsl::basic_string_span<char_const,-1l>,bool,std::function<bool(PackManifest&,PackReport&,bool)>)::{default arg#1}::{lambda(PackManifest&,PackReport&,bool)#1}::operator()(PackManifest &,PackReport &,bool)",
			signature);
	}

	@Test
	public void testParse_UnnamedType() throws Exception {

		//
		// The demangled string contains this string: {unnamed_type#1}
		//
		String mangled =
			"_ZN14GoalDefinitionUt_aSERKS0_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"undefined GoalDefinition::{unnamed_type#1}::operator=({unnamed const &)",
			signature);
	}

	@Test
	public void testParse_DecltypeAuto() throws Exception {

		String mangled =
			"_Z9enum_castIN17FurnaceBlockActorUt_EEDcT_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("decltype (auto)", signature);
	}

	@Test
	public void testMethod() throws Exception {
		String mangled = "_ZN3Foo7getBoolEf";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "getBool", "Foo");

		DemangledFunction function = (DemangledFunction) object;
		assertEquals("undefined Foo::getBool(float)", function.getSignature(false));

		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("float", parameters.get(0).getSignature());
	}

	@Test
	public void testFunctions() throws Exception {
		String mangled = "_Z7toFloatidcls";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "toFloat");

		assertEquals("undefined toFloat(int,double,char,long,short)", object.getSignature(false));

		DemangledFunction function = (DemangledFunction) object;

		List<DemangledDataType> parameters = function.getParameters();
		assertEquals(5, parameters.size());
		assertEquals("int", parameters.get(0).getSignature());
		assertEquals("double", parameters.get(1).getSignature());
		assertEquals("char", parameters.get(2).getSignature());
		assertEquals("long", parameters.get(3).getSignature());
		assertEquals("short", parameters.get(4).getSignature());
	}

	@Test
	public void testVariables() throws Exception {
		String mangled = "_ZN6Magick18magickCleanUpGuardE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledVariable.class);
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
		assertType(object, DemangledAddressTable.class);
		assertName(object, "vtable", "Magick", "DrawableTextAntialias");

		assertEquals("Magick::DrawableTextAntialias::vtable", object.getSignature(false));
	}

	@Test
	public void testReferenceTemporaryFor() throws Exception {

		String mangled = "_ZGRZNK17KSimpleFileFilter12passesFilterEPK9KFileItemE6dotdot";
		String demangled = process.demangle(mangled);
		assertEquals(
			"reference temporary #0 for KSimpleFileFilter::passesFilter(KFileItem const*) const::dotdot",
			demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledVariable.class);
		assertName(object, "dotdot", "KSimpleFileFilter", "passesFilter(KFileItem_const*)");

		assertEquals("KSimpleFileFilter::passesFilter(KFileItem_const*)::dotdot",
			object.getSignature(false));
	}

	@Test
	public void testTypeInfo_AddressTable() throws Exception {

		String mangled = "_ZTIN10NonDiamond1AE";
		String demangled = process.demangle(mangled);
		assertEquals("typeinfo for NonDiamond::A", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "typeinfo", "NonDiamond", "A");

		assertEquals("NonDiamond::A::typeinfo", object.getSignature(false));

		DemangledAddressTable addressTable = (DemangledAddressTable) object;
		assertEquals("typeinfo", addressTable.getName());
		assertEquals("NonDiamond::A::typeinfo", addressTable.getNamespaceString());
		assertEquals("A", addressTable.getNamespace().getNamespaceName());
		assertEquals("NonDiamond::A", addressTable.getNamespace().getNamespaceString());
	}

	@Test
	public void testTypeInfo_AddressTable_WithTrailingNumbers() throws Exception {

		String mangled = "_ZTI31class_with_trailing_numbers1234";
		String demangled = process.demangle(mangled);
		assertEquals("typeinfo for class_with_trailing_numbers1234", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "typeinfo", "class_with_trailing_numbers1234");

		assertEquals("class_with_trailing_numbers1234::typeinfo", object.getSignature(false));
	}

	@Test
	public void testTypeInfo() throws Exception {
		String mangled = "_ZTIN4Arts28FileInputStream_impl_FactoryE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "typeinfo", "Arts", "FileInputStream_impl_Factory");

		assertEquals("Arts::FileInputStream_impl_Factory::typeinfo", object.getSignature(false));
	}

	@Test
	public void testTypeInfo_For() throws Exception {
		String mangled = "_ZTISt14unary_functionIPN9MagickLib12_DrawContextEvE";
		String demangled = process.demangle(mangled);
		assertEquals("typeinfo for std::unary_function<MagickLib::_DrawContext*, void>", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "typeinfo", "std", "unary_function<MagickLib::_DrawContext*,void>");

		assertEquals("std::unary_function<MagickLib::_DrawContext*,void>::typeinfo",
			object.getSignature(false));
	}

	@Test
	public void testTypeInfo_NameFor() throws Exception {
		String mangled = "_ZTSSt14unary_functionIPN9MagickLib12_DrawContextEvE";
		String demangled = process.demangle(mangled);
		assertEquals("typeinfo name for std::unary_function<MagickLib::_DrawContext*, void>",
			demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledString.class);
		assertName(object, "typeinfo-name", "std", "unary_function<MagickLib::_DrawContext*,void>");

		assertEquals("typeinfo name for std::unary_function<MagickLib::_DrawContext*, void>",
			object.getSignature(false));
	}

	@Test
	public void testVtable_ConstructionVtableFor() throws Exception {

		String mangled = "_ZTCN4Arts17StdoutWriter_implE68_NS_11Object_skelE";
		String demangled = process.demangle(mangled);
		assertEquals("construction vtable for Arts::Object_skel-in-Arts::StdoutWriter_impl",
			demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "construction-vtable", "Arts", "Object_skel-in-Arts",
			"StdoutWriter_impl");

		assertEquals("Arts::Object_skel-in-Arts::StdoutWriter_impl::construction-vtable",
			object.getSignature(false));
	}

	@Test
	public void testGuardVariable_WithGuardVariableText() throws Exception {

		String mangled = "_ZGVZN10KDirLister11emitChangesEvE3dot";
		String demangled = process.demangle(mangled);
		assertEquals("guard variable for KDirLister::emitChanges()::dot", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledVariable.class);
		assertName(object, "dot", "KDirLister", "emitChanges()");

		assertEquals("KDirLister::emitChanges()::dot", object.getSignature(false));

		DemangledVariable variable = (DemangledVariable) object;
		assertEquals("dot", variable.getName());
		assertEquals("KDirLister::emitChanges()::dot", variable.getNamespaceString());
		assertEquals("emitChanges()", variable.getNamespace().getNamespaceName());
		assertEquals("KDirLister::emitChanges()", variable.getNamespace().getNamespaceString());
		assertNull(variable.getDataType()); // no type information provided
	}

	@Test
	public void testGuardVariable_ThreadPointer() throws Exception {

		String mangled = "_ZZ18__gthread_active_pvE20__gthread_active_ptr";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledVariable.class);
		assertName(object, "__gthread_active_ptr", "__gthread_active_p()");

		assertEquals("__gthread_active_p()::__gthread_active_ptr", object.getSignature(false));

		DemangledVariable variable = (DemangledVariable) object;
		assertEquals("__gthread_active_ptr", variable.getName());
		assertEquals("__gthread_active_p()", variable.getNamespace().getNamespaceName());
		assertNull(variable.getDataType()); // no type information provided
	}

	@Test
	public void testConstFunction() throws Exception {
		//
		// The below demangles to LScrollerView::CalcPortExposedRect( const(Rect &, bool))
		// note the const() syntax
		//
		String mangled = "CalcPortExposedRect__13LScrollerViewCFR4Rectb";

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "__dt", "MsoDAL", "VertFrame");

		assertEquals("undefined MsoDAL::VertFrame::__dt(void)", object.getSignature(false));
	}

	@Test
	public void testStaticLocalVariable() throws Exception {
		//
		// The below demangles to DDDSaveOptionsCB(_WidgetRec*, void*, void*)::dialog [#1]
		//
		String mangled = "_ZZ16DDDSaveOptionsCBP10_WidgetRecPvS1_E6dialog_0";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledVariable.class);
		assertName(object, "dialog", "DDDSaveOptionsCB(_WidgetRec*,void*,void*)");

		assertEquals("DDDSaveOptionsCB(_WidgetRec*,void*,void*)::dialog",
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

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
		assertName(object, "graphNew", "Layout");

		assertEquals("undefined Layout::graphNew(_GRAPH * *[],char *)", object.getSignature(false));
	}

	@Test
	public void testPointerToArrayWithSpace() throws Exception {
		//
		// A fabricated example test space between the pointer and the array syntax
		//

		String mangled = "fake";
		String demangled = "Layout::graphNew(short (*) [41], char*)";

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "_gmStage2");

		assertEquals("undefined _gmStage2(SECTION_INFO *,int *,int *[],int,short const *)",
			object.getSignature(false));

		DemangledFunction method = (DemangledFunction) object;

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(5, parameters.size());
		assertEquals("SECTION_INFO *", parameters.get(0).getSignature());
		assertEquals("int *", parameters.get(1).getSignature());
		assertEquals("int *[]", parameters.get(2).getSignature());
		assertEquals("int", parameters.get(3).getSignature());
		assertEquals("short const *", parameters.get(4).getSignature());
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

		// use an older demangler; the current demangler cannot handle this string
		process = GnuDemanglerNativeProcess
				.getDemanglerNativeProcess(GnuDemanglerOptions.GNU_DEMANGLER_V2_24);

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledVariable.class);
		assertName(object, "aaa<(bbb::ccc)120,ddd>");

		assertEquals("aaa<(bbb::ccc)120,ddd>", object.getSignature(false));

		//
		// Functions
		//

		// template with cast
		mangled = "_ZN10mysequenceIiLi5EE9setmemberEii";

		demangled = process.demangle(mangled);

		object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "setmember", "mysequence<int,5>");

		assertEquals("undefined mysequence<int,5>::setmember(int,int)", object.getSignature(false));

		//
		// Class
		//

		// constructor with template (this was broken once during changes--here now for regression)
		mangled = "_ZN6Magick5ImageC1ERKSs";

		demangled = process.demangle(mangled);

		object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
		assertName(object, "operator<", "Magick");

		DemangledFunction method = (DemangledFunction) object;
		assertEquals(
			"undefined Magick::operator<(Magick::Coordinate const &,Magick::Coordinate const &)",
			method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(2, parameters.size());
		assertEquals("Magick::Coordinate const &", parameters.get(0).getSignature());
		assertEquals("Magick::Coordinate const &", parameters.get(1).getSignature());
	}

	@Test
	public void testOperatorAsNamespace() throws Exception {

		//
		// Mangled: __ZN3WTF15__visitor_tableINS_7VisitorIZZN7WebCore12SubtleCrypto11generateKeyERN3JSC9ExecStateEONS_7VariantIJNS4_6StrongINS4_8JSObjectEEENS_6StringEEEEbONS_6VectorINS2_14CryptoKeyUsageELm0ENS_15CrashOnOverflowELm16ENS_10FastMallocEEEONS_3RefINS2_15DeferredPromiseENS_13DumbPtrTraitsISL_EEEEEN4$_10clEONS7_IJNS_6RefPtrINS2_9CryptoKeyENSM_ISS_EEEENS2_13CryptoKeyPairEEEEEUlRSU_E_JZZNS3_11generateKeyES6_SD_bSJ_SP_ENSQ_clESX_EUlRSV_E_EEEJSU_SV_EE12__trampolineE
		//
		// Demangled: WTF::__visitor_table<WTF::Visitor<WebCore::SubtleCrypto::generateKey(JSC::ExecState&, WTF::Variant<JSC::Strong<JSC::JSObject>, WTF::String>&&, bool, WTF::Vector<WebCore::CryptoKeyUsage, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc>&&, WTF::Ref<WebCore::DeferredPromise, WTF::DumbPtrTraits<WebCore::DeferredPromise> >&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>&&)::{lambda(WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >&)#1}, WebCore::SubtleCrypto::generateKey(JSC::ExecState&, WTF::Variant<JSC::Strong<JSC::JSObject>, WTF::String>&&, bool, WTF::Vector<WebCore::CryptoKeyUsage, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc>&&, WTF::Ref<WebCore::DeferredPromise, WTF::DumbPtrTraits<WebCore::DeferredPromise> >&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>&&)::{lambda(WebCore::CryptoKeyPair&)#1}>, WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>::__trampoline
		//

		DemangledObject object = parser.parse(
			"__ZN3WTF15__visitor_tableINS_7VisitorIZZN7WebCore12SubtleCrypto11generateKeyERN3JSC9ExecStateEONS_7VariantIJNS4_6StrongINS4_8JSObjectEEENS_6StringEEEEbONS_6VectorINS2_14CryptoKeyUsageELm0ENS_15CrashOnOverflowELm16ENS_10FastMallocEEEONS_3RefINS2_15DeferredPromiseENS_13DumbPtrTraitsISL_EEEEEN4$_10clEONS7_IJNS_6RefPtrINS2_9CryptoKeyENSM_ISS_EEEENS2_13CryptoKeyPairEEEEEUlRSU_E_JZZNS3_11generateKeyES6_SD_bSJ_SP_ENSQ_clESX_EUlRSV_E_EEEJSU_SV_EE12__trampolineE",
			"WTF::__visitor_table<WTF::Visitor<WebCore::SubtleCrypto::generateKey(JSC::ExecState&, WTF::Variant<JSC::Strong<JSC::JSObject>, WTF::String>&&, bool, WTF::Vector<WebCore::CryptoKeyUsage, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc>&&, WTF::Ref<WebCore::DeferredPromise, WTF::DumbPtrTraits<WebCore::DeferredPromise> >&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>&&)::{lambda(WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >&)#1}, WebCore::SubtleCrypto::generateKey(JSC::ExecState&, WTF::Variant<JSC::Strong<JSC::JSObject>, WTF::String>&&, bool, WTF::Vector<WebCore::CryptoKeyUsage, 0ul, WTF::CrashOnOverflow, 16ul, WTF::FastMalloc>&&, WTF::Ref<WebCore::DeferredPromise, WTF::DumbPtrTraits<WebCore::DeferredPromise> >&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>&&)::{lambda(WebCore::CryptoKeyPair&)#1}>, WTF::RefPtr<WebCore::CryptoKey, WTF::DumbPtrTraits<WebCore::CryptoKey> >, WebCore::CryptoKeyPair>::__trampoline");

		assertNotNull(object);
		assertType(object, DemangledVariable.class);

		String name = "__trampoline";
		assertName(object, name, "WTF",
			"__visitor_table<WTF::Visitor<WebCore::SubtleCrypto::generateKey(JSC::ExecState&,WTF::Variant<JSC::Strong<JSC::JSObject>,WTF::String>&&,bool,WTF::Vector<WebCore::CryptoKeyUsage,0ul,WTF::CrashOnOverflow,16ul,WTF::FastMalloc>&&,WTF::Ref<WebCore::DeferredPromise,WTF::DumbPtrTraits<WebCore::DeferredPromise>>&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>&&)::{lambda(WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>&)#1},WebCore::SubtleCrypto::generateKey(JSC::ExecState&,WTF::Variant<JSC::Strong<JSC::JSObject>,WTF::String>&&,bool,WTF::Vector<WebCore::CryptoKeyUsage,0ul,WTF::CrashOnOverflow,16ul,WTF::FastMalloc>&&,WTF::Ref<WebCore::DeferredPromise,WTF::DumbPtrTraits<WebCore::DeferredPromise>>&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>&&)::{lambda(WebCore::CryptoKeyPair&)#1}>,WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>");

		String signature = object.getSignature(false);
		assertEquals(
			"WTF::__visitor_table<WTF::Visitor<WebCore::SubtleCrypto::generateKey(JSC::ExecState&,WTF::Variant<JSC::Strong<JSC::JSObject>,WTF::String>&&,bool,WTF::Vector<WebCore::CryptoKeyUsage,0ul,WTF::CrashOnOverflow,16ul,WTF::FastMalloc>&&,WTF::Ref<WebCore::DeferredPromise,WTF::DumbPtrTraits<WebCore::DeferredPromise>>&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>&&)::{lambda(WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>&)#1},WebCore::SubtleCrypto::generateKey(JSC::ExecState&,WTF::Variant<JSC::Strong<JSC::JSObject>,WTF::String>&&,bool,WTF::Vector<WebCore::CryptoKeyUsage,0ul,WTF::CrashOnOverflow,16ul,WTF::FastMalloc>&&,WTF::Ref<WebCore::DeferredPromise,WTF::DumbPtrTraits<WebCore::DeferredPromise>>&&)::$_10::operator()(WTF::Variant<WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>&&)::{lambda(WebCore::CryptoKeyPair&)#1}>,WTF::RefPtr<WebCore::CryptoKey,WTF::DumbPtrTraits<WebCore::CryptoKey>>,WebCore::CryptoKeyPair>::__trampoline",
			signature);
	}

	@Test
	public void testOverloadedShiftOperatorTemplated_RightShift() {
		parser = new GnuDemanglerParser();
		DemangledObject object = parser.parse("fakemangled",
			"std::basic_istream<char, std::char_traits<char> >& " +
				"std::operator>><char, std::char_traits<char> >" +
				"(std::basic_istream<char, std::char_traits<char> >&, char&)");
		String name = object.getName();
		assertEquals("operator>>", name);
		assertEquals(
			"std::basic_istream<char,std::char_traits<char>> & " +
				"std::operator>><char,std::char_traits<char>>" +
				"(std::basic_istream<char,std::char_traits<char>> &,char &)",
			object.getSignature());
	}

	@Test
	public void testOverloadedShiftOperatorTemplated_LeftShift() {

		String raw = "std::basic_ostream<char, std::char_traits<char> >& " +
			"std::operator<< <std::char_traits<char> >" +
			"(std::basic_ostream<char, std::char_traits<char> >&, char const*)";
		String formatted = "std::basic_ostream<char,std::char_traits<char>> & " +
			"std::operator<<<std::char_traits<char>>" +
			"(std::basic_ostream<char,std::char_traits<char>> &,char const *)";
		DemangledObject object =
			parser.parse("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", raw);
		String name = object.getName();
		assertEquals("operator<<", name);
		assertEquals(formatted, object.getSignature());
	}

	@Test
	public void testOverloadedLeftShiftOperatorWithFunctionPointer() {

		String mangled = "_ZNSolsEPFRSoS_E";
		parser = new GnuDemanglerParser();
		DemangledObject object = parser.parse(mangled,
			"std::basic_ostream<char, std::char_traits<char> >" +
				"::operator<<(std::basic_ostream<char, std::char_traits<char> >&" +
				"(*)(std::basic_ostream<char, std::char_traits<char> >&))");
		String name = object.getName();
		assertEquals("operator<<", name);
		assertName(object, "operator<<", "std", "basic_ostream<char,std::char_traits<char>>");
		assertEquals("undefined std::basic_ostream<char,std::char_traits<char>>" + "::operator<<(" +
			"std::basic_ostream<char,std::char_traits<char>> & (*)(std::basic_ostream<char,std::char_traits<char>> &))",
			object.getSignature());
	}

	@Test
	public void testTypeInfo_For_FunctionThatContainsOperatorText() throws Exception {

		String mangled =
			"_ZTINSt6__ndk110__function6__funcIZZN5dummy2it5other9Namespace8functionEfENK3$" +
				"_2clEPNS4_9NamespaceEEUlS8_E_NS_9allocatorIS9_EEFiS8_EEE";
		String demangled = process.demangle(mangled);

		/*
		 	typeinfo for
		 		std::__ndk1::__function::__func<
		 			dummy::it::other::Namespace::function(float)::$_2::operator()(dummy::it::other::Namespace*) const::{lambda(dummy::it::other::Namespace*)#1},
		 			std::__ndk1::allocator<{lambda(dummy::it::other::Namespace*)#1}>,
		 			int (dummy::it::other::Namespace*)
		 		>
		
		 	'__func' has 3 template parameters, the operator and the allocator
		
		 */

		String dummyNs = "dummy::it::other::Namespace";
		String dummyNsP = dummyNs + "*";
		String lambda = "{lambda(" + dummyNsP + ")#1}";

		String lambdaOperator =
			dummyNs + "::function(float)::$_2::operator()(" + dummyNsP + ")const::" + lambda;
		String lambdaAllocator = "std::__ndk1::allocator<" + lambda + ">";
		String thirdParam = "int(" + dummyNsP + ")";

		String infoNs = "std::__ndk1::__function::";
		String name = "__func<" + lambdaOperator + "," + lambdaAllocator + "," + thirdParam + ">";
		assertTrue(demangled.startsWith("typeinfo for " + infoNs));
		assertTrue(demangled.replaceAll("\\s", "").endsWith(name));

		DemangledObject object = parser.parse(mangled, demangled);

		assertType(object, DemangledAddressTable.class);
		assertName(object, "typeinfo", "std", "__ndk1", "__function", name);

		assertEquals(infoNs + name + "::typeinfo", object.getSignature(false));
	}

	@Test
	public void testOperator_Functor() throws Exception {

		String mangled = "_ZNK6Magick9pageImageclERNS_5ImageE";
		String demangled = process.demangle(mangled);
		assertEquals("Magick::pageImage::operator()(Magick::Image&) const", demangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "operator()", "Magick", "pageImage");

		DemangledFunction method = (DemangledFunction) object;
		assertEquals("undefined Magick::pageImage::operator()(Magick::Image &)",
			method.getSignature(false));

		List<DemangledDataType> parameters = method.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("Magick::Image &", parameters.get(0).getSignature());
	}

	@Test
	public void testPointerToArray_WithLambda() throws Exception {

		String mangled =
			"_ZNSt14__array_traitsIN12LayerDetails15RandomProviderTIZNKS0_9LayerBase10initRandomEllEUlRljE_EELm4EE6_S_refERA4_KS5_m";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"undefined std::__array_traits<LayerDetails::RandomProviderT<LayerDetails::LayerBase::initRandom(long,long)const::{lambda(long&,unsigned_int)#1}>,4ul>::_S_ref(LayerDetails::LayerBase::initRandom(long,long) const::{lambda(long&, unsigned int)#1} const &[],unsigned long)",
			signature);
	}

	@Test
	public void testOperator_WithTemplatesMissingATemplateArgument() throws Exception {

		/*
		
		 	Note: the empty template type: '<, std...' 
		 		<, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>>
		 		
		 		 
		 	std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > std::_Bind<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > (EduAppConfigs::*(EduAppConfigs const*))() const>::operator()<, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >()
		
		 */
		String mangled =
			"_ZNSt5_BindIFM13EduAppConfigsKFNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEvEPKS0_EEclIJES6_EET0_DpOT_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> std::_Bind<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>(EduAppConfigs::*(EduAppConfigs_const*))()const>::operator()<missing_argument,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>(void)",
			signature);
	}

	@Test
	public void testParamegterWithTemplateValue_DataTypeLiteral_int() throws Exception {

		String mangled = "_Z13reverse_rangeIjLin1EE5RangeIiXT0_EET_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("Range<int,int> reverse_range<unsigned_int,-1>(unsigned int)", signature);
	}

	@Test
	public void testParamegterWithTemplateValue_DataTypeLiteral_long() throws Exception {

		String mangled =
			"_ZN3gsl9to_stringIKcLln1EEENSt7__cxx1112basic_stringINSt12remove_constIT_E4typeESt11char_traitsIS7_ESaIS7_EEENS_17basic_string_spanIS5_XT0_EEE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"std::__cxx11::basic_string<std::remove_const<char_const>::type,std::char_traits<std::remove_const<char_const>::type>,std::allocator<std::remove_const<char_const>::type>> gsl::to_string<char_const,-1l>(gsl::basic_string_span<char const,long>)",
			signature);
	}

	@Test
	public void testLambdaWithLambdaParameters() throws Exception {

		/*
		 
		 lambda contents - lambdas in templates and as a parameter
		 
		 	bool (*** 
		 			const* std::
		 				__addressof<
		 						Bedrock::
		 						Threading::
		 						TLSDetail::
		 						DefaultConstructor<bool (**)(AssertHandlerContext const&), void>::
		 						create()::
		 						{lambda(bool (*** const)(AssertHandlerContext const&))#1}
		 						>
		 						(
		 							Bedrock::
		 							Threading::
		 							TLSDetail::
		 							DefaultConstructor<bool (**)(AssertHandlerContext const&), void>::
		 							create()::
		 							{lambda(bool (*** const&)(AssertHandlerContext const&))#1}
		 					    )
		 	     )(AssertHandlerContext const&)
		 
		 */

		String mangled =
			"_ZSt11__addressofIKZN7Bedrock9Threading9TLSDetail18DefaultConstructorIPPFbRK20AssertHandlerContextEvE6createEvEUlPS9_E_EPT_RSE_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"undefined Bedrock::Threading::TLSDetail::DefaultConstructor<bool(**)(AssertHandlerContext_const&),void>::create()::{lambda(bool(***const*std::__addressof<Bedrock::Threading::TLSDetail::DefaultConstructor<bool(**)(AssertHandlerContext_const&),void>::create()::{lambda(bool(***const)(AssertHandlerContext_const&))#1}>(Bedrock::Threading::TLSDetail::DefaultConstructor<bool(**)(AssertHandlerContext_const&),void>::create()::{lambda(bool(***const&)(AssertHandlerContext_const&))#1}))(AssertHandlerContext_const&))#1}",
			signature);
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
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("bool std::integral_constant::operator.cast.to.bool(void)", signature);
	}

	@Test
	public void testOperatorCastTo_FunctionPointer() throws Exception {

		String mangled =
			"_ZZNK4entt14basic_registryI8EntityIdE6assureI32FilteredTransformationAttributesI26PreHillsEdgeTransformationEEERKNS2_12pool_handlerIT_EEvENKUlRNS_10sparse_setIS1_EERS2_S1_E_cvPFvSE_SF_S1_EEv";
		String demangled = process.demangle(mangled);

		/*
		 	
		 	Full demangled:
		 	
			Operator Text
			
				entt::
				basic_registry<EntityId>::
				assure<FilteredTransformationAttributes<PreHillsEdgeTransformation> >() const::
				{lambda(entt::sparse_set<EntityId>&, entt::basic_registry<EntityId>&, EntityId)#1}::
				operator void (*)(entt::sparse_set<EntityId>&, entt::basic_registry<EntityId>&, EntityId)() const
		
			Operartor Without Namespace
		
		 		operator void (*)(entt::sparse_set<EntityId>&, entt::basic_registry<EntityId>&, EntityId)()
		 	
		 	Simplified Cast Operator Construct
		 	
		 		operator void (*)(A,B,C)()
					 	
		 */

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		//@formatter:off
		String expected = 
			"void (* " +
					"entt::" +
					"basic_registry::" +
					"assure() const::" +
					"{lambda(entt::sparse_set&,entt::basic_registry&,EntityId)#1}::" +
					"operator.cast.to.function.pointer(void)" +
				   ")(entt::sparse_set<EntityId> &,entt::basic_registry<EntityId> &,EntityId)";
		//@formatter:on
		String signature = object.getSignature(false);
		assertEquals(expected, signature);
	}

	@Test
	public void testConversionOperator() throws Exception {

		//
		// Converts the object upon which it is overridden to the given value.
		//
		// Format: operator std::string() const { return "bob"; }
		//
		//
		//
		//
		// Mangled: _ZNK6Magick5ColorcvSsEv
		//
		// Demangled: Magick::Color::operator std::basic_string<char, std::char_traits<char>, std::allocator<char> >() const
		//

		String mangled = "_ZNK6Magick5ColorcvSsEv";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
		assertName(object, "operator.new");

		assertEquals("void * operator.new(unsigned long)", object.getSignature(false));
	}

	@Test
	public void testFunctorOperator() throws Exception {
		String mangled = "_ZNK6Magick9viewImageclERNS_5ImageE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
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
		assertType(object, DemangledFunction.class);
		assertName(object, "decode_charset_iconv", "(anonymous_namespace)");

		assertEquals("undefined (anonymous_namespace)::decode_charset_iconv(char const *)",
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
		assertType(object, DemangledFunction.class);
		assertName(object, "mystrdup", "MeCab", "(anonymous_namespace)");

		assertEquals("undefined MeCab::(anonymous_namespace)::mystrdup(char const *)",
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
		assertType(object, DemangledFunction.class);

		assertName(object,
			"__uninitialized_copy_aux<MeCab::(anonymous_namespace)::Range*,MeCab::(anonymous_namespace)::Range*>",
			"std");

		assertEquals(
			"MeCab::(anonymous_namespace)::Range * std::__uninitialized_copy_aux<MeCab::(anonymous_namespace)::Range*,MeCab::(anonymous_namespace)::Range*>(MeCab::(anonymous_namespace)::Range *,MeCab::(anonymous_namespace)::Range *,MeCab::(anonymous_namespace)::Range *,std::__false_type)",
			object.getSignature(false));
	}

	@Test
	public void testAnonymousNamespaceInParameter_FirstNamespace() throws Exception {
		//
		// Mangled: __ZL7pperrorPN12_GLOBAL__N_17ContextEPKc
		//
		// Demangled: pperror((anonymous namespace)::Context*, char const*)
		//
		String mangled = "_ZL7pperrorPN12_GLOBAL__N_17ContextEPKc";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "pperror");

		assertEquals("undefined pperror((anonymous_namespace)::Context *,char const *)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatedParametersWithCast() throws Exception {
		//
		// Mangled: _ZN2Dr15ClipboardHelper17FTransferGvmlDataERN3Art11TransactionERKN3Ofc13TReferringPtrINS_10DrawingE2oEEEbNS4_7TCntPtrI11IDataObjectEERNS_18IClientDataCreatorERNS4_7TVectorINS4_8TWeakPtrINS_14DrawingElementEEELj0ELj4294967295EEERNS1_6Rect64E
		//
		// Demangled: Dr::ClipboardHelper::FTransferGvmlData(Art::Transaction&, Ofc::TReferringPtr<Dr::DrawingE2o> const&, bool, Ofc::TCntPtr<IDataObject>, Dr::IClientDataCreator&, Ofc::TVector<Ofc::TWeakPtr<Dr::DrawingElement>, 0u, 4294967295u>&, Art::Rect64&)
		//
		String mangled =
			"_ZN2Dr15ClipboardHelper17FTransferGvmlDataERN3Art11TransactionERKN3Ofc13TReferringPtrINS_10DrawingE2oEEEbNS4_7TCntPtrI11IDataObjectEERNS_18IClientDataCreatorERNS4_7TVectorINS4_8TWeakPtrINS_14DrawingElementEEELj0ELj4294967295EEERNS1_6Rect64E";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "FTransferGvmlData", "Dr", "ClipboardHelper");

		assertEquals(
			"undefined Dr::ClipboardHelper::FTransferGvmlData(Art::Transaction &,Ofc::TReferringPtr<Dr::DrawingE2o> const &,bool,Ofc::TCntPtr<IDataObject>,Dr::IClientDataCreator &,Ofc::TVector<Ofc::TWeakPtr<Dr::DrawingElement>,int,int> &,Art::Rect64 &)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatedParametersWithCast_OldStyleDemangle() throws Exception {
		//
		// This demangled string has appeared at some point in the past.  It no longer looks like
		// this (note the odd syntax of '<(int)2085>&)')
		//
		// Ofc::TSimpleTypeHelper<Art::Percentage>::ToString(Art::Percentage const&, Ofc::TFixedVarStr<(int)2085>&)
		//
		String demangled =
			"Ofc::TSimpleTypeHelper<Art::Percentage>::ToString(Art::Percentage const&, Ofc::TFixedVarStr<(int)2085>&)";
		DemangledObject object = parser.parse("nomangled", demangled);
		assertType(object, DemangledFunction.class);
		assertName(object, "ToString", "Ofc", "TSimpleTypeHelper<Art::Percentage>");

		assertEquals(
			"undefined Ofc::TSimpleTypeHelper<Art::Percentage>::ToString(Art::Percentage const &,Ofc::TFixedVarStr<(int)2085> &)",
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
		assertType(object, DemangledFunction.class);
		assertName(object, "perform", "Core", "AsyncFile");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		assertEquals("Name of type parsed", "F", parameters.get(0).getName());
		assertEquals("Param Type Name parsed", "WTF", parameters.get(0).getNamespace().toString());
		assertEquals("Param Template was parsed",
			"<WTF::F<void (Core::FileClient &)> (Core::File &)>",
			parameters.get(0).getTemplate().toString());

		assertEquals(
			"undefined Core::AsyncFile::perform(WTF::F<WTF::F<void (Core::FileClient &)> (Core::File &)> &&)",
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
		assertType(object, DemangledFunction.class);

		assertName(object, "registerKeysChangedCallback", "LogLevelMonitor");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		DemangledDataType demangParamDT = parameters.get(0);

		assertEquals("Name of type parsed", "function", demangParamDT.getName());
		assertEquals("Param Type Name parsed", "boost", demangParamDT.getNamespace().toString());
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
		assertType(object, DemangledFunction.class);
		assertName(object, "set_mutate_ares_options_callback", "DnsThread");

		DemangledFunction df = (DemangledFunction) object;

		List<DemangledDataType> parameters = df.getParameters();
		assertEquals("Number of parameters", 1, parameters.size());
		DemangledDataType demangParamDT = parameters.get(0);

		assertEquals("Name of type parsed", "function", demangParamDT.getName());
		assertEquals("Param Type Name parsed", "boost", demangParamDT.getNamespace().toString());
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
		assertType(object, DemangledFunction.class);
		assertName(object, "_M_insert_aux", "std",
			"vector<boost::function<void()>,std::allocator<boost::function<void()>>>");

		assertEquals(
			"undefined std::vector<boost::function<void()>,std::allocator<boost::function<void()>>>::_M_insert_aux(__gnu_cxx::__normal_iterator<boost::function<void ()> *,std::vector<boost::function<void ()>,std::allocator<boost::function<void ()>>>>,boost::function<void ()> const &)",
			object.getSignature(false));
	}

	@Test
	public void testTemplatesThatContainFunctionSignatures_Regression() throws Exception {

		//
		// Mangled: _ZN7WebCore27ContentFilterUnblockHandlerC2EN3WTF6StringENSt3__18functionIFvNS4_IFvbEEEEEE
		//
		// Demangled: WebCore::ContentFilterUnblockHandler::ContentFilterUnblockHandler(WTF::String, std::__1::function<void (std::__1::function<void (bool)>)>)
		//
		// Note: this parameter name caused an infinite loop
		//
		// 		function<void (std::__1::function<void (bool)>)>)
		//

		DemangledObject object = parser.parse(
			"_ZN7WebCore27ContentFilterUnblockHandlerC2EN3WTF6StringENSt3__18functionIFvNS4_IFvbEEEEEE",
			"WebCore::ContentFilterUnblockHandler::ContentFilterUnblockHandler(WTF::String, std::__1::function<void (std::__1::function<void (bool)>)>)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name = "ContentFilterUnblockHandler";
		assertName(object, name, "WebCore", "ContentFilterUnblockHandler");

		String signature = object.getSignature(false);
		assertEquals(
			"undefined WebCore::ContentFilterUnblockHandler::ContentFilterUnblockHandler(WTF::String,std::__1::function<void (std::__1::function<void (bool)>)>)",
			signature);
	}

	@Test
	public void testVtableParsingError_NoSpaceBeforeTrailingDigits() throws Exception {
		//
		// Mangled: _ZTCN6Crypto10HmacSha256E0_NS_3MacE
		//
		// Demangled: construction vtable for Crypto::Mac-in-Crypto::HmacSha256
		//

		String mangled = "_ZTCN6Crypto10HmacSha256E0_NS_3MacE";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertType(object, DemangledAddressTable.class);
		assertName(object, "construction-vtable", "Crypto", "Mac-in-Crypto", "HmacSha256");

		assertEquals("Crypto::Mac-in-Crypto::HmacSha256::construction-vtable",
			object.getSignature(false));
	}

	@Test
	public void testVarArgs() throws Exception {
		//
		// Mangled: _Z11testVarArgsiz
		//
		// Demangled: testVarArgs(int, ...)
		//

		String mangled = "_Z11testVarArgsiz";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

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
		assertType(object, DemangledFunction.class);

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
		DemangledObject demangled = demangler.demangle(mangled);
		assertNull(demangled);
	}

	@Test
	public void testStructureConstructorWithinTemplatedFunction() throws Exception {

		//
		// Mangled: _ZZN9__gnu_cxx6__stoaIlicJiEEET0_PFT_PKT1_PPS3_DpT2_EPKcS5_PmS9_EN11_Save_errnoC2Ev
		//
		// Demangled: __gnu_cxx
		//            ::
		//            __stoa<long, int, char, int>(long (*)(char const*, char**, int), char const*, char const*, unsigned long*, int)
		//            ::
		//            _Save_errno
		//            ::
		//            _Save_errno()
		//
		// This is _Save_errno struct's constructor inside of the stoa templated function, in the
		// __gnu_cxx namespace.
		//

		String mangled =
			"_ZZN9__gnu_cxx6__stoaIlicJiEEET0_PFT_PKT1_PPS3_DpT2_EPKcS5_PmS9_EN11_Save_errnoC2Ev";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("undefined __gnu_cxx" + "::" +
			"__stoa<long,int,char,int>(long(*)(char_const*,char**,int),char_const*,char_const*,unsigned_long*,int)" +
			"::" + "_Save_errno::_Save_errno(void)", signature);
	}

	@Test
	public void testOperator_NotEquals() throws Exception {

		//
		// Mangled: _ZNK2cc14ScrollSnapTypeneERKS0_
		//
		// Demangled: cc::ScrollSnapType::operator!=(cc::ScrollSnapType const&) const
		//

		String mangled = "_ZNK2cc14ScrollSnapTypeneERKS0_";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("undefined cc::ScrollSnapType::operator!=(cc::ScrollSnapType const &)",
			signature);
	}

	@Test
	public void testNamespaceElementWithMultipleFunctionParentheses() throws Exception {

		// __ZN7brigand13for_each_argsIZN7WebCore11JSConverterINS1_8IDLUnionIJNS1_7IDLNullENS1_12IDLDOMStringENS1_21IDLUnrestrictedDoubleEEEEE7convertERN3JSC9ExecStateERNS1_17JSDOMGlobalObjectERKN3WTF7VariantIJDnNSE_6StringEdEEEEUlOT_E_JNS_5type_INSt3__117integral_constantIlLl0EEEEENSN_INSP_IlLl1EEEEENSN_INSP_IlLl2EEEEEEEESK_SK_DpOT0_

		DemangledObject object = parser.parse(
			"__ZN7brigand13for_each_argsIZN7WebCore11JSConverterINS1_8IDLUnionIJNS1_7IDLNullENS1_12IDLDOMStringENS1_21IDLUnrestrictedDoubleEEEEE7convertERN3JSC9ExecStateERNS1_17JSDOMGlobalObjectERKN3WTF7VariantIJDnNSE_6StringEdEEEEUlOT_E_JNS_5type_INSt3__117integral_constantIlLl0EEEEENSN_INSP_IlLl1EEEEENSN_INSP_IlLl2EEEEEEEESK_SK_DpOT0_",
			"WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1} brigand::for_each_args<WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}, brigand::type_<std::__1::integral_constant<long, 0l> >, WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}<std::__1<long, 1l> >, WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}<std::__1<long, 2l> > >(WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}, brigand::type_<std::__1::integral_constant<long, 0l> >&&, WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}<std::__1<long, 1l> >&&, WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull, WebCore::IDLDOMString, WebCore::IDLUnrestrictedDouble> >::convert(JSC::ExecState&, WebCore::JSDOMGlobalObject&, WTF::Variant<decltype(nullptr), WTF::String, double> const&)::{lambda(auto:1&&)#1}<std::__1<long, 2l> >&&)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name =
			"for_each_args<WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1},brigand::type_<std::__1::integral_constant<long,0l>>,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,1l>>,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,2l>>>";
		assertName(object, name, "brigand");

		String signature = object.getSignature(false);
		assertEquals(
			"WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1} brigand::for_each_args<WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1},brigand::type_<std::__1::integral_constant<long,0l>>,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,1l>>,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,2l>>>(WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1},brigand::type_<std::__1::integral_constant<long,long>> &&,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,long>> &&,WebCore::JSConverter<WebCore::IDLUnion<WebCore::IDLNull,WebCore::IDLDOMString,WebCore::IDLUnrestrictedDouble>>::convert(JSC::ExecState&,WebCore::JSDOMGlobalObject&,WTF::Variant<decltype(nullptr),WTF::String,double>const&)::{lambda(auto:1&&)#1}<std::__1<long,long>> &&)",
			signature);
	}

	@Test
	public void testFunctionParameterWithMemberPointer() throws Exception {

		//
		// Mangled: __ZN7WebCore22FontSelectionAlgorithm16filterCapabilityEPbMS0_KFNS0_14DistanceResultENS_25FontSelectionCapabilitiesEEMS3_NS_18FontSelectionRangeE
		//
		// Demangled: WebCore::FontSelectionAlgorithm::filterCapability(bool*, WebCore::FontSelectionAlgorithm::DistanceResult (WebCore::FontSelectionAlgorithm::*)(WebCore::FontSelectionCapabilities) const, WebCore::FontSelectionRange WebCore::FontSelectionCapabilities::*)
		//
		//
		// WebCore::FontSelectionAlgorithm::filterCapability
		// (
		//		bool*,
		//		WebCore::FontSelectionAlgorithm::DistanceResult (WebCore::FontSelectionAlgorithm::*)(WebCore::FontSelectionCapabilities) const,
		//		WebCore::FontSelectionRange WebCore::FontSelectionCapabilities::*
		// )
		//
		// This demangled string introduces a new construct:
		//
		//		FontSelectionRange FontSelectionCapabilities::*
		//
		// where the type is 'FontSelectionRange' which is a member of 'FontSelectionCapabilities'
		//
		DemangledObject object = parser.parse(
			"__ZN7WebCore22FontSelectionAlgorithm16filterCapabilityEPbMS0_KFNS0_14DistanceResultENS_25FontSelectionCapabilitiesEEMS3_NS_18FontSelectionRangeE",
			"WebCore::FontSelectionAlgorithm::filterCapability(bool*, WebCore::FontSelectionAlgorithm::DistanceResult (WebCore::FontSelectionAlgorithm::*)(WebCore::FontSelectionCapabilities) const, WebCore::FontSelectionRange WebCore::FontSelectionCapabilities::*)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name = "filterCapability";
		assertName(object, name, "WebCore", "FontSelectionAlgorithm");

		String signature = object.getSignature(false);
		assertEquals(
			"undefined WebCore::FontSelectionAlgorithm::filterCapability(bool *,WebCore::FontSelectionAlgorithm::DistanceResult (*)(WebCore::FontSelectionCapabilities) const,WebCore::FontSelectionCapabilities::FontSelectionRange *)",
			signature);
	}

	@Test
	public void testFunctionParameterWithMemberPointer_ToFloat() throws Exception {

		//
		// Test to ensure proper handling of 'float AvoidBlockGoal::Definition::* const&'
		// which is a const reference to a floating point member of the class 
		// AvoidBlockGoal::Definition
		// 

		/*
		 
		 	Demangled:
		 
		  auto && JsonUtil::
			addMember<std::shared_ptr<JsonUtil::JsonSchemaObjectNode<JsonUtil::EmptyClass,AvoidBlockGoal::Definition>>,AvoidBlockGoal::Definition,float>			
			(
			
				std::shared_ptr<JsonUtil::JsonSchemaObjectNode<JsonUtil::EmptyClass,AvoidBlockGoal::Definition>>,
			    float AvoidBlockGoal::Definition::*,
			    char const *,
			    float AvoidBlockGoal::Definition::* const&
			
			)
		
		 */
		String mangled =
			"_ZN8JsonUtil9addMemberISt10shared_ptrINS_20JsonSchemaObjectNodeINS_10EmptyClassEN14AvoidBlockGoal10DefinitionEEEES5_fEEODaT_MT0_T1_PKcRKSC_";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"auto && JsonUtil::addMember<std::shared_ptr<JsonUtil::JsonSchemaObjectNode<JsonUtil::EmptyClass,AvoidBlockGoal::Definition>>,AvoidBlockGoal::Definition,float>(std::shared_ptr<JsonUtil::JsonSchemaObjectNode<JsonUtil::EmptyClass,AvoidBlockGoal::Definition>>,AvoidBlockGoal::Definition::float *,char const *,AvoidBlockGoal::Definition::float *)",
			signature);
	}

	@Test
	public void testFunctionParameterWithMultipleParentheses() throws Exception {

		//
		// Mangled: __ZN7WebCore12TextCodecICU14registerCodecsEPFvPKcON3WTF8FunctionIFNSt3__110unique_ptrINS_9TextCodecENS5_14default_deleteIS7_EEEEvEEEE
		//
		// Demangled: undefined WebCore::TextCodecICU::registerCodecs(void ()(char const *,WTF::Function<std::__1::unique_ptr<WebCore::TextCodec,std::__1::default_delete<WebCore::TextCodec>> ()> &&))
		//
		// The regression tested here revolves around this parameter:
		//
		// 		void ()(char const *,WTF::Function<std::__1::unique_ptr<WebCore::TextCodec,std::__1::default_delete<WebCore::TextCodec>> ()> &&
		//
		// (note the trailing '()' chars)
		//

		DemangledObject object = parser.parse(
			"__ZN7WebCore12TextCodecICU14registerCodecsEPFvPKcON3WTF8FunctionIFNSt3__110unique_ptrINS_9TextCodecENS5_14default_deleteIS7_EEEEvEEEE",
			"undefined WebCore::TextCodecICU::registerCodecs(void ()(char const *,WTF::Function<std::__1::unique_ptr<WebCore::TextCodec,std::__1::default_delete<WebCore::TextCodec>> ()> &&))");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name = "registerCodecs";
		assertName(object, name, "WebCore", "TextCodecICU");

		String signature = object.getSignature(false);
		assertEquals(
			"undefined WebCore::TextCodecICU::registerCodecs(void (*)(char const *,WTF::Function<std::__1::unique_ptr<WebCore::TextCodec,std::__1::default_delete<WebCore::TextCodec>> ()> &&))",
			signature);
	}

	@Test
	public void testFunctionWithVarargsRvalueParameter() throws Exception {

		// __ZN3WTF15__visit_helper2ILl1ELm1EJEE7__visitINS_7VisitorIZNKS_17TextBreakIterator9followingEjEUlRKT_E_JEEEJRKNS_7VariantIJNS_20TextBreakIteratorICUENS_19TextBreakIteratorCFEEEEEEENS_27__multi_visitor_return_typeIS5_JDpT0_EE6__typeERS5_DpOSH_
		//
		//
		// this demangled string introduces a new construct:
		//
		// 		(WTF::__multi_visitor_return_type&&)...
		//
		// where the above is a parameter to function, where the params look like:
		// (
		//	WTF::Visitor<WTF::TextBreakIterator::following(unsigned int) const::{lambda(auto:1 const&)#1}>&,
		//	(WTF::__multi_visitor_return_type&&)...
		// )
		//

		DemangledObject object = parser.parse(
			"__ZN3WTF15__visit_helper2ILl1ELm1EJEE7__visitINS_7VisitorIZNKS_17TextBreakIterator9followingEjEUlRKT_E_JEEEJRKNS_7VariantIJNS_20TextBreakIteratorICUENS_19TextBreakIteratorCFEEEEEEENS_27__multi_visitor_return_typeIS5_JDpT0_EE6__typeERS5_DpOSH_",
			"WTF::__multi_visitor_return_type<WTF::Visitor<WTF::TextBreakIterator::following(unsigned int) const::{lambda(auto:1 const&)#1}>, WTF::Variant<WTF::TextBreakIteratorICU, WTF::TextBreakIteratorCF> const&>::__type WTF::__visit_helper2<1l, 1ul>::__visit<WTF::Visitor<WTF::TextBreakIterator::following(unsigned int) const::{lambda(auto:1 const&)#1}>, WTF::Variant<WTF::TextBreakIteratorICU, WTF::TextBreakIteratorCF> const&>(WTF::Visitor<WTF::TextBreakIterator::following(unsigned int) const::{lambda(auto:1 const&)#1}>&, (WTF::__multi_visitor_return_type&&)...)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name =
			"__visit<WTF::Visitor<WTF::TextBreakIterator::following(unsigned_int)const::{lambda(auto:1_const&)#1}>,WTF::Variant<WTF::TextBreakIteratorICU,WTF::TextBreakIteratorCF>const&>";
		assertName(object, name, "WTF", "__visit_helper2<1l,1ul>");

		String signature = object.getSignature(false);
		assertEquals(
			"WTF::__multi_visitor_return_type<WTF::Visitor<WTF::TextBreakIterator::following(unsigned_int)const::{lambda(auto:1_const&)#1}>,WTF::Variant<WTF::TextBreakIteratorICU,WTF::TextBreakIteratorCF>const&>::__type WTF::__visit_helper2<1l,1ul>::__visit<WTF::Visitor<WTF::TextBreakIterator::following(unsigned_int)const::{lambda(auto:1_const&)#1}>,WTF::Variant<WTF::TextBreakIteratorICU,WTF::TextBreakIteratorCF>const&>(WTF::Visitor<WTF::TextBreakIterator::following(unsigned_int) const::{lambda(auto:1 const&)#1}> &,WTF::__multi_visitor_return_type &&)",
			signature);
	}

	@Test
	public void testOperator_Equals_ExcessivelyTemplated() throws Exception {

		DemangledObject object = parser.parse(
			"__ZN3WTF8FunctionIFvvEEaSIZN7WebCore9IDBClient24TransactionOperationImplIJRKNS4_18IDBObjectStoreInfoEEEC1ERNS4_14IDBTransactionEMSB_FvRKNS4_13IDBResultDataEEMSB_FvRNS5_20TransactionOperationES9_ES9_EUlvE_vEERS2_OT_",
			"WTF::Function<void ()>& WTF::Function<void ()>::operator=<WebCore::IDBClient::TransactionOperationImpl<WebCore::IDBObjectStoreInfo const&>::TransactionOperationImpl(WebCore::IDBTransaction&, void (WebCore::IDBTransaction::*)(WebCore::IDBResultData const&), void (WebCore::IDBTransaction::*)(WebCore::IDBClient::TransactionOperation&, WebCore::IDBObjectStoreInfo const&), WebCore::IDBObjectStoreInfo const&)::{lambda()#1}, void>(WebCore::IDBClient::TransactionOperationImpl<WebCore::IDBObjectStoreInfo const&>::TransactionOperationImpl(WebCore::IDBTransaction&, void (WebCore::IDBTransaction::*)(WebCore::IDBResultData const&), void (WebCore::IDBTransaction::*)(WebCore::IDBClient::TransactionOperation&, WebCore::IDBObjectStoreInfo const&), WebCore::IDBObjectStoreInfo const&)::{lambda()#1}&&)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name = "operator=";
		assertName(object, name, "WTF", "Function<void()>");

		String signature = object.getSignature(false);
		assertEquals(
			"WTF::Function<void ()> & WTF::Function<void()>::operator=<WebCore::IDBClient::TransactionOperationImpl<WebCore::IDBObjectStoreInfo_const&>::TransactionOperationImpl(WebCore::IDBTransaction&,void(WebCore::IDBTransaction::*)(WebCore::IDBResultData_const&),void(WebCore::IDBTransaction::*)(WebCore::IDBClient::TransactionOperation&,WebCore::IDBObjectStoreInfo_const&),WebCore::IDBObjectStoreInfo_const&)::{lambda()#1},void>(WebCore::IDBClient::TransactionOperationImpl<WebCore::IDBObjectStoreInfo_const&>::TransactionOperationImpl(WebCore::IDBTransaction&,void(WebCore::IDBTransaction::*)(WebCore::IDBResultData_const&),void(WebCore::IDBTransaction::*)(WebCore::IDBClient::TransactionOperation&,WebCore::IDBObjectStoreInfo_const&),WebCore::IDBObjectStoreInfo_const&)::{lambda()#1} &&)",
			signature);

	}

	@Test
	public void testOperator_ArrayReference() throws Exception {
		String mangled =
			"_ZN12LayerDetails15RandomProviderTIZNKS_9LayerBase10initRandomEllEUlRljE_EclIiLm2EEET_RAT0__KS6_";

		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals(
			"int LayerDetails::RandomProviderT<LayerDetails::LayerBase::initRandom(long,long)const::{lambda(long&,unsigned_int)#1}>::operator()<int,2ul>(LayerDetails::RandomProviderT<LayerDetails::LayerBase::initRandom(long,long)const::{lambda(long&,unsigned_int)#1}>::operator() const &[])",
			signature);
	}

	@Test
	public void testLambdaWithTemplates() throws Exception {

		// {lambda(auto:1&&)#1}<NS1::NS2>>&&
		DemangledObject object = parser.parse(
			"_ZN3WTF6VectorINS_9RetainPtrI29AVAssetResourceLoadingRequestEELm0ENS_15CrashOnOverflowELm16ENS_10FastMallocEE17removeAllMatchingIZNS6_9removeAllIPS2_EEjRKT_EUlRKS3_E_EEjSC_m",
			"WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString, WebCore::IDLInterface<WebCore::CanvasGradient>, WebCore::IDLInterface<WebCore::CanvasPattern> > >::convert(JSC::ExecState&, JSC::JSValue)::{lambda(auto:1&&)#1} brigand::for_each_args<WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString, WebCore::IDLInterface<WebCore::CanvasGradient>, WebCore::IDLInterface<WebCore::CanvasPattern> > >::convert(JSC::ExecState&, JSC::JSValue)::{lambda(auto:1&&)#1}, brigand::type_<WebCore::IDLInterface<WebCore::CanvasGradient> >, WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString, WebCore::IDLInterface<WebCore::CanvasGradient>, WebCore::IDLInterface<WebCore::CanvasPattern> > >::convert(JSC::ExecState&, JSC::JSValue)::{lambda(auto:1&&)#1}<WebCore::IDLInterface<WebCore::CanvasPattern> > >(WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString, WebCore::IDLInterface<WebCore::CanvasGradient>, WebCore::IDLInterface<WebCore::CanvasPattern> > >::convert(JSC::ExecState&, JSC::JSValue)::{lambda(auto:1&&)#1}, brigand::type_<WebCore::IDLInterface<WebCore::CanvasGradient> >&&, WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString, WebCore::IDLInterface<WebCore::CanvasGradient>, WebCore::IDLInterface<WebCore::CanvasPattern> > >::convert(JSC::ExecState&, JSC::JSValue)::{lambda(auto:1&&)#1}<WebCore::IDLInterface<WebCore::CanvasPattern> >&&)");

		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name =
			"for_each_args<WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1},brigand::type_<WebCore::IDLInterface<WebCore::CanvasGradient>>,WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1}<WebCore::IDLInterface<WebCore::CanvasPattern>>>";
		assertName(object, name, "brigand");

		String signature = object.getSignature(false);
		assertEquals(
			"WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1} brigand::for_each_args<WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1},brigand::type_<WebCore::IDLInterface<WebCore::CanvasGradient>>,WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1}<WebCore::IDLInterface<WebCore::CanvasPattern>>>(WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1},brigand::type_<WebCore::IDLInterface<WebCore::CanvasGradient>> &&,WebCore::Converter<WebCore::IDLUnion<WebCore::IDLDOMString,WebCore::IDLInterface<WebCore::CanvasGradient>,WebCore::IDLInterface<WebCore::CanvasPattern>>>::convert(JSC::ExecState&,JSC::JSValue)::{lambda(auto:1&&)#1}<WebCore::IDLInterface<WebCore::CanvasPattern>> &&)",
			signature);
	}

	@Test
	public void testFunctionWithLambdaParameter() throws Exception {

		//
		// Mangled: _ZN3JSC9Structure3addILNS0_9ShouldPinE1EZNS_8JSObject35prepareToPutDirectWithoutTransitionERNS_2VMENS_12PropertyNameEjjPS0_EUlRKNS_24GCSafeConcurrentJSLockerEiiE_EEiS5_S6_jRKT0_
		//
		// Demangled: int
		//            JSC::Structure::add<
		//						(JSC::Structure::ShouldPin)1,
		//						 JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&, JSC::PropertyName, unsigned int, unsigned int, JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker const&, int, int)#1}
		//								>(
		//									JSC::VM&, JSC::PropertyName,
		//									unsigned int,
		//									JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&, JSC::PropertyName, unsigned int, unsigned int, JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker const&, int, int)#1} const&
		//								  )
		//
		//

		DemangledObject object = parser.parse(
			"_ZN3JSC9Structure3addILNS0_9ShouldPinE1EZNS_8JSObject35prepareToPutDirectWithoutTransitionERNS_2VMENS_12PropertyNameEjjPS0_EUlRKNS_24GCSafeConcurrentJSLockerEiiE_EEiS5_S6_jRKT0_",
			"int JSC::Structure::add<(JSC::Structure::ShouldPin)1, JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&, JSC::PropertyName, unsigned int, unsigned int, JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker const&, int, int)#1}>(JSC::VM&, JSC::PropertyName, unsigned int, JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&, JSC::PropertyName, unsigned int, unsigned int, JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker const&, int, int)#1} const&)");
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String name =
			"add<(JSC::Structure::ShouldPin)1,JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&,JSC::PropertyName,unsigned_int,unsigned_int,JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker_const&,int,int)#1}>";
		assertName(object, name, "JSC", "Structure");

		String signature = object.getSignature(false);
		assertEquals(
			"int JSC::Structure::add<(JSC::Structure::ShouldPin)1,JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&,JSC::PropertyName,unsigned_int,unsigned_int,JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker_const&,int,int)#1}>(JSC::VM &,JSC::PropertyName,unsigned int,JSC::JSObject::prepareToPutDirectWithoutTransition(JSC::VM&,JSC::PropertyName,unsigned_int,unsigned_int,JSC::Structure*)::{lambda(JSC::GCSafeConcurrentJSLocker const&, int, int)#1} const &)",
			signature);
	}

	@Test
	public void testFunctionInLambdaNamespace() throws Exception {

		//
		// Mangled: _ZZN12GrGLFunctionIFPKhjEEC1IZN13skia_bindings28CreateGLES2InterfaceBindingsEPN3gpu5gles214GLES2InterfaceEPNS6_14ContextSupportEE3$_0EET_ENUlPKvjE_8__invokeESF_j
		//
		// Demangled: GrGLFunction<unsigned char const* (unsigned int)>
		//            ::
		//			  GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0)
		//	          ::
		//	          {lambda(void const*, unsigned int)#1}
		//	          ::
		//	          __invoke(void const*, unsigned int)
		//

		DemangledObject object = parser.parse(
			"_ZZN12GrGLFunctionIFPKhjEEC1IZN13skia_bindings28CreateGLES2InterfaceBindingsEPN3gpu5gles214GLES2InterfaceEPNS6_14ContextSupportEE3$_0EET_ENUlPKvjE_8__invokeESF_j",
			"GrGLFunction<unsigned char const* (unsigned int)>::GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*, gpu::ContextSupport*)::$_0)::{lambda(void const*, unsigned int)#1}::__invoke(void const*, unsigned int)");
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		assertName(object, "__invoke", "GrGLFunction<unsigned_char_const*(unsigned_int)>",
			"GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0)",
			"{lambda(void_const*,unsigned_int)#1}");

		String signature = object.getSignature(false);
		assertEquals(
			"undefined GrGLFunction<unsigned_char_const*(unsigned_int)>::GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0)::{lambda(void_const*,unsigned_int)#1}::__invoke(void const *,unsigned int)",
			signature);
	}

	@Test
	public void testFunctionWithLamba_WithUnnamedType() throws Exception {

		//
		// Mangled: _ZN13SoloGimbalEKFUt_C2Ev
		//
		// Demangled: SoloGimbalEKF::{unnamed type#1}::SoloGimbalEKF()
		//
		String mangled = "_ZN13SoloGimbalEKFUt_C2Ev";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("undefined SoloGimbalEKF::{unnamed_type#1}::SoloGimbalEKF(void)", signature);
	}

	@Test
	public void testFunctionWithLambda_WrappingAnotherFunctionCall() throws Exception {

		//
		// Mangled: _Z11wrap_360_cdIiEDTcl8wrap_360fp_Lf42c80000EEET_
		//
		// Demangled: decltype (wrap_360({parm#1}, (float)[42c80000])) wrap_360_cd<int>(int)
		//
		// 'wrap_360_cd<int>(int)' is a function that takes an int and then passes that int along
		// with a constant value to 'wrap_360<int>' by using a lambda function.  It looks like
		// this:
		//     auto wrap_360_cd<int>(int a) -> decltype(wrap_360(angle, 100.f))
		//
		// where the function is declared with this syntax:
		// 	   auto identifier ( argument-declarations... ) -> return_type
		//

		String mangled = "_Z11wrap_360_cdIiEDTcl8wrap_360fp_Lf42c80000EEET_";
		String demangled = process.demangle(mangled);

		DemangledObject object = parser.parse(mangled, demangled);
		assertNotNull(object);
		assertType(object, DemangledFunction.class);

		String signature = object.getSignature(false);
		assertEquals("undefined wrap_360_cd<int>(int)", signature);
	}

	@Test
	public void testGetDataType_LongLong() throws Exception {
		assertNotNull(
			new DemangledDataType("fake", "fake", DemangledDataType.LONG_LONG).getDataType(null));
	}

	private void assertType(Demangled o, Class<?> c) {
		assertTrue("Wrong demangled type. " + "\nExpected " + c + "; " + "\nfound " + o.getClass(),
			c.isInstance(o));
	}

	private void assertName(DemangledObject demangledObj, String name, String... namespaces) {

		assertEquals("Unexpected demangled name", name, demangledObj.getName());
		Demangled namespace = demangledObj.getNamespace();
		for (int i = namespaces.length - 1; i >= 0; i--) {
			String expectedName = namespaces[i];
			assertNotNull("Namespace mismatch", namespace);
			String actualName = namespace.getNamespaceName();
			assertEquals(expectedName, actualName);
			namespace = namespace.getNamespace();
		}
		assertNull("Namespace mismatch", namespace);
	}
}
