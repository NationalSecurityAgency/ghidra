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
package ghidra.app.util.cparser;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class CParserTest extends AbstractGhidraHeadlessIntegrationTest {

	public CParserTest() {
		super();
	}

	@Test
	public void testSimple() throws Exception {
		CParser parser = new CParser();

		DataType pdt = parser.parse("typedef long int32_t;");
		assertTrue(pdt != null);
		assertTrue(pdt instanceof TypeDef);
		assertTrue(pdt.getName().equals("int32_t"));
		DataType dt = parser.getDataTypeManager().getDataType("/int32_t");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);
		
		dt = parser.parse("struct mystruct {" +
                     "    int field1;" +
                     "    char field2;" +
                     " };");
		
		assertTrue(dt != null);
		assertTrue(dt instanceof Structure);
		Structure sdt = (Structure) dt;
		DataTypeComponent comp = sdt.getComponent(0);
		assertEquals("field1", comp.getFieldName());
		assertEquals(comp.getDataType().getName(),"int");
		comp = sdt.getComponent(1);
		assertEquals("field2", comp.getFieldName());
		assertEquals(comp.getDataType().getName(),"char");
	}

	@Test
	public void testLongLong() throws Exception {
		CParser parser;

		parser = new CParser();
		DataType pdt64 = parser.parse("typedef unsigned long int uint64_t;");

		assertTrue(pdt64 != null);
		assertTrue(pdt64 instanceof TypeDef);
		assertTrue(pdt64.getName().equals("uint64_t"));
		assertEquals(4, pdt64.getLength());

		DataType dt = parser.getDataTypeManager().getDataType("/uint64_t");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);

		parser = new CParser();
		DataType pdt32 = parser.parse("typedef unsigned long long int uint64_t;");
		assertTrue(pdt32 != null);
		assertTrue(pdt32 instanceof TypeDef);
		assertTrue(pdt32.getName().equals("uint64_t"));
		assertEquals(8, pdt32.getLength());
	}
	
	@Test
	public void testTypedef() throws Exception {
		CParser parser;

		parser = new CParser();
		DataType tdDt = parser.parse("typedef struct foo * foo;");

		assertTrue(tdDt != null);
		assertTrue(tdDt instanceof TypeDef);
		System.out.println(tdDt.getPathName());
		System.out.println(((TypeDef)tdDt).getDataType().getPathName());
		assertEquals("foo", tdDt.getName());
		assertEquals("foo.conflict *", ((TypeDef)tdDt).getDataType().getName());
		assertEquals(4, tdDt.getLength());

		DataType dt = parser.getDataTypeManager().getDataType("/foo");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);

	}
	
	@Test
	public void testWcharT() throws Exception {

		DataType dt;
		Structure sdt;
		DataTypeComponent comp;
		
		CParser parser;
		
		parser = new CParser();
		dt = parser.parse("typedef int wchar_t;");
		
		assertTrue(dt instanceof WideCharDataType);

		parser = new CParser();
		dt = parser.parse("struct mystruct {" +
						  "    wchar_t defined_wchar_t;" +
				          "};");

		sdt = (Structure) dt;
		comp = sdt.getComponent(0);
		assertTrue(comp.getDataType() instanceof WideCharDataType);
		
		parser = new CParser();
		dt = parser.parse("typedef int wchar_t;" +
		                  "struct mystruct {" +
				          "    wchar_t defined_wchar_t;" +
		                  "};");
		
		sdt = (Structure) dt;
		comp = sdt.getComponent(0);
		assertTrue(comp.getDataType() instanceof WideCharDataType);
		

		parser = new CParser();
		dt = parser.parse("typedef short wchar_t;" +
                                   "  typedef wchar_t foo;");

		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt.getName().equals("foo"));
		assertEquals(2, dt.getLength());
		assertTrue(((TypeDef) dt).getBaseDataType() instanceof BuiltInDataType);

		parser = new CParser();
		DataType pdt32 = parser.parse("typedef wchar_t foo;");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt.getName().equals("foo"));
		assertEquals(2, dt.getLength());
		assertTrue(((TypeDef) dt).getBaseDataType() instanceof BuiltInDataType);
	}

	@Test
	public void testParseDataType_NoSubArchive() throws Exception {

		DataTypeManager primary = new StandAloneDataTypeManager("primary");

		DataTypeManager[] subs = new DataTypeManager[] {};

		CParser parser = new CParser(primary, false, subs);
		try {
			parser.parse("void foo(bar *);");
			Assert.fail("Expected an exception when the parser was missing a data type definition");
		}
		catch (ParseException e) {
			// good!
		}
	}

	@Test
	public void testParseDataType_WithSubArchive() throws Exception {

		DataTypeManager primary = new StandAloneDataTypeManager("primary");

		DataTypeManager[] subs = new DataTypeManager[] { createDataTypeManagerWithABar() };

		CParser parser = new CParser(primary, false, subs);
		DataType result = parser.parse("void foo(bar *);");
		assertNotNull(result);
	}

	private DataTypeManager createDataTypeManagerWithABar() {
		DataTypeManager dtm = new StandAloneDataTypeManager("sub 0");

		int txID = dtm.startTransaction("Add DataType");
		try {
			DataType dt = new StructureDataType("bar", 1);
			dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		finally {
			dtm.endTransaction(txID, true);
		}

		return dtm;
	}

	@Test
	public void testHeaderParsing() throws Exception {
		DataTypeManager dtMgr;
		CParser parser;

		parser = new CParser();
//		Uncomment to save the parse results to a GDT file to check out
//
//		File fgdt = new File("/tmp/CParserTest.gdt");
//		fgdt.delete();
//		FileDataTypeManager fdt = FileDataTypeManager.createFileArchive(fgdt);
//		parser = new CParser(fdt, true, null);

		String resourceName;
		resourceName = "CParserTest.h";
		InputStream is = CParserTest.class.getResourceAsStream(resourceName);

		parser.setParseFileName("CParserTest.h");
		parser.parse(is);
		dtMgr = parser.getDataTypeManager();

//		Uncomment to save the parse results to a GDT file to check out
//
//		fdt.save();
//		fdt.close();

		String parseMessages = parser.getParseMessages();
		System.out.println(parseMessages);
		
		DataType dt;
		DataType pointedToDT;
		ParameterDefinition[] funcArgs;
		FunctionDefinition funcDef;
		String str;

		dt = dtMgr.getDataType(new CategoryPath("/"), "pragmaPassed");
		assertNotNull("Structure after pragma not parsed", dt);
		
		assertTrue("Duplicate ENUM message missing", parseMessages.contains("duplicate enum value: options_enum : PLUS_SET : 16"));
		
		assertTrue("Static assert fail missing", parseMessages.contains("Static_Assert possibly failed  \"\"math fail!\"\""));
		
		assertTrue("Static assert fail missing", parseMessages.contains("Static_Assert possibly failed  \"\"1 + 1 == 3, fail!\"\""));
		
		dt = dtMgr.getDataType(new CategoryPath("/"), "_IO_FILE_complete");
		Structure sldt = (Structure) dt;
		DataTypeComponent data3 = sldt.getComponent(2);
		assertEquals("Computed Array correct", 40, data3.getLength());


		dt = dtMgr.getDataType(new CategoryPath("/"), "fnptr"); // typedef int (*fnptr)(struct fstruct);
		// "fnptr" named typedef of pointer to "int fnptr(fstruct )" --- should an anonymous function name be used?
		assertTrue("typedefed fnptr", dt instanceof TypeDef);
		dt = ((TypeDef) dt).getDataType();
		assertTrue("typedef fnptr *", dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue("typedef fnptr *", dt instanceof FunctionDefinition);
		funcDef = (FunctionDefinition) dt;
		funcArgs = funcDef.getArguments();
		assertTrue("struct fstruct", funcArgs[0].getDataType() instanceof Structure);
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "int fnptr(fstruct )", replaceAnonFuncName(str));		
		

		// Test 
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "_Once"); // void __cdecl _Once(_Once_t *, void (__cdecl *)(void));
		// void _Once(_Once_t * , void * ) ---- 2nd param should be an anonymous function * --> void (__cdecl *)(void)
		assertTrue("_Once function definition", dt instanceof FunctionDefinition);
		funcDef = (FunctionDefinition) dt;
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "void _Once(_Once_t * , _func_anon_ * )", replaceAnonFuncName(str));
		assertEquals("calling convention _Once", "__cdecl", funcDef.getCallingConventionName());
		funcArgs = funcDef.getArguments();
		assertTrue("struct fstruct", funcArgs[0].getDataType() instanceof Pointer);	
		assertTrue("ptr", funcArgs[1].getDataType() instanceof Pointer);
		pointedToDT = ((Pointer) funcArgs[1].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);	
		funcDef = (FunctionDefinition) pointedToDT;
		assertEquals("calling convention _Once", "__cdecl", funcDef.getCallingConventionName());
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "void _func_anon_(void)", replaceAnonFuncName(str));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "_Twice"); // void __cdecl _Once(_Once_t *, void (__cdecl *)(void));
		// void _Once(_Once_t * , void * ) ---- 2nd param should be an anonymous function * --> void (__cdecl *)(void)
		assertTrue("_Twice function definition", dt instanceof FunctionDefinition);
		funcDef = (FunctionDefinition) dt;
		str = funcDef.getPrototypeString();
		assertEquals("calling convention _Twice", "__stdcall", funcDef.getCallingConventionName());
		funcArgs = funcDef.getArguments();
		pointedToDT = ((Pointer) funcArgs[0].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);	
		funcDef = (FunctionDefinition) pointedToDT;
		assertEquals("calling convention _Once", "__cdecl", funcDef.getCallingConventionName());
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "void _func_anon_(void)", replaceAnonFuncName(str));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "_Thrice"); // void __cdecl _Once(_Once_t *, void (__cdecl *)(void));
		// void _Once(_Once_t * , void * ) ---- 2nd param should be an anonymous function * --> void (__cdecl *)(void)
		assertTrue("_Twice function definition", dt instanceof FunctionDefinition);
		funcDef = (FunctionDefinition) dt;
		str = funcDef.getPrototypeString();
		assertEquals("calling convention _Thrice", "unknown", funcDef.getCallingConventionName());
		funcArgs = funcDef.getArguments();
		pointedToDT = ((Pointer) funcArgs[0].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);	
		funcDef = (FunctionDefinition) pointedToDT;
		assertEquals("calling convention _Once", "__cdecl", funcDef.getCallingConventionName());
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "void _func_anon_(void)", replaceAnonFuncName(str));
		
		dt = dtMgr.getDataType(new CategoryPath("/"), "UShortInt");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof UnsignedShortDataType);

		dt = dtMgr.getDataType(new CategoryPath("/"), "ULongLong");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof UnsignedLongLongDataType);

		dt = dtMgr.getDataType(new CategoryPath("/"), "SLongLong");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof LongLongDataType);

		dt = dtMgr.getDataType(new CategoryPath("/"), "LongLong");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof LongLongDataType);

		dt = dtMgr.getDataType(new CategoryPath("/"), "SShortInt");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof ShortDataType);

		dt = dtMgr.getDataType(new CategoryPath("/"), "ShortInt");
		assertTrue(dt instanceof TypeDef);
		assertTrue("signature not correct",
			((TypeDef) dt).getBaseDataType() instanceof ShortDataType);

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "bob");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertTrue("signature not correct", str.equals("int bob(int b)"));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "bobCRef");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertTrue("signature not correct",
			str.equals("int bobCRef(int a, fstruct * fs, fstruct * fp)"));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "stdcall_func");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertTrue("Callee should not purge", CompilerSpec.CALLING_CONVENTION_stdcall
				.equals(((FunctionDefinition) dt).getCallingConventionName()));
		assertTrue("signature not correct", str.equals("int stdcall_func(int b)"));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "cdecl_func");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertTrue("Caller should purge", CompilerSpec.CALLING_CONVENTION_cdecl
				.equals(((FunctionDefinition) dt).getCallingConventionName()));
		assertTrue("signature not correct", str.equals("int cdecl_func(int a)"));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "cdecl_func_after");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		assertTrue("Caller should purge", CompilerSpec.CALLING_CONVENTION_cdecl
				.equals(((FunctionDefinition) dt).getCallingConventionName()));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "_Noreturn_exit");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		assertTrue("Caller should noreturn", ((FunctionDefinition) dt).hasNoReturn());

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "win_exit");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		assertTrue("Caller should noreturn", ((FunctionDefinition) dt).hasNoReturn());

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "gcc_exit");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		assertTrue("Caller should noreturn", ((FunctionDefinition) dt).hasNoReturn());
		
		dt = dtMgr.getDataType(new CategoryPath("/"), "UINT2");
		assertTrue(dt instanceof TypeDef);
		assertEquals("ushort", ((TypeDef) dt).getBaseDataType().getName());

		dt = dtMgr.getDataType("/int32_t");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);

		// typedef long unsigned int LUI_size_t;
		dt = dtMgr.getDataType("/LUI_size_t");
		assertEquals("ulong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef unsigned long int ULI_size_t;
		dt = dtMgr.getDataType("/ULI_size_t");
		assertEquals("ulong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef long signed   int LSI_size_t;
		dt = dtMgr.getDataType("/LSI_size_t");
		assertEquals("long", ((TypeDef) dt).getBaseDataType().getName());

		// typedef long          int LI_size_t;
		dt = dtMgr.getDataType("/LI_size_t");
		assertEquals("long", ((TypeDef) dt).getBaseDataType().getName());

		// typedef long long     int LLI_size_t;
		dt = dtMgr.getDataType("/LLI_size_t");
		assertEquals("longlong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef long unsigned long int LULI_size_t;
		dt = dtMgr.getDataType("/LULI_size_t");
		assertEquals("ulonglong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef unsigned long long int ULLI_size_t;
		dt = dtMgr.getDataType("/ULLI_size_t");
		assertEquals("ulonglong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef long long unsigned int LLUI_size_t;
		dt = dtMgr.getDataType("/LLUI_size_t");
		assertEquals("ulonglong", ((TypeDef) dt).getBaseDataType().getName());

		// typedef unsigned int  UI_size_t;
		dt = dtMgr.getDataType("/UI_size_t");
		assertEquals("uint", ((TypeDef) dt).getBaseDataType().getName());

		dt = dtMgr.getDataType("/baz");
		assertTrue(dt != null);
		assertTrue(dt instanceof TypeDef);
		assertTrue(((TypeDef) dt).getBaseDataType() instanceof Array);
		Array adt = (Array) ((TypeDef) dt).getBaseDataType();
		assertEquals(8, adt.getNumElements());
		assertTrue(adt.getDataType() instanceof Array);
		adt = (Array) adt.getDataType();
		assertEquals(6, adt.getNumElements());

		dt = dtMgr.getDataType("/outer");
		assertTrue(dt != null);
		assertTrue(dt instanceof Structure);
		Structure sdt = (Structure) dt;
		DataTypeComponent comp = sdt.getComponentAt(2);
		assertEquals("sa", comp.getFieldName());
		assertEquals(2, comp.getOffset());
		comp = sdt.getComponentAt(4);
		assertEquals("ia", comp.getFieldName());
		assertEquals(4, comp.getOffset());
		comp = sdt.getComponentAt(8);
		assertEquals("cb", comp.getFieldName());
		assertEquals(8, comp.getOffset());
		comp = sdt.getComponentAt(10);
		assertEquals("ib", comp.getFieldName());
		assertEquals(10, comp.getOffset());
		comp = sdt.getComponentAt(16);
		assertEquals("cc", comp.getFieldName());
		assertEquals(16, comp.getOffset());
		// fdt.save();

		dt = dtMgr.getDataType(new CategoryPath("/"), "options_enum");
		assertTrue(dt instanceof Enum);
		assertEquals("enum options_enum not correct", 0x4, ((Enum) dt).getValue("SUPPORTED"));
		assertEquals("enum options_enum not correct", 0x5, ((Enum) dt).getValue("ONE_UP"));
		assertEquals("enum options_enum not correct", 4 + 12, ((Enum) dt).getValue("PLUS_SET"));
		assertEquals("enum options_enum not correct", 12 - 1, ((Enum) dt).getValue("MINUS_SET"));
		assertEquals("enum options_enum not correct", 1 - 1 + 1, ((Enum) dt).getValue("ISONE"));
		assertEquals("enum options_enum not correct", -5 - 1, ((Enum) dt).getValue("ISNEGATIVE"));
		assertEquals("enum options_enum not correct", 64 * 16 + 16, ((Enum) dt).getValue("BIGNUM"));
		assertEquals("enum options_enum not correct", 11, ((Enum) dt).getValue("TRINARY"));
		assertEquals("enum options_enum not correct", 1 << 1 >> 1,
			((Enum) dt).getValue("SHIFTED1"));
		assertEquals("enum options_enum not correct", 7 >> 3 << 3,
			((Enum) dt).getValue("SHIFTED3"));
		assertEquals("enum options_enum not correct", 15 >> 3 << 3,
			((Enum) dt).getValue("SHIFTED4"));

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "__checkint");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "int __checkint(int val, int * err)", str);

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "fputs");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "int fputs(char * , void * )", str);
		
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "funcParam");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		
		
		assertEquals("signature not correct", "void funcParam(_func_anon_ * )", replaceAnonFuncName(str));
		funcDef = (FunctionDefinition) dt;
		funcArgs = funcDef.getArguments();
		assertTrue("ptr", funcArgs[0].getDataType() instanceof Pointer);
		pointedToDT = ((Pointer) funcArgs[0].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);
		str = ((FunctionDefinition) pointedToDT).getPrototypeString();
		assertEquals("signature not correct", "void _func_anon_(void)", replaceAnonFuncName(str));

		for (int i=1; i < 11; i++) {
			dt = dtMgr.getDataType(new CategoryPath("/functions"), "funcParam"+i);
			assertTrue("not a function" + dt.getName(), dt instanceof FunctionDefinition);
			str = ((FunctionDefinition) dt).getPrototypeString();
			funcDef = (FunctionDefinition) dt;
			funcArgs = funcDef.getArguments();
			assertTrue("ptr", funcArgs[1].getDataType() instanceof Pointer);
			pointedToDT = ((Pointer) funcArgs[1].getDataType()).getDataType();
			assertTrue("ptr not to a function " + dt.getName(), pointedToDT instanceof FunctionDefinition);
			funcArgs = ((FunctionDefinition) pointedToDT).getArguments();
			assertEquals("function args != 1 " + pointedToDT, 1, funcArgs.length);
			assertEquals("double", funcArgs[0].getDataType().getName());
		}
		
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "funcParamNoPtr");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "double funcParamNoPtr(double x, func * func)", str);
		funcDef = (FunctionDefinition) dt;
		funcArgs = funcDef.getArguments();
		assertTrue("ptr", funcArgs[1].getDataType() instanceof Pointer);
		pointedToDT = ((Pointer) funcArgs[1].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);
		str = ((FunctionDefinition) pointedToDT).getPrototypeString();
		assertEquals("signature not correct", "double func(double , void * )", str);
		
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "funcParmWithName");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "void funcParmWithName(_func_arg * _func_arg)", str);

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "__mem_func");
		assertTrue("not a function", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "void __mem_func("
				+ "void * ,"
				+ " char * * ,"
				+ " int * * * ,"
				+ " _func_anon_ * ,"
				+ " _func_anon_1 * ,"
				+ " _func_anon_2 * )", replaceAnonFuncName(str));
		funcDef = (FunctionDefinition) dt;
		funcArgs = funcDef.getArguments();
		assertTrue("ptr", funcArgs[5].getDataType() instanceof Pointer);
		pointedToDT = ((Pointer) funcArgs[5].getDataType()).getDataType();
		assertTrue("ptr not to a function", pointedToDT instanceof FunctionDefinition);
		str = ((FunctionDefinition) pointedToDT).getPrototypeString();
		assertEquals("signature not correct", "void * _func_anon_(void * , size_t )", replaceAnonFuncName(str));
		
		// ensure that temporary anonymous function definition names did not get retained
		ArrayList<DataType> list = new ArrayList<>();
		dtMgr.findDataTypes("_func_", list);
		assertTrue(list.isEmpty());
		dtMgr.findDataTypes("_func_1", list);
		assertTrue(
				"Expected anonymous function replaced (is blarg first function in CParserTest.h file?):" +
					list,
				list.isEmpty());
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "blarg");
		assertTrue("named function blarg", dt instanceof FunctionDefinition);
		str = ((FunctionDefinition) dt).getPrototypeString();
		assertEquals("signature not correct", "void blarg(int * , long[0][0] * )", replaceAnonFuncName(str));

	    // Structure extension
		dt = dtMgr.getDataType(new CategoryPath("/"), "System_System_SystemException_Fields");
		assertTrue (dt instanceof Structure);
		sdt = (Structure) dt;
		comp = sdt.getComponent(1);
		assertEquals("foo", comp.getFieldName());
		comp = sdt.getComponent(2);
		assertEquals("bar", comp.getFieldName());
		assertEquals("short", comp.getDataType().getName());
		comp = sdt.getComponent(0);
		assertTrue (comp.getDataType() instanceof Structure);
		assertEquals ("extended parent ", "System_SystemException_Fields", comp.getDataType().getName());
		sdt = (Structure) comp.getDataType();
		comp = sdt.getComponent(0);
		assertTrue (comp.getDataType() instanceof Structure);
		assertEquals ("extended parent ", "System_Exception_Fields", comp.getDataType().getName());
		

		// Check arrays of functions in structures
		dt = dtMgr.getDataType(new CategoryPath("/"), "SomeStruct");
		assertTrue (dt instanceof Structure);
		sdt = (Structure) dt;
		
		int numComponents = sdt.getNumComponents();
		assertEquals("Number of components in struct arrays of function pointer + \n" + sdt.toString(),
				8, numComponents);
		
		DataTypeComponent component = sdt.getComponent(2);
		assertEquals("procArray1", component.getFieldName());
		dt = component.getDataType();
		assertTrue("procArray1 member is a an array", dt instanceof Array);
		assertEquals("ProcArray1 member bad size", 2, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();
		assertTrue("ProcArray1 is not an Array of pointers", dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue("procArray1 member is Array of function pointers", dt instanceof FunctionDefinition);
		funcDef = (FunctionDefinition) dt;
		funcArgs = funcDef.getArguments();
		str = funcDef.getPrototypeString();
		assertEquals("signature not correct", "char _func_anon_(int * , short * )", replaceAnonFuncName(str));
		
		dt = dtMgr.getDataType(new CategoryPath("/"), "EmptyBuffer");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;

		// Check trailing flex-array
		DataTypeComponent flexDtc = sdt.getComponent(sdt.getNumComponents() - 1);
		assertEquals("Flex-array reports component length of 0", 0, flexDtc.getLength());
		dt = flexDtc.getDataType();
		assertTrue(dt instanceof Array);
		Array a = (Array) dt;
		assertEquals(0, a.getNumElements());
		assertTrue(a.isZeroLength());
		assertTrue(a.getDataType() instanceof CharDataType);
		assertEquals(1, a.getElementLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "BitFields1");
		assertEquals("char size bitfield", 1, dt.getLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "BitFields2");
		assertEquals("char size overflow bitfield", 2, dt.getLength());

		// bitfield is aligned
		dt = dtMgr.getDataType(new CategoryPath("/"), "BitFields3");
		assertEquals("char to int to char bitfield split", 4, dt.getLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "BitFields4");
		assertEquals("char to int to char bitfield split", 8, dt.getLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "wait");
		assertEquals("union of bitfields in structures with empty names", 8, dt.getLength());

		dt = dtMgr.getDataType("/packed2");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		assertEquals("Explicit packing", true, sdt.hasExplicitPackingValue());
		assertEquals("Packing of packed2", 2, sdt.getExplicitPackingValue());
		comp = sdt.getComponentAt(2);  // int should be at offset 2
		assertEquals("d", comp.getFieldName());
		assertEquals(2, comp.getOffset());

		dt = dtMgr.getDataType("/packed4");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		assertEquals("Explicit packing", true, sdt.hasExplicitPackingValue());
		assertEquals("Packing of packed4", 4, sdt.getExplicitPackingValue());
		comp = sdt.getComponentAt(4);  // int should be at offset 4
		assertEquals("d", comp.getFieldName());
		assertEquals(4, comp.getOffset());

		// pack setting with no push/pop
		dt = dtMgr.getDataType("/packed1");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		assertEquals("Explicit packing", true, sdt.hasExplicitPackingValue());
		assertEquals("Packing of packed1", 1, sdt.getExplicitPackingValue());

		// pack setting with no push/pop
		dt = dtMgr.getDataType("/packed_none");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		assertEquals("Default packing", false, sdt.hasExplicitPackingValue());

		// data type after #pragma got parsed
		dt = dtMgr.getDataType("/functions/dtAfterPragma"); // typedef int (*fnptr)(struct fstruct);
		assertNotNull("parsed datatype after #pragma", dt);
		assertTrue(dt instanceof FunctionDefinition);
		DataType returnType = ((FunctionDefinition) dt).getReturnType();
		assertEquals("return type", "packed4 *", returnType.getName());

		// test function definition typedef
		dt = dtMgr.getDataType(new CategoryPath("/functions"), "range_t");
		assertTrue("not a function", dt instanceof FunctionDefinition);

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "WNDPROC");

		dt = dtMgr.getDataType(new CategoryPath("/functions"), "enumerator");
		assertFalse("structure member anonymous function", dt instanceof FunctionDefinition);

		dt = dtMgr.getDataType(new CategoryPath("/"), "ArraysInStruct");
		sdt = (Structure) ((TypeDef) dt).getBaseDataType();
		DataTypeComponent data4 = sdt.getComponent(4);
		assertEquals("Computed Array correct", 32, data4.getLength());
		DataTypeComponent flexOne = sdt.getComponent(5);
		assertEquals("Flex Array middle component", 0, flexOne.getLength());
		DataTypeComponent data16 = sdt.getComponent(6);
		assertEquals("Computed Array correct", 64, data16.getLength());
		DataTypeComponent flexTwo = sdt.getComponent(8);
		assertEquals("Flex Array end component", 0, flexTwo.getLength());

		// Check trailing flex-array
		flexDtc = sdt.getComponent(sdt.getNumComponents() - 1);
		assertEquals("Flex-array reports component length of 0", 0, flexDtc.getLength());
		dt = flexDtc.getDataType();
		assertTrue(dt instanceof Array);
		a = (Array) dt;
		assertEquals(0, a.getNumElements());
		assertTrue(a.isZeroLength());
		assertTrue(a.getDataType() instanceof UnsignedLongDataType);
		assertEquals(4, a.getElementLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "sizeof_t");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		DataTypeComponent cdt = sdt.getComponent(0);
		assertTrue(cdt.getDataType() instanceof Array);
		assertEquals("Array field defined with sizeof typedef", 128, cdt.getLength());

		dt = dtMgr.getDataType(new CategoryPath("/"), "cpu_set_t");
		assertTrue(dt instanceof Structure);
		sdt = (Structure) dt;
		cdt = sdt.getComponent(0);
		assertTrue(cdt.getDataType() instanceof Array);
		assertEquals("Array field defined with sizeof typedef", 128, cdt.getLength());
		cdt = sdt.getComponent(1);
		assertTrue(cdt.getDataType() instanceof Array);
		assertEquals("Array field defined with sizeof typedef", 2084, cdt.getLength());
	}

	private String replaceAnonFuncName(String str) {
		int num = 0;
		String replStr = str;
		String origStr = null;
		
		while (!replStr.equals(origStr)) {
		   origStr = replStr;
		   replStr = replStr.replaceFirst("_func_([0-9])+", "_func_anon_" + (num == 0 ? "" : num));
		   num++;
		}
		
		return replStr;
	}
}
