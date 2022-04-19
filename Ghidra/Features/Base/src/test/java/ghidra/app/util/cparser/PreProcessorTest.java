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

import java.io.ByteArrayOutputStream;
import java.net.URL;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.cparser.CPP.ParseException;
import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class PreProcessorTest extends AbstractGenericTest {
	private static String resourceName = "PreProcessorTest.h";
	private static CategoryPath path = new CategoryPath(new CategoryPath("/PreProcessorTest.h"), "defines");
	
	// must get rid of after all tests
	private static StandAloneDataTypeManager dtMgr;
	private static ByteArrayOutputStream baos = new ByteArrayOutputStream();
	private static PreProcessor parser;
	
	long value;
	String defname;

	public PreProcessorTest() {
		super();
	}

	@BeforeClass
	public static void init() {
		URL url = PreProcessorTest.class.getResource(resourceName);
		
		String[] args = new String[]  {"-I"+url.getPath()+"/..","-DFROM_ARG_VALUE=300", "-DFROM_ARG_DEF", "-DFROM_ARG_EMPTY=\"\""};
		parser = null;
		try {
			parser = new PreProcessor(args);
		}
		catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		parser.setOutputStream(baos);

////		String[] args = new String[]  {"-I/local/VisualStudio/Windows/v7.0a/Include", "-I/local/VisualStudio/VS12/include", "-D_WIN32", "-D_CRT_SECURE_NO_WARNINGS"};
//		String[] args = new String[]  {"-I/local/Mac/MacOSX.platform/Developer/SDKs/MacOSX10.10.sdk/usr/include",
//				"-I/local/Mac/MacOSX.platform/Developer/SDKs/MacOSX10.10.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/",
//				"-D_LARGEFILE64_SOURCE=0","-D__GNUCC__=4.1","-D_DARWIN_C_SOURCE","-DBSD","-D__APPLE__","-D__x86_64__=1"};
//		parser.setArgs(args);
//		String fullName;
//		fullName = "mach/memory_object_types.h";
//		parser.parse(fullName);
//		fullName = "ctype.h";
//		parser.parse(fullName);
////		fullName = "adoguids.h";
////		parser.parse(fullName);

		parser.parse(url.getFile());

		// Uncomment to print out parse results
		// System.err.println(baos.toString());

		dtMgr = new StandAloneDataTypeManager("parsed");
		parser.getDefinitions().populateDefineEquates(dtMgr);
	}
	
	@AfterClass
	public static void destroy() {
		dtMgr = null;
		baos = null;
		parser = null;
	}
	
	@Test
	public void testHeaderParsed() throws Exception {
		
		String results = baos.toString("ASCII");
		int end = results.lastIndexOf(";") + 1;
		String endStr = results.substring(end - 9, end);
		assertEquals("theEnd();", endStr);

		assertTrue("macro expansion _fpl(bob) failed ", results
				.indexOf("extern int __declspec(\"fp(\\\"l\\\", \" #bob \")\") __ifplbob;") != -1);
	}
	
	@Test
	public void testDefines() throws Exception {
		long value;
		String defname;

		value = 32516;
		defname = "DefVal1";
		checkDefine(dtMgr, path, value, defname);

		value = 0x06010000 + 0xf1;
		defname = "DefVal2";
		checkDefine(dtMgr, path, value, defname);

		value = 0x60010001 & 0x21234 | 1;
		defname = "DefVal3";
		checkDefine(dtMgr, path, value, defname);

		value = 0x1 << (1 + 2 | 4);
		defname = "DefVal4";
		checkDefine(dtMgr, path, value, defname);

		value = (0xFF000000L & (~(0x01000000L | 0x02000000L | 0x04000000L)));
		defname = "DefVal5";
		checkDefine(dtMgr, path, value, defname);

		value = ((0x000F0000L) | (0x00100000L) | 0x3);
		defname = "DefVal6";
		checkDefine(dtMgr, path, value, defname);

		value = 0x40000000L;
		defname = "DefVal7";
		checkDefine(dtMgr, path, value, defname);

		value = ((3 << 13) | (3 << 9) | 4);
		defname = "DefVal8";
		checkDefine(dtMgr, path, value, defname);

		value = ((0x7fff & ~(((1 << 4) - 1))));
		defname = "DefVal9";
		checkDefine(dtMgr, path, value, defname);

		value = ((0x7fff) * 900L / 1000);
		defname = "DefVal10";
		checkDefine(dtMgr, path, value, defname);

		value = 0;
		defname = "TOO_MANY_FISH";
		checkDefine(dtMgr, path, value, defname);

		value = 0x53977;
		defname = "ImOctal";
		checkDefine(dtMgr, path, value, defname);

		defname = "TEST_FAILED";
		checkNotDefine(dtMgr, path, defname);

		defname = "isDefineOnValue";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
		
		defname = "DID_EXPANSION";
		value = 1;
		checkDefine(dtMgr, path, value, defname);

		defname = "BIGNUM";
		value = 64 * 16 + 16;
		checkDefine(dtMgr, path, value, defname);
		
		defname = "NEWLINETEST1";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
		
		defname = "NEWLINETEST2";
		value = 2;
		checkDefine(dtMgr, path, value, defname);
		
		defname = "NEWLINETEST3";
		value = 3;
		checkDefine(dtMgr, path, value, defname);
		
		
		defname = "SEPERATORC";
		String defval = parser.getDef(defname);
		assertEquals(defval, "','");
	}
	
	@Test
	public void testDefinesArgValue() {
		defname = "DID_ARG_VALUE";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
		
		// This is from a -D arg define, not from a file
		CategoryPath argCategoryPath = new CategoryPath(CategoryPath.ROOT, "defines");	
		defname = "FROM_ARG_VALUE";
		value = 300;
		checkDefine(dtMgr, argCategoryPath, value, defname);
	}

	@Test
	public void testDefinesArgEmpty() {
		defname = "DID_ARG_EMPTY";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesArgDef() {
		defname = "DID_ARG_DEF";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesArgIsDefValue() {
		defname = "DID_ARG_ISDEF_VALUE";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesArgIsDefEmpty() {
		defname = "DID_ARG_ISDEF_EMPTY";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesArgIsDefDef() {
		defname = "DID_ARG_ISDEF_DEF";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testFileDefinesValue() {
		defname = "DID_FILE_VALUE";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesFileEmpty() {
		defname = "DID_FILE_EMPTY";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesFileDef() {
		defname = "DID_FILE_DEF";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesFileIsDefValue() {
		defname = "DID_FILE_ISDEF_VALUE";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesFileIsDefEmpty() {
		defname = "DID_FILE_ISDEF_EMPTY";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}

	@Test
	public void testDefinesFileIsDefDef() {
		defname = "DID_FILE_ISDEF_DEF";
		value = 1;
		checkDefine(dtMgr, path, value, defname);
	}
	
	@Test
	public void testMultipleInclude() {
		defname = "INCLUDE1";
		String defval = parser.getDef(defname);
		assertNotNull("Had 1 duplicate include", defval);
		
		defname = "INCLUDE2";
		defval = parser.getDef(defname);
		assertNotNull("Had 2 duplicate include", defval);
		
		defname = "INCLUDE3";
		defval = parser.getDef(defname);
		assertNotNull("Had 3 duplicate include", defval);
		
		defname = "INCLUDE4";
		defval = parser.getDef(defname);
		assertNotNull("Had 4 duplicate include", defval);
		
		defname = "INCLUDE5";
		defval = parser.getDef(defname);
		// if a define is not defined, getDef() returns name of define as value
		assertEquals("No INCLUDE5 define", "INCLUDE5", defval);
	}

	private void checkDefine(StandAloneDataTypeManager dtMgr, CategoryPath path, long value,
			String defname) {
		DataType dataType = dtMgr.getDataType(path, "define_" + defname);
		String msg = "Define Enum " + defname;
		assertNotNull(msg, dataType);
		assertTrue(msg, dataType instanceof Enum);
		assertEquals(msg, value, ((Enum) dataType).getValue(defname));
	}

	private void checkNotDefine(StandAloneDataTypeManager dtMgr, CategoryPath path,
			String defname) {
		DataType dataType = dtMgr.getDataType(path, "define_" + defname);
		assertNull(dataType);
	}
}
