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
package ghidra.app.util.pcodeInject;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class ReferenceMethodsTest extends AbstractGhidraHeadlessIntegrationTest {

	private SleighLanguage language;
	private Address opAddress;
	private long uniqueBase;

	@Before
	public void setUp() throws Exception {
		language =
			(SleighLanguage) getLanguageService().getLanguage(new LanguageID("JVM:BE:32:default"));
		opAddress = language.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000);
		uniqueBase = language.getUniqueBase();
	}

	@Test
	public void testGetStatic1() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "I");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForGetStatic(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.TEMP_1, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_GETSTATIC);
		expected.emitAssignVarnodeFromDereference(ReferenceMethods.VALUE, 4,
			ReferenceMethods.TEMP_1);
		expected.emitPushCat1Value(ReferenceMethods.VALUE);
		assertTrue(pCode.equals(expected));
	}

	@Test
	public void testGetStatic2() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "J");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForGetStatic(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);

		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.TEMP_1, 8,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_GETSTATIC);
		expected.emitAssignVarnodeFromDereference(ReferenceMethods.VALUE, 8,
			ReferenceMethods.TEMP_1);
		expected.emitPushCat2Value(ReferenceMethods.VALUE);

		assertEquals(pCode, expected);
	}

	@Test
	public void testPutStatic1() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "I");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForPutStatic(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat1Value(ReferenceMethods.NEW_VALUE);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.STATIC_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_PUTSTATIC);
		expected.emitWriteToMemory(PcodeOpEmitter.RAM, 4,
			ReferenceMethods.STATIC_OFFSET, ReferenceMethods.NEW_VALUE);
		assertEquals(pCode, expected);
	}

	@Test
	public void testPutStatic2() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "J");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForPutStatic(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat2Value(ReferenceMethods.NEW_VALUE);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.STATIC_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_PUTSTATIC);
		expected.emitWriteToMemory(PcodeOpEmitter.RAM, 8,
			ReferenceMethods.STATIC_OFFSET, ReferenceMethods.NEW_VALUE);
		assertEquals(pCode, expected);
	}

	@Test
	public void testGetField1() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "I");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForGetField(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat1Value(ReferenceMethods.OBJECT_REF);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.TEMP_1, 4,
			ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_GETFIELD);
		expected.emitAssignVarnodeFromDereference(ReferenceMethods.VALUE, 4,
			ReferenceMethods.TEMP_1);
		expected.emitPushCat1Value(ReferenceMethods.VALUE);
		assertEquals(pCode, expected);
	}

	@Test
	public void testGetField2() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "J");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForGetField(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat1Value(ReferenceMethods.OBJECT_REF);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.TEMP_1, 8,
			ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_GETFIELD);
		expected.emitAssignVarnodeFromDereference(ReferenceMethods.VALUE, 8,
			ReferenceMethods.TEMP_1);
		expected.emitPushCat2Value(ReferenceMethods.VALUE);
		assertEquals(pCode, expected);
	}

	@Test
	public void testPutField1() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "I");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForPutField(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat1Value(ReferenceMethods.NEW_VALUE);
		expected.emitPopCat1Value(ReferenceMethods.OBJECT_REF);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.FIELD_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_PUTFIELD);
		expected.emitWriteToMemory(PcodeOpEmitter.RAM, 4,
			ReferenceMethods.FIELD_OFFSET, ReferenceMethods.NEW_VALUE);

		assertEquals(pCode, expected);
	}

	@Test
	public void testPutField2() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendFieldRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                   //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);  //3
		TestClassFileCreator.appendUtf8(classFile, "className");                  //4
		TestClassFileCreator.appendUtf8(classFile, "fieldName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "J");                           //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		ReferenceMethods.getPcodeForPutField(pCode, 1, constantPool);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitPopCat2Value(ReferenceMethods.NEW_VALUE);
		expected.emitPopCat1Value(ReferenceMethods.OBJECT_REF);
		expected.emitAssignVarnodeFromPcodeOpCall(ReferenceMethods.FIELD_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_PUTFIELD);
		expected.emitWriteToMemory(PcodeOpEmitter.RAM, 8,
			ReferenceMethods.FIELD_OFFSET, ReferenceMethods.NEW_VALUE);

		assertEquals(pCode, expected);
	}

}
