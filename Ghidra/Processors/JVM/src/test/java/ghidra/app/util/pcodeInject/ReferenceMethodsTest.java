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

import org.junit.Test;

import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;

public class ReferenceMethodsTest {

	public ReferenceMethodsTest() {

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
		String pCode = ReferenceMethods.getPcodeForGetStatic(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.TEMP_1, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_GETSTATIC);
		PcodeTextEmitter.emitAssignVarnodeFromDereference(expected, ReferenceMethods.VALUE, 4,
			ReferenceMethods.TEMP_1);
		PcodeTextEmitter.emitPushCat1Value(expected, ReferenceMethods.VALUE);
		assertTrue(pCode.equals(expected.toString()));

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
		String pCode = ReferenceMethods.getPcodeForGetStatic(1, constantPool);

		StringBuilder expected = new StringBuilder();

		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.TEMP_1, 8,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_GETSTATIC);
		PcodeTextEmitter.emitAssignVarnodeFromDereference(expected, ReferenceMethods.VALUE, 8,
			ReferenceMethods.TEMP_1);
		PcodeTextEmitter.emitPushCat2Value(expected, ReferenceMethods.VALUE);

		assertEquals(pCode, expected.toString());
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
		String pCode = ReferenceMethods.getPcodeForPutStatic(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.NEW_VALUE);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.STATIC_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_PUTSTATIC);
		PcodeTextEmitter.emitWriteToMemory(expected, PcodeTextEmitter.RAM, 4,
			ReferenceMethods.STATIC_OFFSET, ReferenceMethods.NEW_VALUE);
		assertEquals(pCode, expected.toString());
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
		String pCode = ReferenceMethods.getPcodeForPutStatic(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat2Value(expected, ReferenceMethods.NEW_VALUE);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.STATIC_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_PUTSTATIC);
		PcodeTextEmitter.emitWriteToMemory(expected, PcodeTextEmitter.RAM, 8,
			ReferenceMethods.STATIC_OFFSET, ReferenceMethods.NEW_VALUE);
		assertEquals(pCode, expected.toString());

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
		String pCode = ReferenceMethods.getPcodeForGetField(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.OBJECT_REF);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.TEMP_1, 4,
			ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_GETFIELD);
		PcodeTextEmitter.emitAssignVarnodeFromDereference(expected, ReferenceMethods.VALUE, 4,
			ReferenceMethods.TEMP_1);
		PcodeTextEmitter.emitPushCat1Value(expected, ReferenceMethods.VALUE);
		assertEquals(pCode, expected.toString());

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
		String pCode = ReferenceMethods.getPcodeForGetField(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.OBJECT_REF);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.TEMP_1, 8,
			ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_GETFIELD);
		PcodeTextEmitter.emitAssignVarnodeFromDereference(expected, ReferenceMethods.VALUE, 8,
			ReferenceMethods.TEMP_1);
		PcodeTextEmitter.emitPushCat2Value(expected, ReferenceMethods.VALUE);
		assertEquals(pCode, expected.toString());

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
		String pCode = ReferenceMethods.getPcodeForPutField(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.NEW_VALUE);
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.OBJECT_REF);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.FIELD_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_PUTFIELD);
		PcodeTextEmitter.emitWriteToMemory(expected, PcodeTextEmitter.RAM, 4,
			ReferenceMethods.FIELD_OFFSET, ReferenceMethods.NEW_VALUE);

		assertEquals(pCode, expected.toString());

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
		String pCode = ReferenceMethods.getPcodeForPutField(1, constantPool);

		StringBuilder expected = new StringBuilder();
		PcodeTextEmitter.emitPopCat2Value(expected, ReferenceMethods.NEW_VALUE);
		PcodeTextEmitter.emitPopCat1Value(expected, ReferenceMethods.OBJECT_REF);
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(expected, ReferenceMethods.FIELD_OFFSET,
			4, ConstantPoolJava.CPOOL_OP, ReferenceMethods.OBJECT_REF, "1",
			ConstantPoolJava.CPOOL_PUTFIELD);
		PcodeTextEmitter.emitWriteToMemory(expected, PcodeTextEmitter.RAM, 8,
			ReferenceMethods.FIELD_OFFSET, ReferenceMethods.NEW_VALUE);

		assertEquals(pCode, expected.toString());

	}

}
