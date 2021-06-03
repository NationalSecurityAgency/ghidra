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

/**
 * 
 * size of constant pool structures in bytes:
 * Class: 3
 * MethodRef: 5
 * String: 3
 * Integer: 5
 * Float: 5
 * Long: 9
 * Double: 9
 * Utf8: 
 *
 * Constant pool begins at offset 0xa of the class file
 */


public class LdcMethodsTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final int COUNT_LOW_BYTE = 9;
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
	public void testLdcInteger() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 2);
		TestClassFileCreator.appendInteger(classFile, 0x12345678);
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append an additional integer to the end of the constant pool and generate a reference to it
		classFile.set(COUNT_LOW_BYTE, (byte) 3);
		TestClassFileCreator.appendInteger(classFile, 0x11111111);
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 2, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "2", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcFloat() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 2);
		TestClassFileCreator.appendFloat(classFile, 2.0f);
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);

		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		//+1 to skip over the tag
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append an additional float to the end of the constant pool and generate a reference to it
		classFile.set(COUNT_LOW_BYTE, (byte) 3);
		TestClassFileCreator.appendFloat(classFile, 4.0f);
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);

		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 2, constantPool);
		//+1 for tag of first float, +4 for data of first float, +1 for tag of 2nd float
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "2", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcDouble() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 3);
		TestClassFileCreator.appendDouble(classFile, 2.0);
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		//+1 to skip over the tag
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 8,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC2_W);
		expectedPcode.emitPushCat2Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append an additional double to the end of the constant pool and generate a reference to it
		//doubles count as two elements in the constant pool!
		classFile.set(COUNT_LOW_BYTE, (byte) 5);
		TestClassFileCreator.appendDouble(classFile, 4.0);
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 3, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 8,
			ConstantPoolJava.CPOOL_OP, "0", "3", ConstantPoolJava.CPOOL_LDC2_W);
		expectedPcode.emitPushCat2Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcLong() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 3);
		TestClassFileCreator.appendLong(classFile, 0x123456789l);
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 8,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC2_W);
		expectedPcode.emitPushCat2Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append an additional long to the end of the constant pool and generate a reference to it
		//longs count as two elements in the constant pool!
		classFile.set(COUNT_LOW_BYTE, (byte) 5);
		TestClassFileCreator.appendLong(classFile, 0x1111111111l);
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 3, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 8,
			ConstantPoolJava.CPOOL_OP, "0", "3", ConstantPoolJava.CPOOL_LDC2_W);
		expectedPcode.emitPushCat2Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcString() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 3);
		TestClassFileCreator.appendString(classFile, (short) 2);
		TestClassFileCreator.appendUtf8(classFile, "input1");
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);	
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append additional string, utf8 element to the end of the constant pool and generate a reference 
		//character string
		classFile.set(COUNT_LOW_BYTE, (byte) 5);
		TestClassFileCreator.appendString(classFile, (short) 4);
		TestClassFileCreator.appendUtf8(classFile, "input2");
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 3, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "3", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcClass() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile,(short) 3);
		TestClassFileCreator.appendClass(classFile, (short) 2);
		TestClassFileCreator.appendUtf8(classFile, "Ljava/lang/Integer;");
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);	
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);

		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append additional class, utf8 element to the end of the constant pool and generate a reference 
		//character string
		classFile.set(COUNT_LOW_BYTE, (byte) 5);
		TestClassFileCreator.appendClass(classFile, (short) 4);
		TestClassFileCreator.appendUtf8(classFile, "Ljava/lang/String;");
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 3, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "3", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}

	@Test
	public void testLdcMethodType() throws IOException{
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 3);
		TestClassFileCreator.appendMethodType(classFile, (short) 2);
		TestClassFileCreator.appendUtf8(classFile, "(I)Ljava/lang/Integer;");
		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);	
		AbstractConstantPoolInfoJava[] constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 1, constantPool);
		//+1 to skip over the tag of the MethodType element
		//+2 to skip over data of MethodType element (2-byte ref to utf8 element)
		//+1 to skip over tag of utf8 element
		//+2 to skip over length of utf8 element
		PcodeOpEmitter expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);

		//append additional MethodType, utf8 element to the end of the constant pool and generate a reference 
		//character string
		classFile.set(COUNT_LOW_BYTE, (byte) 5);
		TestClassFileCreator.appendMethodType(classFile, (short) 4);
		TestClassFileCreator.appendUtf8(classFile, "(I)Ljava/lang/Integer;");
		classFileBytes = TestClassFileCreator.getByteArray(classFile);
		constantPool = TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		LdcMethods.getPcodeForLdc(pCode, 3, constantPool);
		expectedPcode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expectedPcode.emitAssignVarnodeFromPcodeOpCall(LdcMethods.VALUE, 4,
			ConstantPoolJava.CPOOL_OP, "0", "3", ConstantPoolJava.CPOOL_LDC);
		expectedPcode.emitPushCat1Value(LdcMethods.VALUE);
		assertEquals(pCode, expectedPcode);
	}





}


