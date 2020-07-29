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
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class InvokeMethodsTest extends AbstractGhidraHeadlessIntegrationTest {

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
	public void testEmitPcodeToResolveMethodReferenceInvokeDynamic() throws IOException {
		short bootstrap = 0;
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 5);
		TestClassFileCreator.appendInvokeDynamicInfo(classFile, bootstrap, (short) 2);      //1
		TestClassFileCreator.appendNameAndType(classFile, (short) 3, (short) 4);   //2
		TestClassFileCreator.appendUtf8(classFile, "dynamicMethodName");         //3
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //4 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		InvokeMethods.emitPcodeToResolveMethodReference(pCode, 1, constantPool,
			JavaInvocationType.INVOKE_DYNAMIC);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitAssignRegisterFromPcodeOpCall(InvokeMethods.CALL_TARGET,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_INVOKEDYNAMIC);
		assertEquals("incorrect pcode for dynamic invocation", expected, pCode);
	}

	@Test
	public void testEmitPcodeToResolveMethodReferenceInvokeInterface() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendInterfaceMethodRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                    //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);   //3
		TestClassFileCreator.appendUtf8(classFile, "className");                   //4
		TestClassFileCreator.appendUtf8(classFile, "interfaceMethodName");         //5
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		pCode.defineTemp(InvokeMethods.THIS, 4);
		InvokeMethods.emitPcodeToResolveMethodReference(pCode, 1, constantPool,
			JavaInvocationType.INVOKE_INTERFACE);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.defineTemp(InvokeMethods.THIS, 4);
		expected.emitAssignRegisterFromPcodeOpCall(InvokeMethods.CALL_TARGET,
			ConstantPoolJava.CPOOL_OP, InvokeMethods.THIS, "1",
			ConstantPoolJava.CPOOL_INVOKEINTERFACE);
		assertEquals("incorrect pcode for interface method invocation", expected, pCode);
	}

	@Test
	public void testEmitPcodeToResolveMethodReferenceInvokeSpecial() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendMethodRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                    //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);   //3
		TestClassFileCreator.appendUtf8(classFile, "className");                   //4
		TestClassFileCreator.appendUtf8(classFile, "methodName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		pCode.defineTemp(InvokeMethods.THIS, 4);
		InvokeMethods.emitPcodeToResolveMethodReference(pCode, 1, constantPool,
			JavaInvocationType.INVOKE_SPECIAL);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.defineTemp(InvokeMethods.THIS, 4);
		expected.emitAssignRegisterFromPcodeOpCall(InvokeMethods.CALL_TARGET,
			ConstantPoolJava.CPOOL_OP, InvokeMethods.THIS, "1",
			ConstantPoolJava.CPOOL_INVOKESPECIAL);
		assertEquals("incorrect pcode for special method invocation", expected, pCode);
	}

	@Test
	public void testEmitPcodeToResolveMethodReferenceInvokeStatic() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendMethodRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                    //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);   //3
		TestClassFileCreator.appendUtf8(classFile, "className");                   //4
		TestClassFileCreator.appendUtf8(classFile, "methodName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		InvokeMethods.emitPcodeToResolveMethodReference(pCode, 1, constantPool,
			JavaInvocationType.INVOKE_STATIC);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.emitAssignRegisterFromPcodeOpCall(InvokeMethods.CALL_TARGET,
			ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_INVOKESTATIC);
		assertEquals("incorrect pcode for static method invocation", expected, pCode);
	}

	@Test
	public void testEmitPcodeToResolveMethodReferenceInvokeVirtual() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 7);
		TestClassFileCreator.appendMethodRef(classFile, (short) 2, (short) 3);      //1
		TestClassFileCreator.appendClass(classFile, (short) 4);                    //2
		TestClassFileCreator.appendNameAndType(classFile, (short) 5, (short) 6);   //3
		TestClassFileCreator.appendUtf8(classFile, "className");                   //4
		TestClassFileCreator.appendUtf8(classFile, "methodName");                  //5
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //6 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		pCode.defineTemp(InvokeMethods.THIS, 4);
		InvokeMethods.emitPcodeToResolveMethodReference(pCode, 1, constantPool,
			JavaInvocationType.INVOKE_VIRTUAL);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		expected.defineTemp(InvokeMethods.THIS, 4);
		expected.emitAssignRegisterFromPcodeOpCall(InvokeMethods.CALL_TARGET,
			ConstantPoolJava.CPOOL_OP, InvokeMethods.THIS, "1",
			ConstantPoolJava.CPOOL_INVOKEVIRTUAL);
		assertEquals("incorrect pcode for static method invocation", expected, pCode);
	}

	@Test
	public void testEmitPcodeToReverseStackNoParamsNoThis() {
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		//InvokeMethods.emitPcodeToReverseStack(pCode, new ArrayList<JavaComputationalCategory>(), false);
		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		assertEquals("incorrect pcode reversing stack: no params no this", expected, pCode);
	}

	//test bad category

	@Test
	public void testGetPcodeForInvoke() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 5);
		TestClassFileCreator.appendInvokeDynamicInfo(classFile, (short) 0, (short) 2);      //1
		TestClassFileCreator.appendNameAndType(classFile, (short) 3, (short) 4);   //2
		TestClassFileCreator.appendUtf8(classFile, "dynamicMethodName");         //3
		TestClassFileCreator.appendUtf8(classFile, "(JJII)I");                         //4 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, opAddress, uniqueBase);
		InvokeMethods.getPcodeForInvoke(pCode, 1, constantPool, JavaInvocationType.INVOKE_DYNAMIC);

		PcodeOpEmitter expected = new PcodeOpEmitter(language, opAddress, uniqueBase);
		String descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_DYNAMIC);
		List<JavaComputationalCategory> categories =
			DescriptorDecoder.getParameterCategories(descriptor);

		InvokeMethods.emitPcodeToMoveParams(expected, categories, false, 24);
		InvokeMethods.emitPcodeToResolveMethodReference(expected, 1, constantPool,
			JavaInvocationType.INVOKE_DYNAMIC);
		expected.emitIndirectCall(InvokeMethods.CALL_TARGET);
		expected.emitPushCat1Value(InvokeMethods.CAT_1_RETURN);

		assertEquals("incorrect pcode for invoke dynamic: (JJII)I", expected, pCode);
	}

}
