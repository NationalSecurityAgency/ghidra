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
package ghidra.javaclass.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.pcodeInject.*;
import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.data.*;

public class DescriptorDecoderTest extends AbstractGenericTest {
	DataTypeManager dtm;
	DataType dtInteger;

	@Before
	public void setUp() {
		dtm = new StandAloneDataTypeManager("");
		int transactionID = dtm.startTransaction(null);
		dtInteger = DescriptorDecoder.resolveClassForString("java/lang/Integer", dtm,
			DWordDataType.dataType);
		DescriptorDecoder.resolveClassForString("JVM_primitives/byte", dtm,
			SignedByteDataType.dataType);
		DescriptorDecoder.resolveClassForString("JVM_primitives/boolean", dtm,
			BooleanDataType.dataType);
		dtm.endTransaction(transactionID, true);
	}

	@Test
	public void testGetComputationalCategoryOfDescriptor() {
		//test type 1 descriptors
		JavaComputationalCategory cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("B");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("C");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("F");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("I");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("L");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("Ljava/lang/Integer;");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("S");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("Z");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("[I");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("[[I");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("[Ljava/lang/Integer;");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_1));
		//test type 2
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("D");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_2));
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("J");
		assertTrue(cat.equals(JavaComputationalCategory.CAT_2));
		//test void
		cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("V");
		assertTrue(cat.equals(JavaComputationalCategory.VOID));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testUnknownDescriptor() {
		@SuppressWarnings("unused")
		JavaComputationalCategory cat = DescriptorDecoder.getComputationalCategoryOfDescriptor("X");
	}

	@Test
	public void testGetStackPurgeAndReturnCategory() {
		String ItoInt = "(I)Ljava/lang/Integer;";
		int expectedStackPurge = PcodeInjectLibraryJava.REFERENCE_SIZE;
		JavaComputationalCategory expectedReturn = JavaComputationalCategory.CAT_1;

		int computedStackPurge = DescriptorDecoder.getStackPurge(ItoInt);
		assertTrue(computedStackPurge == expectedStackPurge);
		JavaComputationalCategory returnCat =
			DescriptorDecoder.getReturnCategoryOfMethodDescriptor(ItoInt);
		assertTrue(returnCat.equals(expectedReturn));

		String IntIntInttoInt =
			"(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)Ljava/lang/Integer;";
		expectedStackPurge = 3 * PcodeInjectLibraryJava.REFERENCE_SIZE;
		expectedReturn = JavaComputationalCategory.CAT_1;

		computedStackPurge = DescriptorDecoder.getStackPurge(IntIntInttoInt);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(IntIntInttoInt);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String voidTovoid = "()V";
		expectedStackPurge = 0;
		expectedReturn = JavaComputationalCategory.VOID;

		computedStackPurge = DescriptorDecoder.getStackPurge(voidTovoid);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(voidTovoid);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String ItoI = "(I)I";
		expectedStackPurge = PcodeInjectLibraryJava.REFERENCE_SIZE;
		expectedReturn = JavaComputationalCategory.CAT_1;

		computedStackPurge = DescriptorDecoder.getStackPurge(ItoI);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(ItoI);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String OneDIntTwoDInttoInt =
			"([Ljava/lang/Integer;[[Ljava/lang/Integer;)Ljava/lang/Integer;";
		expectedStackPurge = 2 * PcodeInjectLibraryJava.REFERENCE_SIZE;
		expectedReturn = JavaComputationalCategory.CAT_1;

		computedStackPurge = DescriptorDecoder.getStackPurge(OneDIntTwoDInttoInt);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(OneDIntTwoDInttoInt);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String DDtoD = "(DD)D";
		expectedStackPurge =
			2 * PcodeInjectLibraryJava.REFERENCE_SIZE + 2 * PcodeInjectLibraryJava.REFERENCE_SIZE;
		expectedReturn = JavaComputationalCategory.CAT_2;

		computedStackPurge = DescriptorDecoder.getStackPurge(DDtoD);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(DDtoD);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String crazy = "(DJLjava/lang/Integer;[[Ljava/lang/Integer;)[[Ljava/lang/Integer;";
		expectedStackPurge = 6 * PcodeInjectLibraryJava.REFERENCE_SIZE;
		expectedReturn = JavaComputationalCategory.CAT_1;

		computedStackPurge = DescriptorDecoder.getStackPurge(crazy);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(crazy);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));

		String getClass = "()Ljava/lang/Class";
		expectedStackPurge = 0;
		expectedReturn = JavaComputationalCategory.CAT_1;

		computedStackPurge = DescriptorDecoder.getStackPurge(getClass);
		returnCat = DescriptorDecoder.getReturnCategoryOfMethodDescriptor(getClass);
		assertTrue(computedStackPurge == expectedStackPurge);
		assertTrue(returnCat.equals(expectedReturn));
	}

	@Test
	public void testGetParameterCategories() {
		String ItoInt = "(I)Ljava/lang/Integer;";
		List<JavaComputationalCategory> expectedList = new ArrayList<>();
		expectedList.add(JavaComputationalCategory.CAT_1);
		List<JavaComputationalCategory> computedList =
			DescriptorDecoder.getParameterCategories(ItoInt);
		assertTrue(expectedList.equals(computedList));

		String IntIntInttoInt =
			"(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)Ljava/lang/Integer;";
		expectedList.removeAll(expectedList);
		expectedList.add(JavaComputationalCategory.CAT_1);
		expectedList.add(JavaComputationalCategory.CAT_1);
		expectedList.add(JavaComputationalCategory.CAT_1);
		computedList = DescriptorDecoder.getParameterCategories(IntIntInttoInt);
		assertTrue(expectedList.equals(computedList));

		String voidTovoid = "()V";
		expectedList.removeAll(expectedList);
		computedList = DescriptorDecoder.getParameterCategories(voidTovoid);
		assertTrue(expectedList.equals(computedList));

		String IDItoI = "(IDI)I";
		expectedList.removeAll(expectedList);
		expectedList.add(JavaComputationalCategory.CAT_1);
		expectedList.add(JavaComputationalCategory.CAT_2);
		expectedList.add(JavaComputationalCategory.CAT_1);
		computedList = DescriptorDecoder.getParameterCategories(IDItoI);
		assertTrue(expectedList.equals(computedList));

		String OneDIntTwoDInttoInt =
			"([Ljava/lang/Integer;[[Ljava/lang/Integer;)Ljava/lang/Integer;";
		expectedList.removeAll(expectedList);
		expectedList.add(JavaComputationalCategory.CAT_1);
		expectedList.add(JavaComputationalCategory.CAT_1);
		computedList = DescriptorDecoder.getParameterCategories(OneDIntTwoDInttoInt);
		assertTrue(expectedList.equals(computedList));

		String DDtoD = "(DD)D";
		expectedList.removeAll(expectedList);
		expectedList.add(JavaComputationalCategory.CAT_2);
		expectedList.add(JavaComputationalCategory.CAT_2);
		computedList = DescriptorDecoder.getParameterCategories(DDtoD);
		assertTrue(expectedList.equals(computedList));

		String crazy = "(DJLjava/lang/Integer;[[Ljava/lang/Integer;)[[Ljava/lang/Integer;";
		expectedList.removeAll(expectedList);
		expectedList.add(JavaComputationalCategory.CAT_2);
		expectedList.add(JavaComputationalCategory.CAT_2);
		expectedList.add(JavaComputationalCategory.CAT_1);
		expectedList.add(JavaComputationalCategory.CAT_1);
		computedList = DescriptorDecoder.getParameterCategories(crazy);
		assertTrue(expectedList.equals(computedList));

		String getClass = "()Ljava/lang/Class";
		computedList = DescriptorDecoder.getParameterCategories(getClass);
		expectedList.removeAll(expectedList);
		assertTrue(expectedList.equals(computedList));
	}

	@Test
	public void testGetDataTypeOfDescriptor() {

		DataType computedType = DescriptorDecoder.getDataTypeOfDescriptor("B", dtm);
		DataType expectedType = SignedByteDataType.dataType;
		assertTrue(computedType.equals(expectedType));

		computedType = DescriptorDecoder.getDataTypeOfDescriptor("Z", dtm);
		expectedType = BooleanDataType.dataType;
		assertTrue(computedType.equals(expectedType));

		computedType = DescriptorDecoder.getDataTypeOfDescriptor("C", dtm);
		assertTrue(computedType.equals(CharDataType.dataType));

		computedType = DescriptorDecoder.getDataTypeOfDescriptor("S", dtm);
		assertTrue(computedType.equals(ShortDataType.dataType));

		computedType = DescriptorDecoder.getDataTypeOfDescriptor("I", dtm);
		assertTrue(computedType.equals(IntegerDataType.dataType));

		String floatDescriptor = "F";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(floatDescriptor, dtm);
		assertTrue(computedType.equals(FloatDataType.dataType));

		String arrayDescriptor = "[I";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(arrayDescriptor, dtm);
		assertTrue(computedType.equals(dtm.getPointer(IntegerDataType.dataType)));

		String referenceDescriptor = "Ljava/lang/Integer;";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(referenceDescriptor, dtm);
		DataType intRef = new PointerDataType(dtInteger);
		assertTrue(computedType.equals(intRef));

		String doubleDescriptor = "D";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(doubleDescriptor, dtm);
		assertTrue(computedType.equals(DoubleDataType.dataType));

		String longDescriptor = "J";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(longDescriptor, dtm);
		assertTrue(computedType.equals(LongDataType.dataType));

		String voidDescriptor = "V";
		computedType = DescriptorDecoder.getDataTypeOfDescriptor(voidDescriptor, dtm);
		assertTrue(computedType.equals(DataType.VOID));
	}

	@Test
	public void testGetDataTypeList() {
		String comprehensive = "(BZCSIF[[ILjava/lang/Integer;DJ)Ljava/lang/Integer;";
		List<DataType> computedList = DescriptorDecoder.getDataTypeList(comprehensive, dtm);
		List<DataType> expectedList = new ArrayList<>();
		expectedList.add(SignedByteDataType.dataType);
		expectedList.add(BooleanDataType.dataType);
		expectedList.add(CharDataType.dataType);
		expectedList.add(ShortDataType.dataType);
		expectedList.add(IntegerDataType.dataType);
		expectedList.add(FloatDataType.dataType);
		expectedList.add(dtm.getPointer(IntegerDataType.dataType));
		expectedList.add(dtm.getPointer(dtInteger));
		expectedList.add(DoubleDataType.dataType);
		expectedList.add(LongDataType.dataType);
		for (int i = 0, max = Integer.max(expectedList.size(), computedList.size()); i < max; ++i) {
			assertTrue(computedList.get(i).isEquivalent(expectedList.get(i)));
		}

		String voidTovoid = "()V";
		expectedList.clear();
		computedList = DescriptorDecoder.getDataTypeList(voidTovoid, null);
		assertTrue(expectedList.equals(computedList));
	}

	@Test
	public void testGetDescriptorForInvokeMethodRef() throws IOException {
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

		String descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_VIRTUAL);
		String err = "returned " + descriptor + " instead of (I)I for " +
			JavaInvocationType.INVOKE_VIRTUAL.name();
		assertEquals(err, descriptor, "(I)I");

		descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_STATIC);
		err = "returned " + descriptor + " instead of (I)I for " +
			JavaInvocationType.INVOKE_STATIC.name();
		assertEquals(err, descriptor, "(I)I");

		descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_SPECIAL);
		err = "returned " + descriptor + " instead of (I)I for " +
			JavaInvocationType.INVOKE_SPECIAL.name();
		assertEquals(err, descriptor, "(I)I");
	}

	@Test
	public void testGetDescriptorForInvokeInterfaceMethodRef() throws IOException {
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

		String descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_INTERFACE);
		String err = "returned " + descriptor + " instead of (I)I for " +
			JavaInvocationType.INVOKE_INTERFACE.name();
		assertEquals(err, descriptor, "(I)I");
	}

	@Test
	public void testGetDescriptorForInvokeDynamicRef() throws IOException {
		ArrayList<Byte> classFile = new ArrayList<>();
		TestClassFileCreator.appendMagic(classFile);
		TestClassFileCreator.appendVersions(classFile);
		TestClassFileCreator.appendCount(classFile, (short) 5);
		TestClassFileCreator.appendInvokeDynamicInfo(classFile, (short) 0, (short) 2);      //1
		TestClassFileCreator.appendNameAndType(classFile, (short) 3, (short) 4);   //2
		TestClassFileCreator.appendUtf8(classFile, "dynamicMethodName");         //3
		TestClassFileCreator.appendUtf8(classFile, "(I)I");                         //4 (descriptor)

		byte[] classFileBytes = TestClassFileCreator.getByteArray(classFile);
		AbstractConstantPoolInfoJava[] constantPool =
			TestClassFileCreator.getConstantPoolFromBytes(classFileBytes);

		String descriptor = DescriptorDecoder.getDescriptorForInvoke(1, constantPool,
			JavaInvocationType.INVOKE_DYNAMIC);
		String err = "returned " + descriptor + " instead of (I)I for " +
			JavaInvocationType.INVOKE_DYNAMIC.name();
		assertEquals(err, descriptor, "(I)I");
	}

	@Test
	public void testGetTypeNameForDescriptor() {
		assertEquals("byte", DescriptorDecoder.getTypeNameFromDescriptor("B", false, true));
		assertEquals("char", DescriptorDecoder.getTypeNameFromDescriptor("C", false, true));
		assertEquals("float", DescriptorDecoder.getTypeNameFromDescriptor("F", false, true));
		assertEquals("int", DescriptorDecoder.getTypeNameFromDescriptor("I", false, true));
		assertEquals("short", DescriptorDecoder.getTypeNameFromDescriptor("S", false, true));
		assertEquals("boolean", DescriptorDecoder.getTypeNameFromDescriptor("Z", false, true));
		assertEquals("double", DescriptorDecoder.getTypeNameFromDescriptor("D", false, true));
		assertEquals("long", DescriptorDecoder.getTypeNameFromDescriptor("J", false, true));
		assertEquals("void", DescriptorDecoder.getTypeNameFromDescriptor("V", false, true));
		assertEquals("java.lang.Integer",
			DescriptorDecoder.getTypeNameFromDescriptor("Ljava/lang/Integer;", true, true));
		assertEquals("Integer",
			DescriptorDecoder.getTypeNameFromDescriptor("Ljava/lang/Integer;", false, true));
		assertEquals("Integer[][][]",
			DescriptorDecoder.getTypeNameFromDescriptor("[[[Ljava/lang/Integer;", false, true));
		assertEquals("java.lang.Integer[][][]",
			DescriptorDecoder.getTypeNameFromDescriptor("[[[Ljava/lang/Integer;", true, true));

		assertEquals("java/lang/Integer",
			DescriptorDecoder.getTypeNameFromDescriptor("Ljava/lang/Integer;", true, false));
		assertEquals("Integer",
			DescriptorDecoder.getTypeNameFromDescriptor("Ljava/lang/Integer;", false, false));
		assertEquals("Integer[][][]",
			DescriptorDecoder.getTypeNameFromDescriptor("[[[Ljava/lang/Integer;", false, false));
		assertEquals("java/lang/Integer[][][]",
			DescriptorDecoder.getTypeNameFromDescriptor("[[[Ljava/lang/Integer;", true, false));
	}

	@Test
	public void testGetTypeNameList() {
		String methodDescriptor = "(I)I";
		List<String> typeNames = DescriptorDecoder.getTypeNameList(methodDescriptor, false, true);
		assertEquals("int", typeNames.get(0));
		assertEquals("int", typeNames.get(1));

		methodDescriptor = "()V";
		typeNames = DescriptorDecoder.getTypeNameList(methodDescriptor, false, true);
		assertEquals("void", typeNames.get(0));

		methodDescriptor = "(JLjava/lang/Integer;[[[I)[[[Ljava/lang/Integer;";
		typeNames = DescriptorDecoder.getTypeNameList(methodDescriptor, true, true);
		assertEquals("long", typeNames.get(0));
		assertEquals("java.lang.Integer", typeNames.get(1));
		assertEquals("int[][][]", typeNames.get(2));
		assertEquals("java.lang.Integer[][][]", typeNames.get(3));

		typeNames = DescriptorDecoder.getTypeNameList(methodDescriptor, false, true);
		assertEquals("long", typeNames.get(0));
		assertEquals("Integer", typeNames.get(1));
		assertEquals("int[][][]", typeNames.get(2));
		assertEquals("Integer[][][]", typeNames.get(3));
	}

	@Test
	public void testGetReturnTypeOfMethodDescriptor() {
		String ItoInt = "(I)Ljava/lang/Integer;";

		DataType type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(ItoInt, dtm);
		assertEquals(new PointerDataType(dtInteger), type);

		String IntIntInttoInt =
			"(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)Ljava/lang/Integer;";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(IntIntInttoInt, dtm);
		assertEquals(new PointerDataType(dtInteger), type);

		String voidTovoid = "()V";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(voidTovoid, dtm);
		assertEquals(DataType.VOID, type);

		String ItoI = "(I)I";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(ItoI, dtm);
		assertEquals(IntegerDataType.dataType, type);

		String OneDIntTwoDInttoInt =
			"([Ljava/lang/Integer;[[Ljava/lang/Integer;)Ljava/lang/Integer;";

		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(OneDIntTwoDInttoInt, dtm);
		assertEquals(new PointerDataType(dtInteger), type);

		String DDtoD = "(DD)D";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(DDtoD, dtm);
		assertEquals(DoubleDataType.dataType, type);

		String crazy = "(DJLjava/lang/Integer;[[Ljava/lang/Integer;)[[Ljava/lang/Integer;";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(crazy, dtm);
		assertEquals(dtm.getPointer(DWordDataType.dataType), type);

		String getClass = "()Ljava/lang/Class";
		type = DescriptorDecoder.getReturnTypeOfMethodDescriptor(getClass, dtm);
		assertEquals(PointerDataType.dataType, type);
	}

	@Test
	public void testGetParameterString() {
		String ItoInt = "(I)Ljava/lang/Integer;";

		String paramString = DescriptorDecoder.getParameterString(ItoInt);
		assertEquals("(int)", paramString);

		String IntIntInttoInt =
			"(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)Ljava/lang/Integer;";
		paramString = DescriptorDecoder.getParameterString(IntIntInttoInt);
		assertEquals("(java.lang.Integer, java.lang.Integer, java.lang.Integer)", paramString);

		String voidToVoid = "()V";
		paramString = DescriptorDecoder.getParameterString(voidToVoid);
		assertEquals("()", paramString);

		String ItoI = "(I)I";
		paramString = DescriptorDecoder.getParameterString(ItoI);
		assertEquals("(int)", paramString);

		String OneDIntTwoDInttoInt =
			"([Ljava/lang/Integer;[[Ljava/lang/Integer;)Ljava/lang/Integer;";

		paramString = DescriptorDecoder.getParameterString(OneDIntTwoDInttoInt);
		assertEquals("(java.lang.Integer[], java.lang.Integer[][])", paramString);

		String DDtoD = "(DD)D";
		paramString = DescriptorDecoder.getParameterString(DDtoD);
		assertEquals("(double, double)", paramString);

		String crazy = "(DJLjava/lang/Integer;[[Ljava/lang/Integer;)[[Ljava/lang/Integer;";
		paramString = DescriptorDecoder.getParameterString(crazy);
		assertEquals("(double, long, java.lang.Integer, java.lang.Integer[][])", paramString);
	}

}
