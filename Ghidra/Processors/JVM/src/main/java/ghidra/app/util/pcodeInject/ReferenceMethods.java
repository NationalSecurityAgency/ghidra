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

import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.javaclass.format.constantpool.*;

/**
 * 
 * This class contains methods to produce pcode for the getstatic, putstatic 
 * getfield, and putfield instructions.
 * 
 * This class is a non-instantiable utility class.
 * 
 * In .class files, a getstatic, getfield, putstatic, or putfield instruction is 
 * followed by a two-byte index into the constant pool. At that index is a symbolic 
 * reference to a field, which ultimately yields the class, the field name, and the 
 * JVM type of the element to be gotten or put. 
 */

public class ReferenceMethods {

	static final String VALUE = "value";
	static final String TEMP_1 = "temp_1";
	static final String TEMP_2 = "temp_2";
	static final String NEW_VALUE = "newValue";
	static final String OBJECT_REF = "objectRef";
	static final String FIELD_OFFSET = "fieldOffset";
	static final String STATIC_OFFSET = "staticOffset";

	//private constructor to enforce noninstantiability
	private ReferenceMethods() {
		throw new AssertionError();
	}

	/**
	 * Generate a String of pcode for a getstatic op.
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool of the class file
	 * @return - the pcode string
	 */
	public static String getPcodeForGetStatic(int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		StringBuilder pCode = new StringBuilder();
		//determine the computational category and push a value of the correct size onto the operand stack
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 1, TEMP_1);
				PcodeTextEmitter.emitSignExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 1, TEMP_1);
				PcodeTextEmitter.emitZeroExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 2, TEMP_1);
				PcodeTextEmitter.emitZeroExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 2, TEMP_1);
				PcodeTextEmitter.emitSignExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, VALUE, 4, TEMP_1);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 8,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, VALUE, 8, TEMP_1);
				PcodeTextEmitter.emitPushCat2Value(pCode, VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
		return pCode.toString();
	}

	/**
	 * Generate a String of pcode for a putstatic op.
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool of the class file
	 * @return - the pcode string
	 */
	public static String getPcodeForPutStatic(int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		StringBuilder pCode = new StringBuilder();
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 1, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 1, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 1, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 1, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 2, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 2, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 2, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 2, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 4, STATIC_OFFSET,
					NEW_VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				PcodeTextEmitter.emitPopCat2Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 8, STATIC_OFFSET,
					NEW_VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
		return pCode.toString();
	}

	/**
	 * Generate pcode for a getfield op
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool
	 * @return - the pcode string
	 */
	public static String getPcodeForGetField(int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		StringBuilder pCode = new StringBuilder();

		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 1, TEMP_1);
				PcodeTextEmitter.emitSignExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 1, TEMP_1);
				PcodeTextEmitter.emitZeroExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 2, TEMP_1);
				PcodeTextEmitter.emitZeroExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, TEMP_2, 2, TEMP_1);
				PcodeTextEmitter.emitSignExtension(pCode, VALUE, 4, TEMP_2);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, VALUE, 4, TEMP_1);
				PcodeTextEmitter.emitPushCat1Value(pCode, VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, TEMP_1, 8,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, VALUE, 8, TEMP_1);
				PcodeTextEmitter.emitPushCat2Value(pCode, VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
		return pCode.toString();
	}

	/**
	 * Generate pcode for a putfield op
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool
	 * @return - the pcode
	 */
	public static String getPcodeForPutField(int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		StringBuilder pCode = new StringBuilder();

		//determine the computational category and push a value of the correct size onto the operand stack
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 1, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 1, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 1, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 1, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 2, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 2, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitTruncate(pCode, TEMP_1, 2, NEW_VALUE);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 2, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 4, FIELD_OFFSET,
					NEW_VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				PcodeTextEmitter.emitPopCat2Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 8, FIELD_OFFSET,
					NEW_VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
		return pCode.toString();

		/*JavaComputationalCategory category = DescriptorDecoder.getComputationalCategoryOfDescriptor(descriptor);
		switch (category){
			case CAT_1:
				//top of operand stack is NEW_VALUE, the new value for the field
				//next on stack is OBJECT_REF, a pointer to the object whose field is to be modified
				PcodeTextEmitter.emitPopCat1Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4, ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index), ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 4, FIELD_OFFSET, NEW_VALUE);
				break;
			case CAT_2:
				PcodeTextEmitter.emitPopCat2Value(pCode, NEW_VALUE);
				PcodeTextEmitter.emitPopCat1Value(pCode, OBJECT_REF);
				PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, FIELD_OFFSET, 4, ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index), ConstantPoolJava.CPOOL_PUTFIELD);
				PcodeTextEmitter.emitWriteToMemory(pCode, PcodeTextEmitter.RAM, 8, FIELD_OFFSET, NEW_VALUE);
				break;
			default:
				throw new IllegalArgumentException("Bad computational category for descriptor " + descriptor);
		}
		return pCode.toString();*/
	}

	/**
	 * Returns the descriptor of a field reference in the constant pool
	 * @param constantPool
	 * @param index
	 * @return
	 */
	static String getDescriptorForFieldRef(AbstractConstantPoolInfoJava[] constantPool, int index) {
		ConstantPoolFieldReferenceInfo fieldRef =
			(ConstantPoolFieldReferenceInfo) constantPool[index];
		int nameAndTypeIndex = fieldRef.getNameAndTypeIndex();
		ConstantPoolNameAndTypeInfo nameAndTypeInfo =
			(ConstantPoolNameAndTypeInfo) constantPool[nameAndTypeIndex];
		ConstantPoolUtf8Info descriptorInfo =
			(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];
		return descriptorInfo.getString();
	}

}
