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
	 * @param pCode is the pcode accumulator
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool of the class file
	 */
	public static void getPcodeForGetStatic(PcodeOpEmitter pCode, int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		//determine the computational category and push a value of the correct size onto the operand stack
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 1, TEMP_1);
				pCode.emitSignExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 1, TEMP_1);
				pCode.emitZeroExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 2, TEMP_1);
				pCode.emitZeroExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 2, TEMP_1);
				pCode.emitSignExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(VALUE, 4, TEMP_1);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 8,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_GETSTATIC);
				pCode.emitAssignVarnodeFromDereference(VALUE, 8, TEMP_1);
				pCode.emitPushCat2Value(VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
	}

	/**
	 * Generate a String of pcode for a putstatic op.
	 * @param pCode is the pcode accumulator
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool of the class file
	 */
	public static void getPcodeForPutStatic(PcodeOpEmitter pCode, int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitTruncate(TEMP_1, 1, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 1, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitTruncate(TEMP_1, 1, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 1, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitTruncate(TEMP_1, 2, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 2, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitTruncate(TEMP_1, 2, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 2, STATIC_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 4, STATIC_OFFSET,
					NEW_VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				pCode.emitPopCat2Value(NEW_VALUE);
				pCode.emitAssignVarnodeFromPcodeOpCall(STATIC_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, "0", Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTSTATIC);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 8, STATIC_OFFSET,
					NEW_VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
	}

	/**
	 * Generate pcode for a getfield op
	 * @param pCode is the pcode accumulator
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool
	 */
	public static void getPcodeForGetField(PcodeOpEmitter pCode, int index,
			AbstractConstantPoolInfoJava[] constantPool) {

		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 1, TEMP_1);
				pCode.emitSignExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 1,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 1, TEMP_1);
				pCode.emitZeroExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 2, TEMP_1);
				pCode.emitZeroExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 2,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(TEMP_2, 2, TEMP_1);
				pCode.emitSignExtension(VALUE, 4, TEMP_2);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(VALUE, 4, TEMP_1);
				pCode.emitPushCat1Value(VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(TEMP_1, 8,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_GETFIELD);
				pCode.emitAssignVarnodeFromDereference(VALUE, 8, TEMP_1);
				pCode.emitPushCat2Value(VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}
	}

	/**
	 * Generate pcode for a putfield op
	 * @param pCode is the pcode accumulator
	 * @param index - the index of the field reference in the constant pool
	 * @param constantPool - the constant pool
	 */
	public static void getPcodeForPutField(PcodeOpEmitter pCode, int index,
			AbstractConstantPoolInfoJava[] constantPool) {
		//determine the computational category and push a value of the correct size onto the operand stack
		String descriptor = getDescriptorForFieldRef(constantPool, index);

		switch (descriptor.charAt(0)) {
			case DescriptorDecoder.BASE_TYPE_BYTE:  //signed byte
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitTruncate(TEMP_1, 1, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 1, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_BOOLEAN:  //boolean
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitTruncate(TEMP_1, 1, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 1, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_CHAR:  //char
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitTruncate(TEMP_1, 2, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 2, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_SHORT:  //signed short
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitTruncate(TEMP_1, 2, NEW_VALUE);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 2, FIELD_OFFSET,
					TEMP_1);
				break;
			case DescriptorDecoder.BASE_TYPE_ARRAY:  //array dimension
			case DescriptorDecoder.BASE_TYPE_FLOAT:  //float
			case DescriptorDecoder.BASE_TYPE_INT:  //int
			case DescriptorDecoder.BASE_TYPE_REFERENCE:  //object reference
				pCode.emitPopCat1Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 4, FIELD_OFFSET,
					NEW_VALUE);
				break;
			case DescriptorDecoder.BASE_TYPE_DOUBLE:  //double
			case DescriptorDecoder.BASE_TYPE_LONG:  //long
				pCode.emitPopCat2Value(NEW_VALUE);
				pCode.emitPopCat1Value(OBJECT_REF);
				pCode.emitAssignVarnodeFromPcodeOpCall(FIELD_OFFSET, 4,
					ConstantPoolJava.CPOOL_OP, OBJECT_REF, Integer.toString(index),
					ConstantPoolJava.CPOOL_PUTFIELD);
				pCode.emitWriteToMemory(PcodeOpEmitter.RAM, 8, FIELD_OFFSET,
					NEW_VALUE);
				break;
			default:
				throw new IllegalArgumentException("Invalid descriptor: " + descriptor);
		}

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
