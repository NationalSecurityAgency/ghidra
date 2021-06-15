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
import ghidra.javaclass.format.JavaClassConstants;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * 
 * This is a utility class for generating pcode for the multianewarray operation.
 * Note that the newarray operation, which creates arrays of primitive types, does not
 * reference the constant pool and does not require pcode injection (but see 
 * ConstantPoolJava.getRecord()
 *
 */


public class ArrayMethods {

	static final String ARRAY_REF = "arrayref";
	static final String CLASS_NAME = "className";
	static final String DIMENSION = "dim";
	static final String MULTIANEWARRAY = "multianewarrayOp";
	static final String PROCESS_ADDITIONAL_DIMENSIONS = "multianewarrayProcessAdditionalDimensionsOp";
	static final int MAX_PCODE_OP_ARGS = 7;

	//private constructor to enforce noninstantiability
	private ArrayMethods(){
		throw new AssertionError();
	}
	
	/**
	 * Emits pcode for the multianewarray op, which is used to create new multi-dimensional arrays
	 * It is modeled with two black-box pcode ops: multianewarrayOp and multianewarrayProcessAdditionalDimensionsOp.
	 * The second op is need because pcode operations are limited to 8 input parameters, whereas multianewarray 
	 * takes between 1 and 256 parameters.  
	 * 
	 * The first argument to multianewarrayOp is a reference to the class of the new array.  The remaining seven arguments
	 * are array dimensions.  Additional array dimensions are consumed from the stack with calls to 
	 * multianewarrayProcessAdditionalDimensionsOp, which takes a reference returned by multianewarrayOp as its first argument 
	 * and a dimension as its second argument.
	 * @param pCode is the pcode accumulator
	 * @param constantPoolIndex
	 * @param constantPool
	 * @param dimensions
	 */
	public static void getPcodeForMultiANewArray(PcodeOpEmitter pCode, int constantPoolIndex,
			AbstractConstantPoolInfoJava[] constantPool,
			int dimensions) {
		//pop all of the dimensions off the stack
		for (int i = dimensions; i >= 1; --i){
			String iAsString = Integer.toString(i);
			pCode.emitPopCat1Value(DIMENSION + iAsString);
		}
		
		pCode.emitAssignVarnodeFromPcodeOpCall(CLASS_NAME, 4, ConstantPoolJava.CPOOL_OP, "0",
			Integer.toString(constantPoolIndex), ConstantPoolJava.CPOOL_MULTIANEWARRAY);


		//emit the call to multianewarrayOp
		String[] multianewarrayOpArgs = null;

		//if clause: more dimension arguments than will fit in a call to multianewarrayOp
		//-1 since the first argument will be a reference to the class name
		if (dimensions > (MAX_PCODE_OP_ARGS -1) ){
			multianewarrayOpArgs = new String[MAX_PCODE_OP_ARGS];
			multianewarrayOpArgs[0] = CLASS_NAME;
			for (int i = 1; i < MAX_PCODE_OP_ARGS; ++i){
				multianewarrayOpArgs[i] = DIMENSION + Integer.toString(i);
			}
		}
		else {
			//+1 for the class reference
			multianewarrayOpArgs = new String[dimensions + 1];
			multianewarrayOpArgs[0] = CLASS_NAME;
			for (int i = 1; i < dimensions + 1; ++i){
				multianewarrayOpArgs[i] = DIMENSION + Integer.toString(i);
			}
		}
		pCode.emitAssignVarnodeFromPcodeOpCall(ARRAY_REF, 4, MULTIANEWARRAY, CLASS_NAME, "dim1",
			"dim2");
		


		//consume any additional arguments
		for (int i = MAX_PCODE_OP_ARGS; i <= dimensions; ++i){
			String[] args = {ARRAY_REF, DIMENSION + Integer.toString(i)};
			pCode.emitVoidPcodeOpCall(PROCESS_ADDITIONAL_DIMENSIONS, args);
		}

		pCode.emitPushCat1Value(ARRAY_REF);
	}
	/**
	 * The array type codes can be found in the JVM documentation for the 
	 * "newarray" instruction.
	 * @param code
	 * @return
	 */
	public static String getPrimitiveArrayToken(int code){
		switch(code){
			case JavaClassConstants.T_BOOLEAN:
				return "boolean";
			case JavaClassConstants.T_CHAR:
				return "char";
			case JavaClassConstants.T_FLOAT:
				return "float";
			case JavaClassConstants.T_DOUBLE:
				return "double";
			case JavaClassConstants.T_BYTE:
				return "byte";
			case JavaClassConstants.T_SHORT:
				return "short";
			case JavaClassConstants.T_INT:
				return "int";
			case JavaClassConstants.T_LONG:
				return "long";
			default:
				throw new IllegalArgumentException("Invalid primitive type code: " + code);
		}
	}
	public static DataType getArrayBaseType(int i, DataTypeManager dtManager) {
		String primitiveType = null;
		switch(i){
			case JavaClassConstants.T_BOOLEAN:
				primitiveType = "Z";
				break;
			case JavaClassConstants.T_CHAR:
				primitiveType = "C";
				break;
			case JavaClassConstants.T_FLOAT:
				primitiveType = "F";
				break;
			case JavaClassConstants.T_DOUBLE:
                primitiveType = "D";
                break;
			case JavaClassConstants.T_BYTE:
				primitiveType = "B";
				break;
			case JavaClassConstants.T_SHORT:
				primitiveType = "S";
				break;
			case JavaClassConstants.T_INT:
				primitiveType = "I";
				break;
			case JavaClassConstants.T_LONG:
				primitiveType = "J";
				break;
			default:
				throw new IllegalArgumentException("Invalid primitive type code: " + i);
		}
		return DescriptorDecoder.getDataTypeOfDescriptor(primitiveType, dtManager);
	}
}
