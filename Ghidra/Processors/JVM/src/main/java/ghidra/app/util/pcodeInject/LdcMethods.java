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

import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.javaclass.format.constantpool.ConstantPoolTagsJava;

/**
 * 
 * This is a utility class containing a method to generate pcode of the ldc, ldc_w, and ldc2_w bytecode ops. 
 *
 */

public class LdcMethods {

	static final String VALUE = "value";

	//private constructor to enforce noninstantiability
	private LdcMethods(){
		throw new AssertionError();
	}

	/**
	 * Generates a String of pcode modeling an ldc, ldc_w, or ldc2_w bytecode ops, which refer to constants
	 * in the constant pool.  
	 *  
	 * @param constantPoolIndex - the index of item in the constant pool.
	 * @param constantPool - the constant pool
	 * @return - String of pcode.
	 */
	public static String getPcodeForLdc(int constantPoolIndex, AbstractConstantPoolInfoJava[] constantPool){
		byte tag = constantPool[constantPoolIndex].getTag();
		StringBuilder pCode = new StringBuilder();
		switch (tag){
		case ConstantPoolTagsJava.CONSTANT_Class: 
		case ConstantPoolTagsJava.CONSTANT_Float:
		case ConstantPoolTagsJava.CONSTANT_Integer:
		case ConstantPoolTagsJava.CONSTANT_MethodHandle:
		case ConstantPoolTagsJava.CONSTANT_MethodType:
		case ConstantPoolTagsJava.CONSTANT_String:
			PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, VALUE, 4, ConstantPoolJava.CPOOL_OP, "0", Integer.toString(constantPoolIndex),ConstantPoolJava.CPOOL_LDC);
			PcodeTextEmitter.emitPushCat1Value(pCode,VALUE);
			break;
		case ConstantPoolTagsJava.CONSTANT_Double:
		case ConstantPoolTagsJava.CONSTANT_Long:
			PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, VALUE, 8, ConstantPoolJava.CPOOL_OP, "0", Integer.toString(constantPoolIndex),ConstantPoolJava.CPOOL_LDC2_W);
			PcodeTextEmitter.emitPushCat2Value(pCode,VALUE);
			break;
		default:
			throw new IllegalArgumentException("Invalid load from constant pool: tag " + tag);

		}
		return pCode.toString();
	}			
}
