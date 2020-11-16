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

import java.util.List;

import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;

/**
 * 
 * asymmetry in java - methods passed on stack, read from local variable array
 *
 */

public class InvokeMethods {

	static final String CALL_TARGET = "call_target";
	static final String CAT_1_RETURN = "return_value";
	static final String CAT_2_RETURN = "cat2_return_value";
	static final String PARAMETER = "param";
	static final String PARAMETER_PART2 = "parampart";
	static final String THIS = "this";
	static final String STATIC_OFFSET = "0";
	static final String PARAM_SPACE = "parameterSpace";

	//private constructor to enforce noninstantiability
	private InvokeMethods() {
		throw new AssertionError();
	}

	/**
	 * Emits the pcode for an invoke instruction.
	 * @param pCode is the pcode accumulator
	 * @param offset - the index of the constant pool element containing a symbolic reference 
	 * to a method or a call site specifier.
	 * @param constantPool - the constant pool
	 * @param type - the JavaInvocationType of the invocation
	 */
	public static void getPcodeForInvoke(PcodeOpEmitter pCode, int offset,
			AbstractConstantPoolInfoJava[] constantPool,
			JavaInvocationType type) {

		String descriptor = DescriptorDecoder.getDescriptorForInvoke(offset, constantPool, type);
		List<JavaComputationalCategory> categories =
			DescriptorDecoder.getParameterCategories(descriptor);
		boolean includeThisPointer = type.equals(JavaInvocationType.INVOKE_VIRTUAL) ||
			type.equals(JavaInvocationType.INVOKE_SPECIAL) ||
			type.equals(JavaInvocationType.INVOKE_INTERFACE);

		int stackPurge = DescriptorDecoder.getStackPurge(descriptor);
		if (includeThisPointer) {
			stackPurge += 4;
		}
		emitPcodeToMoveParams(pCode, categories, includeThisPointer, stackPurge);
		emitPcodeToResolveMethodReference(pCode, offset, constantPool, type);
		pCode.emitIndirectCall(CALL_TARGET);

		JavaComputationalCategory retType =
			DescriptorDecoder.getReturnCategoryOfMethodDescriptor(descriptor);
		switch (retType) {
			case CAT_1:
				pCode.emitPushCat1Value(CAT_1_RETURN);
				break;
			case CAT_2:
				pCode.emitPushCat2Value(CAT_2_RETURN);
				break;
			default:
				break;
		}
	}

	/**
	 * Emits the pcode for an invoke instruction.
	 * @param pCode is the pcode accumulator
	 * @param offset - the index of the constant pool element containing a symbolic reference 
	 * to a method or a call site specifier.
	 * @param constantPool - the constant pool
	 */
	public static void getPcodeForInvokeDynamic(PcodeOpEmitter pCode, int offset,
			AbstractConstantPoolInfoJava[] constantPool) {
		String invokeDynamicDescriptor = DescriptorDecoder.getDescriptorForInvoke(offset,
			constantPool, JavaInvocationType.INVOKE_DYNAMIC);
		List<JavaComputationalCategory> categories =
			DescriptorDecoder.getParameterCategories(invokeDynamicDescriptor);

		int stackPurge = DescriptorDecoder.getStackPurge(invokeDynamicDescriptor);

		emitPcodeToMoveParams(pCode, categories, false, stackPurge);
		emitPcodeToResolveMethodReference(pCode, offset, constantPool,
			JavaInvocationType.INVOKE_DYNAMIC);
		pCode.emitIndirectCall(CALL_TARGET);

		JavaComputationalCategory retType =
			DescriptorDecoder.getReturnCategoryOfMethodDescriptor(invokeDynamicDescriptor);
		switch (retType) {
			case CAT_1:
				pCode.emitPushCat1Value(CAT_1_RETURN);
				break;
			case CAT_2:
				pCode.emitPushCat2Value(CAT_2_RETURN);
				break;
			default:
				break;
		}
	}

	/**
	 * Emits pcode to move the parameters from the stack to the space parameterSpace
	 * Note: if there is an implicit this parameter, then this method will assign it to a varnode
	 * named InvokeMethods.THIS
	 * @param pCode - the pcode buffer
	 * @param categories - the list of computational categories on the top of the stack
	 * @param includeThisPointer - true if the first element on the stack is an implicit this parameter
	 * @param totalSize - 
	 */
	static void emitPcodeToMoveParams(PcodeOpEmitter pCode,
			List<JavaComputationalCategory> categories, boolean includeThisPointer, int totalSize) {

		//pop the parameters off of the stack
		for (int i = categories.size() - 1; i >= 0; --i) {
			switch (categories.get(i)) {
				case CAT_1:
					pCode.emitPopCat1Value(PARAMETER + Integer.toString(i));
					totalSize -= 4;
					pCode.emitWriteToMemory(PARAM_SPACE, 4,
						Integer.toString(totalSize) + ":4", PARAMETER + Integer.toString(i));
					break;
				case CAT_2:
					pCode.emitPopCat1Value(PARAMETER + Integer.toString(i));
					pCode.emitWriteToMemory(PARAM_SPACE, 4,
						Integer.toString(totalSize - 8) + ":4", PARAMETER + Integer.toString(i));
					pCode.emitPopCat1Value(PARAMETER_PART2 + Integer.toString(i));
					pCode.emitWriteToMemory(PARAM_SPACE, 4,
						Integer.toString(totalSize - 4) + ":4",
						PARAMETER_PART2 + Integer.toString(i));
					totalSize -= 8;
					break;
				default:
					throw new IllegalArgumentException("Invalid category!");
			}
		}
		//pop off the this pointer if there is one
		if (includeThisPointer) {
			pCode.emitPopCat1Value(THIS);
			totalSize -= 4;
			pCode.emitWriteToMemory(PARAM_SPACE, 4,
				Integer.toString(totalSize) + ":4", THIS);

		}
	}

	/**
	 * Emits pcode to assign the result of a cpool op to the call_target register for an invocation. 
	 * @param pCode - the pcode buffer
	 * @param offset - index of the method reference in the constant pool
	 * @param constantPool - the constant pool
	 * @param type - the type of the invocation
	 */
	static void emitPcodeToResolveMethodReference(PcodeOpEmitter pCode, int offset,
			AbstractConstantPoolInfoJava[] constantPool, JavaInvocationType type) {
		switch (type) {
			case INVOKE_DYNAMIC:
				pCode.emitAssignRegisterFromPcodeOpCall(CALL_TARGET,
					ConstantPoolJava.CPOOL_OP, STATIC_OFFSET, Integer.toString(offset),
					ConstantPoolJava.CPOOL_INVOKEDYNAMIC);
				break;
			case INVOKE_INTERFACE:
				pCode.emitAssignRegisterFromPcodeOpCall(CALL_TARGET,
					ConstantPoolJava.CPOOL_OP, THIS, Integer.toString(offset),
					ConstantPoolJava.CPOOL_INVOKEINTERFACE);
				break;
			case INVOKE_SPECIAL:
				pCode.emitAssignRegisterFromPcodeOpCall(CALL_TARGET,
					ConstantPoolJava.CPOOL_OP, THIS, Integer.toString(offset),
					ConstantPoolJava.CPOOL_INVOKESPECIAL);
				break;
			case INVOKE_STATIC:
				pCode.emitAssignRegisterFromPcodeOpCall(CALL_TARGET,
					ConstantPoolJava.CPOOL_OP, STATIC_OFFSET, Integer.toString(offset),
					ConstantPoolJava.CPOOL_INVOKESTATIC);
				break;
			case INVOKE_VIRTUAL:
				pCode.emitAssignRegisterFromPcodeOpCall(CALL_TARGET,
					ConstantPoolJava.CPOOL_OP, THIS, Integer.toString(offset),
					ConstantPoolJava.CPOOL_INVOKEVIRTUAL);
				break;
			default:
				throw new IllegalArgumentException(
					"Unimplemented JavaMethodType: " + type.toString());
		}
	}
}
