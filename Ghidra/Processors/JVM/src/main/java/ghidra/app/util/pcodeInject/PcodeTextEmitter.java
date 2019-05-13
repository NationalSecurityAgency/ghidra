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

/**
 * 
 * This is a utility class containing methods to emit pcode for decompile callbacks occurring during analysis of
 * Java .class files
 * 
 * All methods in this class take a StringBuilder object as the first argument.  The generated pcode is emitted
 * into that object.
 *
 */
public class PcodeTextEmitter {

	static final String RAM = "ram";

	//private constructor to enforce noninstantiability
	private PcodeTextEmitter() {
		throw new AssertionError();
	}

	/**
	 * Emits pcode to push a value of computational category 1 onto the stack.
	 * @param pCode - StringBuilder to hold pcode.
	 * @param valueName - name of varnode to push.
	 */
	public static void emitPushCat1Value(StringBuilder pCode, String valueName) {
		pCode.append("SP = SP - 4;\n*:4 SP = ");
		pCode.append(valueName);
		pCode.append(";\n");
	}

	/**
	 * Emits pcode to push a value of computational category 2 onto the stack.
	 * @param pCode - StringBuilder to hold pcode.
	 * @param valueName - name of varnode to push.
	 */
	public static void emitPushCat2Value(StringBuilder pCode, String valueName) {
		pCode.append("SP = SP - 8;\n*:8 SP = ");
		pCode.append(valueName);
		pCode.append(";\n");
	}

	/**
	 * Emits pcode to pop a value of computational category 2 from the stack.
	 * @param pCode - StringBuilder to hold pcode.
	 * @param destName - name of destination varnode.
	 */
	public static void emitPopCat2Value(StringBuilder pCode, String destName) {
		pCode.append(destName);
		pCode.append(":8 = *:8 SP;\nSP = SP + 8;\n");
	}

	/**
	 * Emits pcode to pop a value of computational category 1 from the stack.
	 * @param pCode - StringBuilder to hold pcode.
	 * @param destName - name of destination varnode.
	 */
	public static void emitPopCat1Value(StringBuilder pCode, String destName) {
		pCode.append(destName);
		pCode.append(":4 = *:4 SP;\nSP = SP + 4;\n");
	}

	/**
	 * Emits pcode to assign four bytes resulting from a call to a black-box pcodeop
	 * @param pCode StringBuilder to hold the pcode
	 * @param lhs - varnode name for holding result
	 * @param pcodeop - name of pcodeop
	 * @param args - zero or more arguments for the pcodeop
	 */
	public static void emitAssignVarnodeFromPcodeOpCall(StringBuilder pCode, String varnodeName,
			int size, String pcodeop, String... args) {
		pCode.append(varnodeName);
		pCode.append(":");
		pCode.append(Integer.toString(size));
		pCode.append(" = ");
		pCode.append(pcodeop);
		pCode.append("(");
		for (int i = 0, numArgs = args.length; i < numArgs; ++i) {
			pCode.append(args[i]);
			if (i < numArgs - 1) {
				pCode.append(",");
			}
		}
		pCode.append(");\n");
	}

	/**
	 * Emits pcode to call a void black-box pcodeop
	 * @param pCode StringBuilder to hold the pcode
	 * @param pcodeop - name of pcodeop
	 * @param args - zero or more arguments for the pcodeop
	 */
	public static void emitVoidPcodeOpCall(StringBuilder pCode, String pcodeop, String... args) {
		pCode.append(pcodeop);
		pCode.append("(");
		for (int i = 0, numArgs = args.length; i < numArgs; ++i) {
			pCode.append(args[i]);
			if (i < numArgs - 1) {
				pCode.append(",");
			}
		}
		pCode.append(");\n");
	}

	/**
	 * Appends the pcode to assign an integer constant to a register
	 * @param pCode
	 * @param constantPool
	 * @param index
	 */
	public static void emitAssignConstantToRegister(StringBuilder pCode, String register,
			int constant) {
		pCode.append(register);
		pCode.append(" = 0x");
		pCode.append(Integer.toHexString(constant));
		pCode.append(";\n");
	}

	/**
	 * Appends the pcode to assign a register to the result of a pcode op call with arguments args
	 * @param pCode
	 * @param register
	 * @param pcodeop
	 * @param args
	 */
	public static void emitAssignRegisterFromPcodeOpCall(StringBuilder pCode, String register,
			String pcodeop, String... args) {
		pCode.append(register);
		pCode.append(" = ");
		pCode.append(pcodeop);
		pCode.append("(");
		for (int i = 0, numArgs = args.length; i < numArgs; ++i) {
			pCode.append(args[i]);
			if (i < numArgs - 1) {
				pCode.append(",");
			}
		}
		pCode.append(");\n");
	}

	/**
	 * Appends the pcode to emit a label definition.
	 * @param pCode
	 * @param caseName
	 */
	public static void emitLabelDefinition(StringBuilder pCode, String caseName) {
		pCode.append("<");
		pCode.append(caseName);
		pCode.append(">\n");
	}

	/**
	 * Appends the pcode to write to a value at an offset of a memory space
	 * @param pCode buffer to append pcode 
	 * @param space name of space
	 * @param size size of write
	 * @param offset offset in space
	 * @param value value to write
	 */
	public static void emitWriteToMemory(StringBuilder pCode, String space, int size, String offset,
			String value) {
		pCode.append("*[");
		pCode.append(space);
		pCode.append("]:");
		pCode.append(Integer.toString(size));
		pCode.append(" ");
		pCode.append(offset);
		pCode.append(" = ");
		pCode.append(value);
		pCode.append(";\n");
	}

	/**
	 * Appends the pcode to emit an indirect call
	 * @param pCode buffer to append to
	 * @param target varnode to call indirectly
	 */
	public static void emitIndirectCall(StringBuilder pCode, String target) {
		pCode.append("call [");
		pCode.append(target);
		pCode.append("];\n");
	}

	/**
	 * Appends the pcode to sign-extend the value src into dest
	 * @param pCode buffer to append to
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public static void emitSignExtension(StringBuilder pCode, String dest, int size, String src) {
		pCode.append(dest);
		pCode.append(":");
		pCode.append(Integer.toString(size));
		pCode.append(" = sext(");
		pCode.append(src);
		pCode.append(");\n");
	}

	/**
	 * Appends the pcode to zero-extend the value src into dest
	 * @param pCode buffer to append to
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public static void emitZeroExtension(StringBuilder pCode, String dest, int size, String src) {
		pCode.append(dest);
		pCode.append(":");
		pCode.append(Integer.toString(size));
		pCode.append(" = zext(");
		pCode.append(src);
		pCode.append(");\n");
	}

	/**
	 * Appends the pcode truncate src into dest
	 * @param pCode buffer to append to
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public static void emitTruncate(StringBuilder pCode, String dest, int size, String src) {
		pCode.append(dest);
		pCode.append(" = ");
		pCode.append(src);
		pCode.append(":");
		pCode.append(Integer.toString(size));
		pCode.append(";\n");
	}

	/**
	 * Appends the pcode to assign a varnode from a dereference of another varnode
	 * @param pCode buffer to append to
	 * @param lhs target varnode
	 * @param size size of pointed-to value
	 * @param rhs varnode to dereference
	 */
	public static void emitAssignVarnodeFromDereference(StringBuilder pCode, String lhs, int size,
			String rhs) {
		pCode.append(lhs);
		pCode.append(":");
		pCode.append(Integer.toString(size));
		pCode.append(" = ");
		pCode.append("*:");
		pCode.append(Integer.toString(size));
		pCode.append(" ");
		pCode.append(rhs);
		pCode.append(";\n");
	}

}
