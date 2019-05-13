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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The Code attribute is a variable-length attribute in the attributes table of a
 * method_info (?4.6) structure.
 * <p>
 * A Code attribute contains the Java virtual machine
 * instructions and auxiliary information for a single method, instance initialization
 * method (?2.9), or class or interface initialization method (?2.9). Every Java virtual
 * machine implementation must recognize Code attributes. 
 * <p>
 * If the method is either
 * native or abstract, its method_info structure must not have a Code attribute.
 * Otherwise, its method_info structure must have exactly one Code attribute.
 * <p>
 * The Code attribute has the following format:
 * <pre>
 * 	Code_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 max_stack;
 * 		u2 max_locals;
 * 		u4 code_length;
 * 		u1 code[code_length];
 * 		u2 exception_table_length;
 * 		{
 * 			u2 start_pc;
 * 			u2 end_pc;
 * 			u2 handler_pc;
 * 			u2 catch_type;
 * 		} exception_table[exception_table_length];
 * 		u2 attributes_count;
 * 		attribute_info attributes[attributes_count];
 * 	}
 * </pre>
 */
public class CodeAttribute extends AbstractAttributeInfo {
	private long _codeOffset;

	private short maxStack;
	private short maxLocals;
	private int codeLength;
	private byte[] code;
	private short exceptionTableLength;
	private ExceptionHandlerJava[] exceptionTable;
	private short attributesCount;
	private AbstractAttributeInfo[] attributes;

	public CodeAttribute(BinaryReader reader, AbstractConstantPoolInfoJava[] constantPool)
			throws IOException {
		super(reader);

		maxStack = reader.readNextShort();
		maxLocals = reader.readNextShort();
		codeLength = reader.readNextInt();
		_codeOffset = reader.getPointerIndex();
		code = reader.readNextByteArray(codeLength);
		exceptionTableLength = reader.readNextShort();
		exceptionTable = new ExceptionHandlerJava[getExceptionTableLength()];
		for (int i = 0; i < getExceptionTableLength(); i++) {
			exceptionTable[i] = new ExceptionHandlerJava(reader);
		}
		attributesCount = reader.readNextShort();
		attributes = new AbstractAttributeInfo[getAttributesCount()];
		for (int i = 0; i < getAttributesCount(); i++) {
			attributes[i] = AttributeFactory.get(reader, constantPool);
		}
	}

	/**
	 * The value of the max_stack item gives the maximum depth of the
	 * operand stack of this method at any point during execution of the method.
	 * @return the maximum depth of the operand stack
	 */
	public int getMaxStack() {
		return maxStack & 0xffff;
	}

	/**
	 * The value of the max_locals item gives the number of local variables in the
	 * local variable array allocated upon invocation of this method, including the
	 * local variables used to pass parameters to the method on its invocation.
	 * <p>
	 * The greatest local variable index for a value of type long or double is
	 * max_locals - 2. The greatest local variable index for a value of any other
	 * type is max_locals - 1.
	 * @return the number of local variables in the
	 * local variable array allocated upon invocation of this method
	 */
	public int getMaxLocals() {
		return maxLocals & 0xffff;
	}

	/**
	 * The value of the code_length item gives the number of bytes in the code array
	 * for this method. The value of code_length must be greater than zero; the code
	 * array must not be empty.
	 * @return the number of bytes in the code array for this method
	 */
	public int getCodeLength() {
		return codeLength;
	}

	/**
	 * The code array gives the actual bytes of Java virtual machine code that
	 * implement the method.
	 * <p>
	 * When the code array is read into memory on a byte-addressable machine, if
	 * the first byte of the array is aligned on a 4-byte boundary, the tableswitch and
	 * lookupswitch 32-bit offsets will be 4-byte aligned. (Refer to the descriptions
	 * of those instructions for more information on the consequences of code array
	 * alignment.)
	 * <p>
	 * The detailed constraints on the contents of the code array are extensive and are
	 * given in a separate section.
	 * @return he actual bytes of Java virtual machine code that implement the method
	 */
	public byte[] getCode() {
		return code;
	}

	/**
	 * The value of the exception_table_length item gives the number of entries
	 * in the exception_table table.
	 * @return the number of entries in the exception_table table
	 */
	public int getExceptionTableLength() {
		return exceptionTableLength & 0xffff;
	}

	/**
	 * Each entry in the exception_table array describes one exception handler in
	 * the code array. 
	 * <p>
	 * The order of the handlers in the exception_table array is significant
	 * @return the exception_table array
	 */
	public ExceptionHandlerJava[] getExceptionTable() {
		return exceptionTable;
	}

	/**
	 * The value of the attributes_count item indicates the number of attributes of
	 * the Code attribute.
	 * @return the number of attributes of the Code attribute
	 */
	public int getAttributesCount() {
		return attributesCount & 0xffff;
	}

	/**
	 * Each value of the attributes table must be an attribute structure. A
	 * Code attribute can have any number of optional attributes associated with it.
	 * <p>
	 * The only attributes defined by this specification as appearing in the
	 * attributes table of a Code attribute are the LineNumberTable,
	 * LocalVariableTable, LocalVariableTypeTable, and
	 * StackMapTable attributes.
	 * <p>
	 * If a Java virtual machine implementation recognizes class files whose version
	 * number is 50.0 or above, it must recognize and correctly read StackMapTable
	 * attributes found in the attributes table of a Code attribute of a class
	 * file whose version number is 50.0 or above.
	 * <p>
	 * A Java virtual machine implementation is required to silently ignore any or
	 * all attributes in the attributes table of a Code attribute that it does not
	 * recognize. Attributes not defined in this specification are not allowed to affect
	 * the semantics of the class file, but only to provide additional descriptive
	 * information.
	 * @return the attributes table
	 */
	public AbstractAttributeInfo[] getAttributes() {
		return attributes;
	}

	public LocalVariableTableAttribute getLocalVariableTableAttribute() {
		for (AbstractAttributeInfo attributeInfo : attributes) {
			if (attributeInfo instanceof LocalVariableTableAttribute) {
				return (LocalVariableTableAttribute) attributeInfo;
			}
		}
		return null;
	}

	public long getCodeOffset() {
		return _codeOffset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "Code_attribute" + "|" + exceptionTableLength + "|" + attributesCount + "|";
		StructureDataType structure = getBaseStructure(name);
		structure.add(WORD, "max_stack", null);
		structure.add(WORD, "max_locals", null);
		structure.add(DWORD, "code_length", null);
		if (code.length > 0) {
			DataType array = new ArrayDataType(BYTE, code.length, BYTE.getLength());
			structure.add(array, "code", null);
		}
		structure.add(WORD, "exception_table_length", null);
		for (int i = 0; i < exceptionTable.length; ++i) {
			structure.add(exceptionTable[i].toDataType(), "exception_table_" + i, null);
		}
		structure.add(WORD, "attributes_count", null);
		for (int i = 0; i < attributes.length; ++i) {
			structure.add(attributes[i].toDataType(), "attributes_" + i, null);
		}
		return structure;
	}

}
