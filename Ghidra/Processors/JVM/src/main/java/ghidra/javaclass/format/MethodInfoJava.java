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
package ghidra.javaclass.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.javaclass.flags.MethodsInfoAccessFlags;
import ghidra.javaclass.format.attributes.*;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Each method, including each instance initialization method (2.9) and the class or
 * interface initialization method (2.9), is described by a method_info structure. No
 * two methods in one class file may have the same name and descriptor (4.3.3).
 * <p>
 * The structure has the following format:
 * <pre>
 * 	method_info {
 * 		u2 access_flags;
 * 		u2 name_index;
 * 		u2 descriptor_index;
 * 		u2 attributes_count;
 * 		attribute_info attributes[attributes_count];
 * 	}
 * </pre>
 *
 */
public class MethodInfoJava implements StructConverter {

	private long _offset;

	private short accessFlags;
	private short nameIndex;
	private short descriptorIndex;
	private short attributesCount;
	private AbstractAttributeInfo[] attributes;

	public MethodInfoJava(BinaryReader reader, ClassFileJava classFile) throws IOException {
		_offset = reader.getPointerIndex();

		accessFlags = reader.readNextShort();
		nameIndex = reader.readNextShort();
		descriptorIndex = reader.readNextShort();
		attributesCount = reader.readNextShort();
		attributes = new AbstractAttributeInfo[getAttributesCount()];
		for (int i = 0; i < getAttributesCount(); i++) {
			attributes[i] = AttributeFactory.get(reader, classFile.getConstantPool());
		}
	}

	/**
	 * Returns the file offset where this method exists in the class file.
	 * @return the file offset where this method exists in the class file
	 */
	public long getOffset() {
		return _offset;
	}

	/**
	 * The value of the access_flags item is a mask of flags used to denote access
	 * permission to and properties of this method. The interpretation of each flag,
	 * when set, is as shown in Table 4.20.
	 * @return a mask of flags used to denote access permission to and properties of this method
	 */
	public short getAccessFlags() {
		return accessFlags;
	}

	/**
	 * 
	 * @return boolean encoding whether the method is static
	 */
	public boolean isStatic() {
		return (MethodsInfoAccessFlags.ACC_STATIC.getValue() &
			accessFlags) == MethodsInfoAccessFlags.ACC_STATIC.getValue();
	}

	/**
	 * The value of the name_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing either one of the special
	 * method names <init> or <clinit>, or a valid unqualified name 
	 * denoting a method.
	 * @return a valid index into the constant_pool table
	 */
	public int getNameIndex() {
		return nameIndex & 0xffff;
	}

	/**
	 * The value of the descriptor_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing a valid method descriptor.
	 * @return a valid index into the constant_pool table
	 */
	public int getDescriptorIndex() {
		return descriptorIndex & 0xffff;
	}

	/**
	 * The value of the attributes_count item indicates the number of additional
	 * attributes of this method.
	 * @return the number of additional attributes of this method
	 */
	public int getAttributesCount() {
		return attributesCount & 0xffff;
	}

	/**
	 * Each value of the attributes table must be an attribute structure. A
	 * method can have any number of optional attributes associated with it.
	 * <p>
	 * The attributes defined by this specification as appearing in the attributes
	 * table of a method_info structure are the 
	 * 		Code, 
	 * 		Exceptions, 
	 * 		Synthetic, 
	 * 		Signature,
	 * 		Deprecated,
	 * 		RuntimeVisibleAnnotations, 
	 * 		RuntimeInvisibleAnnotations,
	 * 		RuntimeVisibleParameterAnnotations,
	 * 		RuntimeInvisibleParameterAnnotations,
	 * 		AnnotationDefault attributes.
	 * <p>
	 * A Java virtual machine implementation must recognize and correctly read 
	 * Code  and Exceptions attributes found in the
	 * attributes table of a method_info structure. 
	 * <p>
	 * If a Java virtual machine
	 * implementation recognizes class files whose version number is 49.0
	 * or above, it must recognize and correctly read Signature,
	 * RuntimeVisibleAnnotations, RuntimeInvisibleAnnotations, RuntimeVisibleParameterAnnotations,
	 * RuntimeInvisibleParameterAnnotations, and
	 * AnnotationDefault attributes found in the attributes table of a
	 * method_info structure of a class file whose version number is 49.0 or above.
	 * <p>
	 * A Java virtual machine implementation is required to silently ignore any or
	 * all attributes in the attributes table of a method_info structure that it does
	 * not recognize. Attributes not defined in this specification are not allowed to
	 * affect the semantics of the class file, but only to provide additional descriptive
	 * information.
	 * @return
	 */
	public AbstractAttributeInfo[] getAttributes() {
		return attributes;
	}

	/**
	 * Return a text representation of this methods signature.  
	 * Here are some examples:
	 * <DL>
	 *  <DD><CODE>"public int foo(int bar)"</CODE></DD>
	 *  <DD><CODE>"public static final float foo(double bar)"</CODE></DD>
	 * </DL>
	 * Note: only access flags that map to Java modifier keywords are returned.
	 * @param access the mask of flags denoting access permission.
	 * @return a text representation of the access flags.
	 */
	public String getMethodSignature(ClassFileJava classFile) {
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();
		ConstantPoolUtf8Info methodName = (ConstantPoolUtf8Info) constantPool[nameIndex];
		ConstantPoolUtf8Info methodDescriptor =
			(ConstantPoolUtf8Info) constantPool[descriptorIndex];
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append(MethodsInfoAccessFlags.toString(accessFlags));

		if (methodName.getString().equals("<clinit>")) {
			stringBuffer.append(" (class initializer)");
		}
		else {
			stringBuffer.append(' ');
			if (methodName.getString().equals("<init>")) {//replace constructors with name of this class
				ConstantPoolClassInfo thisClass =
					(ConstantPoolClassInfo) constantPool[classFile.getThisClass()];
				ConstantPoolUtf8Info thisClassName =
					(ConstantPoolUtf8Info) constantPool[thisClass.getNameIndex()];
				String className = thisClassName.getString();
				String dottedClassName = className.replace('/', '.');
				int pos = dottedClassName.lastIndexOf('.');
				if (pos > -1) {
					stringBuffer.append(dottedClassName.substring(pos + 1));
				}
				else {
					stringBuffer.append(className);
//					throw new RuntimeException( );//TODO
				}
			}
			else {
				stringBuffer.append(getReturnType(methodDescriptor));
				stringBuffer.append(' ');
				stringBuffer.append(methodName.getString());
			}

			CodeAttribute codeAttribute = getCodeAttribute();
			if (codeAttribute != null) {
				LocalVariableTableAttribute localVariableTable =
					codeAttribute.getLocalVariableTableAttribute();
				if (localVariableTable != null) {
					stringBuffer.append('(');
					LocalVariableJava[] localVariables = localVariableTable.getLocalVariables();
					int startIndex = getParametersStartIndex();
					for (int i = startIndex; i < localVariables.length; ++i) {
						if (localVariables[i].getStartPC() == 0x0) {
							if (i > startIndex) {
								stringBuffer.append(", ");
							}
							ConstantPoolUtf8Info parameterName =
								(ConstantPoolUtf8Info) constantPool[localVariables[i].getNameIndex()];
							ConstantPoolUtf8Info parameterDescriptor =
								(ConstantPoolUtf8Info) constantPool[localVariables[i].getDescriptorIndex()];

							stringBuffer.append(DescriptorDecoder.getTypeNameFromDescriptor(
								parameterDescriptor.getString(), false, true));
							stringBuffer.append(" ");
							stringBuffer.append(parameterName);

						}
					}
					stringBuffer.append(')');
				}
				else {
					stringBuffer.append(
						DescriptorDecoder.getParameterString(methodDescriptor.getString()));
				}
			}

			ExceptionsAttribute exceptionsAttribute = getExceptionsAttribute();
			if (exceptionsAttribute != null) {
				int i = 0;
				for (int k = 0; k < exceptionsAttribute.getNumberOfExceptions(); k++) {
					ConstantPoolClassInfo exceptionClass =
						(ConstantPoolClassInfo) constantPool[exceptionsAttribute.getExceptionIndexTableEntry(
							k)];
					ConstantPoolUtf8Info exceptionClassName =
						(ConstantPoolUtf8Info) constantPool[exceptionClass.getNameIndex()];
					String className = exceptionClassName.getString();
					String dottedClassName = className.replace('/', '.');
					if (i == 0) {
						stringBuffer.append(" throws ");
					}
					else {
						stringBuffer.append(", ");

					}
					stringBuffer.append(dottedClassName);
					i++;
				}
			}
		}
		stringBuffer.append(' ');
		return stringBuffer.toString();
	}

	/**
	 * If the method is static, then parameters start at index 0,
	 * otherwise skip index 0 because it contains the 'this' parameter.
	 */
	private int getParametersStartIndex() {
		return isStatic() ? 0 : 1;
	}

	/**
	 * Clips the encoded return type from the method descriptor then
	 * decodes it into a readable data type.
	 */
	private String getReturnType(ConstantPoolUtf8Info methodDescriptor) {
		String methodDescriptorString = methodDescriptor.getString();
		int closeParenthesisPos = methodDescriptorString.indexOf(')') + 1;
		String encodedReturnType = methodDescriptorString.substring(closeParenthesisPos);
		return DescriptorDecoder.getTypeNameFromDescriptor(encodedReturnType, false, true);
	}

	public CodeAttribute getCodeAttribute() {
		for (AbstractAttributeInfo attributeInfo : attributes) {
			if (attributeInfo instanceof CodeAttribute) {
				return (CodeAttribute) attributeInfo;
			}
		}
		return null;
	}

	public ExceptionsAttribute getExceptionsAttribute() {
		for (AbstractAttributeInfo attributeInfo : attributes) {
			if (attributeInfo instanceof ExceptionsAttribute) {
				return (ExceptionsAttribute) attributeInfo;
			}
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name =
			"method_info" + "|" + nameIndex + "|" + descriptorIndex + "|" + attributesCount + "|";

		Structure structure = new StructureDataType(name, 0);

		structure.add(WORD, "access_flags", null);
		structure.add(WORD, "name_index", null);
		structure.add(WORD, "descriptor_index", null);
		structure.add(WORD, "attributes_count", null);

		for (int i = 0; i < attributes.length; ++i) {
			structure.add(attributes[i].toDataType(), "attributes_" + i, null);
		}

		return structure;
	}

}
