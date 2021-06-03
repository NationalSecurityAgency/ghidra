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

import java.io.IOException;
import java.util.List;

import ghidra.javaclass.format.*;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;

public class ConstantPoolJava extends ConstantPool {

	public static final String CPOOL_OP = "cpool";
	private ClassFileJava classFile;
	private AbstractConstantPoolInfoJava[] constantPool;
	private DataTypeManager dtManager = null;

	//the following constants must agree with the definitions in JVM.slaspec
	public static final String CPOOL_ANEWARRAY = "0";
	public static final String CPOOL_CHECKCAST = "1";
	public static final String CPOOL_GETFIELD = "2";
	public static final String CPOOL_GETSTATIC = "3";
	public static final String CPOOL_LDC = "4"; //also used for ldc_w
	public static final String CPOOL_LDC2_W = "5";
	public static final String CPOOL_INSTANCEOF = "6";
	public static final String CPOOL_INVOKEDYNAMIC = "7";
	public static final String CPOOL_INVOKEINTERFACE = "8";
	public static final String CPOOL_INVOKESPECIAL = "9";
	public static final String CPOOL_INVOKESTATIC = "10";
	public static final String CPOOL_INVOKEVIRTUAL = "11";
	public static final String CPOOL_MULTIANEWARRAY = "12";
	public static final String CPOOL_NEW = "13";
	public static final String CPOOL_NEWARRAY = "14";
	public static final String CPOOL_PUTSTATIC = "15";
	public static final String CPOOL_PUTFIELD = "16";
	public static final String CPOOL_ARRAYLENGTH = "17";

	public ConstantPoolJava(Program program) throws IOException {
		ClassFileAnalysisState analysisState = ClassFileAnalysisState.getState(program);
		classFile = analysisState.getClassFile();
		constantPool = classFile.getConstantPool();
		dtManager = program.getDataTypeManager();
	}

	private void fillinMethod(int index, int name_and_type_index, Record res,
			JavaInvocationType methodType) {
		ConstantPoolNameAndTypeInfo methodNameAndType =
			(ConstantPoolNameAndTypeInfo) constantPool[name_and_type_index];
		int name_index = methodNameAndType.getNameIndex();
		res.tag = ConstantPool.POINTER_METHOD;

		if (methodType.equals(JavaInvocationType.INVOKE_STATIC)) {
			AbstractConstantPoolReferenceInfo poolRef =
				(AbstractConstantPoolReferenceInfo) constantPool[index];
			ConstantPoolClassInfo classInfo =
				(ConstantPoolClassInfo) constantPool[poolRef.getClassIndex()];
			int classNameIndex = classInfo.getNameIndex();
			String fullyQualifiedName =
				((ConstantPoolUtf8Info) constantPool[classNameIndex]).getString();
			String className = getClassName(fullyQualifiedName);
			res.token =
				className + "." + ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
		}
		else {
			res.token = ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
		}

		int descriptor_index = methodNameAndType.getDescriptorIndex();
		ConstantPoolUtf8Info descriptorInfo = (ConstantPoolUtf8Info) constantPool[descriptor_index];
		String descriptor = descriptorInfo.getString();

		String uniqueifier = Integer.toHexString(index);
		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(uniqueifier + "_" + res.token);
		DataType returnType =
			DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor, dtManager);
		funcDef.setReturnType(returnType);
		List<DataType> params = DescriptorDecoder.getDataTypeList(descriptor, dtManager);
		ParameterDefinitionImpl[] paramDefs;

		//invokestatic and invokedynamic don't have a this pointer on the stack
		if (methodType.equals(JavaInvocationType.INVOKE_STATIC) ||
			methodType.equals(JavaInvocationType.INVOKE_DYNAMIC)) {
			paramDefs = new ParameterDefinitionImpl[params.size()];
			for (int i = 0, max = params.size(); i < max; ++i) {
				ParameterDefinitionImpl currentParam =
					new ParameterDefinitionImpl("", params.get(i), null);
				paramDefs[i] = currentParam;
			}
			funcDef.setGenericCallingConvention(GenericCallingConvention.stdcall);
		}
		//invokeinterface, invokespecial, and invokevirtual do have a this pointer
		else {
			paramDefs = new ParameterDefinitionImpl[params.size() + 1];
			ParameterDefinitionImpl thisParam = new ParameterDefinitionImpl("objectRef",
				new Pointer32DataType(DataType.VOID), null);
			paramDefs[0] = thisParam;
			for (int i = 1, max = params.size(); i <= max; ++i) {
				ParameterDefinitionImpl currentParam =
					new ParameterDefinitionImpl("", params.get(i - 1), null);
				paramDefs[i] = currentParam;
			}
			funcDef.setGenericCallingConvention(GenericCallingConvention.thiscall);
		}
		funcDef.setArguments(paramDefs);
		res.type = new PointerDataType(funcDef);
	}

	//ref array does not include the first element passed to the cpool operator.
	//ref[0] is the constant pool index
	//ref[1] is a defined constant which represents the bytecode operation
	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		String op = Long.toString(ref[1]);
		/*The newarray operation doesn't actually reference the constant pool.
		 * However, it does use "array type codes" to determine the primitive 
		 * type of the elements of the new array.  We use the cpool operator to
		 * look up the string token corresponding to the primitive type.
		 */
		if (op.equals(CPOOL_NEWARRAY)) {
			res.tag = ConstantPool.POINTER_METHOD;
			res.token = ArrayMethods.getPrimitiveArrayToken((int) ref[0]);
			DataType elementType = ArrayMethods.getArrayBaseType((int) ref[0], dtManager);
			res.type = dtManager.getPointer(elementType);
			return res;
		}
		/*arraylength instruction does not reference the constant pool */
		if (op.equals(CPOOL_ARRAYLENGTH)) {
			res.tag = ConstantPool.ARRAY_LENGTH;
			res.token = "length";
			res.type = IntegerDataType.dataType;
			return res;
		}

		AbstractConstantPoolInfoJava poolRef = constantPool[(int) ref[0]];
		int name_and_type_index;
		switch (op) {
			case CPOOL_ANEWARRAY:
			case CPOOL_NEW:
				res.tag = ConstantPool.CLASS_REFERENCE;
				int name_index = ((ConstantPoolClassInfo) poolRef).getNameIndex();
				String fullyQualifiedName =
					((ConstantPoolUtf8Info) constantPool[name_index]).getString();
				String[] parts = fullyQualifiedName.split("/");
				res.token = parts[parts.length - 1];
				StringBuilder sb = new StringBuilder();
				for (String part : parts) {
					sb.append(CategoryPath.DELIMITER_CHAR);
					sb.append(part);
				}
				DataTypePath dataPath = new DataTypePath(sb.toString(), res.token);
				res.type = new PointerDataType(dtManager.getDataType(dataPath));
				break;
			case CPOOL_CHECKCAST:
				setTypeNameInfo(poolRef, res);
				res.tag = ConstantPool.CHECK_CAST;
				PointerDataType pointerType = (PointerDataType) res.type;
				String typeName = pointerType.getDataType().getDisplayName();
				res.token = "checkcast(" + typeName + ")";
				break;
			case CPOOL_INSTANCEOF:
				res.tag = ConstantPool.INSTANCE_OF;
				res.token = "instanceof";
				setTypeNameInfo(poolRef, res);
				break;
			case CPOOL_GETFIELD:
			case CPOOL_PUTFIELD:
			case CPOOL_GETSTATIC:
			case CPOOL_PUTSTATIC:
				handlePutAndGetOps(poolRef, res, op);
				break;
			case CPOOL_INVOKEDYNAMIC:
				name_and_type_index =
					((ConstantPoolInvokeDynamicInfo) poolRef).getNameAndTypeIndex();

				fillinMethod((int) ref[0], name_and_type_index, res,
					JavaInvocationType.INVOKE_DYNAMIC);
				break;
			case CPOOL_INVOKEINTERFACE:
				name_and_type_index =
					((ConstantPoolInterfaceMethodReferenceInfo) poolRef).getNameAndTypeIndex();
				fillinMethod((int) ref[0], name_and_type_index, res,
					JavaInvocationType.INVOKE_INTERFACE);
				break;
			case CPOOL_INVOKESPECIAL:
				AbstractConstantPoolReferenceInfo refInfo =
					(AbstractConstantPoolReferenceInfo) poolRef;
				name_and_type_index = refInfo.getNameAndTypeIndex();
				fillinMethod((int) ref[0], name_and_type_index, res,
					JavaInvocationType.INVOKE_SPECIAL);
				break;
			case CPOOL_INVOKESTATIC:
				refInfo = (AbstractConstantPoolReferenceInfo) poolRef;
				name_and_type_index = refInfo.getNameAndTypeIndex();
				fillinMethod((int) ref[0], name_and_type_index, res,
					JavaInvocationType.INVOKE_STATIC);
				break;
			case CPOOL_INVOKEVIRTUAL:
				name_and_type_index =
					((ConstantPoolMethodReferenceInfo) poolRef).getNameAndTypeIndex();
				fillinMethod((int) ref[0], name_and_type_index, res,
					JavaInvocationType.INVOKE_VIRTUAL);
				break;

			//in this case, the constant pool entry can be a reference to:
			//int, float, string literal, or a symbolic reference to a class,
			//method type, or method handle
			case CPOOL_LDC:
				if (poolRef instanceof ConstantPoolIntegerInfo) {
					res.tag = ConstantPool.PRIMITIVE;
					res.token = "int";
					res.value = ((ConstantPoolIntegerInfo) poolRef).getValue();
					res.type = IntegerDataType.dataType;
				}
				else if (poolRef instanceof ConstantPoolFloatInfo) {
					res.tag = ConstantPool.PRIMITIVE;
					res.token = "float";
					res.value = ((ConstantPoolFloatInfo) poolRef).getRawBytes() & 0xffffffffL;
					res.type = FloatDataType.dataType;
				}
				else if (poolRef instanceof ConstantPoolStringInfo) {
					int string_index = ((ConstantPoolStringInfo) poolRef).getStringIndex();
					res.tag = ConstantPool.STRING_LITERAL;
					res.byteData = ((ConstantPoolUtf8Info) constantPool[string_index]).getBytes();
					res.type = DescriptorDecoder.getReferenceTypeOfDescriptor("java/lang/String",
						dtManager, false);
				}
				else if (poolRef instanceof ConstantPoolClassInfo) {
					res.tag = ConstantPool.CLASS_REFERENCE;
					name_index = ((ConstantPoolClassInfo) poolRef).getNameIndex();
					fullyQualifiedName =
						((ConstantPoolUtf8Info) constantPool[name_index]).getString();
					String className = getClassName(fullyQualifiedName);
					res.token = className + ".class";
					res.type = DescriptorDecoder.getReferenceTypeOfDescriptor(fullyQualifiedName,
						dtManager, false);
				}
				else if (poolRef instanceof ConstantPoolMethodTypeInfo) {
					res.tag = ConstantPool.POINTER_METHOD;
					name_index = ((ConstantPoolMethodTypeInfo) poolRef).getDescriptorIndex();
					res.token = ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
					res.type = dtManager.getPointer(DWordDataType.dataType);
				}
				//TODO set the token?  
				else if (poolRef instanceof ConstantPoolMethodHandleInfo) {
					res.tag = ConstantPool.POINTER_METHOD;
					res.type = dtManager.getPointer(DWordDataType.dataType);
				}
				break;
			//must be a constant of type long or double
			//according to JVM spec
			case CPOOL_LDC2_W:
				if (poolRef instanceof ConstantPoolLongInfo) {
					res.tag = ConstantPool.PRIMITIVE;
					res.token = "long";
					res.value = ((ConstantPoolLongInfo) poolRef).getValue();
					res.type = LongDataType.dataType;
				}
				else {
					res.tag = ConstantPool.PRIMITIVE;
					res.token = "double";
					res.value = ((ConstantPoolDoubleInfo) poolRef).getRawBytes();
					res.type = DoubleDataType.dataType;
				}
				break;
			case CPOOL_MULTIANEWARRAY:
				res.tag = ConstantPool.CLASS_REFERENCE;
				res.type = new PointerDataType(DataType.VOID);
				int nameIndex = ((ConstantPoolClassInfo) poolRef).getNameIndex();
				ConstantPoolUtf8Info utf8Info = (ConstantPoolUtf8Info) constantPool[nameIndex];
				String classNameWithSemicolon = utf8Info.getString();
				res.token = DescriptorDecoder.getTypeNameFromDescriptor(classNameWithSemicolon,
					false, false);
			default:
				break;
		}
		return res;
	}

	private void handlePutAndGetOps(AbstractConstantPoolInfoJava poolRef, Record res, String op) {

		int name_and_type_index = ((ConstantPoolFieldReferenceInfo) poolRef).getNameAndTypeIndex();
		ConstantPoolNameAndTypeInfo fieldNameAndType =
			(ConstantPoolNameAndTypeInfo) constantPool[name_and_type_index];
		int name_index = fieldNameAndType.getNameIndex();
		switch (op) {
			case CPOOL_GETFIELD:
			case CPOOL_PUTFIELD:
				res.token = ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
				break;
			case CPOOL_GETSTATIC:
			case CPOOL_PUTSTATIC:
				int class_index = ((ConstantPoolFieldReferenceInfo) poolRef).getClassIndex();
				ConstantPoolClassInfo classInfo = (ConstantPoolClassInfo) constantPool[class_index];
				int classNameIndex = classInfo.getNameIndex();
				String fullyQualifiedName =
					((ConstantPoolUtf8Info) constantPool[classNameIndex]).getString();
				String className = getClassName(fullyQualifiedName);
				res.token =
					className + "." + ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
				break;
			default:
				throw new IllegalArgumentException("Invalid op: " + op);
		}

		res.tag = ConstantPool.POINTER_FIELD;

		int descriptor_index = fieldNameAndType.getDescriptorIndex();
		ConstantPoolUtf8Info descriptorInfo = (ConstantPoolUtf8Info) constantPool[descriptor_index];
		String descriptor = descriptorInfo.getString();
		DataType type = DescriptorDecoder.getDataTypeOfDescriptor(descriptor, dtManager);
		res.type = new PointerDataType(type);
	}

	private void setTypeNameInfo(AbstractConstantPoolInfoJava poolRef, Record res) {
		int name_index = ((ConstantPoolClassInfo) poolRef).getNameIndex();
		String fullyQualifiedName = ((ConstantPoolUtf8Info) constantPool[name_index]).getString();
		String[] parts = null;
		StringBuilder sb = null;
		if (fullyQualifiedName.startsWith("[")) {
			//TODO: how to get instanceof X to display, where X is an array type?
			//need to decide how to handle multidimensional arrays
			//remove the brackets
			//check whether it's a primitive type
			parts = fullyQualifiedName.split("/");
			sb = new StringBuilder();
			for (String part : parts) {
				sb.append(CategoryPath.DELIMITER_CHAR);
				sb.append(part);
			}
		}
		else {
			parts = fullyQualifiedName.split("/");
			sb = new StringBuilder();
			for (String part : parts) {
				sb.append(CategoryPath.DELIMITER_CHAR);
				sb.append(part);
			}
		}
		DataTypePath dataPath = new DataTypePath(sb.toString(), parts[parts.length - 1]);
		res.type = new PointerDataType(dtManager.getDataType(dataPath));

	}

	private String getClassName(String fullyQualifiedName) {
		int lastSlash = fullyQualifiedName.lastIndexOf("/");
		return fullyQualifiedName.substring(lastSlash + 1, fullyQualifiedName.length());
	}

	public AbstractConstantPoolInfoJava[] getConstantPool() {
		return constantPool;
	}

}
