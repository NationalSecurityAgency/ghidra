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
package ghidra.javaclass.format.constantpool;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class ConstantPoolFactory {

	public static AbstractConstantPoolInfoJava get(BinaryReader reader) throws IOException {

		switch (reader.peekNextByte()) {

			case ConstantPoolTagsJava.CONSTANT_Class:
				return new ConstantPoolClassInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Double:
				return new ConstantPoolDoubleInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Fieldref:
				return new ConstantPoolFieldReferenceInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Float:
				return new ConstantPoolFloatInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Integer:
				return new ConstantPoolIntegerInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_InterfaceMethodref:
				return new ConstantPoolInterfaceMethodReferenceInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_InvokeDynamic:
				return new ConstantPoolInvokeDynamicInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Long:
				return new ConstantPoolLongInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_MethodHandle:
				return new ConstantPoolMethodHandleInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Methodref:
				return new ConstantPoolMethodReferenceInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_MethodType:
				return new ConstantPoolMethodTypeInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_NameAndType:
				return new ConstantPoolNameAndTypeInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_String:
				return new ConstantPoolStringInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Utf8:
				return new ConstantPoolUtf8Info(reader);

			case ConstantPoolTagsJava.CONSTANT_Dynamic:
				return new ConstantPoolDynamicInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Module:
				return new ConstantPoolModuleInfo(reader);

			case ConstantPoolTagsJava.CONSTANT_Package:
				return new ConstantPoolPackageInfo(reader);

			case 0:
				return null;

			default:
				throw new IllegalArgumentException(
					"Unsupport Constant Pool Entry Type: " + reader.peekNextByte());
		}
	}

}
