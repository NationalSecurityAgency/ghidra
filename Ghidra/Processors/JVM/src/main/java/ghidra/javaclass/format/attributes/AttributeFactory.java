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
import ghidra.javaclass.format.constantpool.ConstantPoolUtf8Info;

public class AttributeFactory {

	public static AbstractAttributeInfo get(BinaryReader reader,
			AbstractConstantPoolInfoJava[] constantPool) throws IOException {

		int attributeNameIndex = reader.readShort(reader.getPointerIndex());

		if (attributeNameIndex < 1 || attributeNameIndex >= constantPool.length) {
			throw new RuntimeException("invalid index");
		}

		if (!(constantPool[attributeNameIndex] instanceof ConstantPoolUtf8Info)) {
			throw new RuntimeException();
		}

		ConstantPoolUtf8Info utf8 = (ConstantPoolUtf8Info) constantPool[attributeNameIndex];

		switch (utf8.getString()) {
			case AttributesConstants.AnnotationDefault:
				return new AnnotationDefaultAttribute(reader);
			case AttributesConstants.BootstrapMethods:
				return new BootstrapMethodsAttribute(reader);
			case AttributesConstants.Code:
				return new CodeAttribute(reader, constantPool);
			case AttributesConstants.ConstantValue:
				return new ConstantValueAttribute(reader);
			case AttributesConstants.Deprecated:
				return new DeprecatedAttribute(reader);
			case AttributesConstants.EnclosingMethod:
				return new EnclosingMethodAttribute(reader);
			case AttributesConstants.Exceptions:
				return new ExceptionsAttribute(reader);
			case AttributesConstants.InnerClasses:
				return new InnerClassesAttribute(reader);
			case AttributesConstants.LineNumberTable:
				return new LineNumberTableAttribute(reader);
			case AttributesConstants.LocalVariableTable:
				return new LocalVariableTableAttribute(reader, constantPool);
			case AttributesConstants.LocalVariableTypeTable:
				return new LocalVariableTypeTableAttribute(reader);
			case AttributesConstants.ModuleMainClass:
				return new ModuleMainClassAttribute(reader);
			case AttributesConstants.ModulePackages:
				return new ModulePackagesAttribute(reader);
			case AttributesConstants.NestHost:
				return new NestHostAttribute(reader);
			case AttributesConstants.NestMembers:
				return new NestMembersAttribute(reader);
			case AttributesConstants.RuntimeInvisibleAnnotations:
				return new RuntimeInvisibleAnnotationsAttribute(reader);
			case AttributesConstants.RuntimeInvisibleParameterAnnotations:
				return new RuntimeParameterAnnotationsAttribute(reader, false /*invisible*/ );
			case AttributesConstants.RuntimeVisibleAnnotations:
				return new RuntimeVisibleAnnotationsAttribute(reader);
			case AttributesConstants.RuntimeVisibleParameterAnnotations:
				return new RuntimeParameterAnnotationsAttribute(reader, true /*visible*/ );
			case AttributesConstants.Signature:
				return new SignatureAttribute(reader);
			case AttributesConstants.SourceDebugExtension:
				return new SourceDebugExtensionAttribute(reader);
			case AttributesConstants.SourceFile:
				return new SourceFileAttribute(reader);
			case AttributesConstants.StackMapTable:
				return new StackMapTableAttribute(reader);
			case AttributesConstants.Synthetic:
				return new SyntheticAttribute(reader);
			case AttributesConstants.Module:
				return new ModuleAttribute(reader);
			default:
				throw new RuntimeException("Unknown attribute type: " + utf8.getString());
		}
	}
}
