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

import ghidra.app.util.bin.BinaryReader;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.javaclass.format.constantpool.ConstantPoolUtf8Info;

import java.io.IOException;

public class AttributeFactory {

	public static AbstractAttributeInfo get( BinaryReader reader, AbstractConstantPoolInfoJava [] constantPool ) throws IOException {
		
		int attributeNameIndex = reader.readShort( reader.getPointerIndex() );

		if ( attributeNameIndex < 1 || attributeNameIndex >= constantPool.length ) {
			throw new RuntimeException( "invalid index");
		}

		if ( !( constantPool[ attributeNameIndex ] instanceof ConstantPoolUtf8Info ) ) {
			throw new RuntimeException();
		}

		ConstantPoolUtf8Info utf8 = (ConstantPoolUtf8Info) constantPool[ attributeNameIndex ];

		if ( utf8.getString().equals( AttributesConstants.ConstantValue ) ) {
			return new ConstantValueAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.Code ) ) {
			return new CodeAttribute( reader, constantPool );
		}
		else if ( utf8.getString().equals( AttributesConstants.StackMapTable ) ) {
			return new StackMapTableAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.Exceptions ) ) {
			return new ExceptionsAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.InnerClasses ) ) {
			return new InnerClassesAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.EnclosingMethod ) ) {
			return new EnclosingMethodAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.Synthetic ) ) {
			return new SyntheticAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.Signature ) ) {
			return new SignatureAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.SourceFile ) ) {
			return new SourceFileAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.SourceDebugExtension ) ) {
			return new SourceDebugExtensionAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.LineNumberTable ) ) {
			return new LineNumberTableAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.LocalVariableTable ) ) {
			return new LocalVariableTableAttribute( reader, constantPool );
		}
		else if ( utf8.getString().equals( AttributesConstants.LocalVariableTypeTable ) ) {
			return new LocalVariableTypeTableAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.Deprecated ) ) {
			return new DeprecatedAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.RuntimeVisibleAnnotations ) ) {
			return new RuntimeVisibleAnnotationsAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.RuntimeInvisibleAnnotations ) ) {
			return new RuntimeInvisibleAnnotationsAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.RuntimeVisibleParameterAnnotations ) ) {
			return new RuntimeParameterAnnotationsAttribute( reader, true /*visible*/ );
		}
		else if ( utf8.getString().equals( AttributesConstants.RuntimeInvisibleParameterAnnotations ) ) {
			return new RuntimeParameterAnnotationsAttribute( reader, false /*invisible*/ );
		}
		else if ( utf8.getString().equals( AttributesConstants.AnnotationDefault ) ) {
			return new AnnotationDefaultAttribute( reader );
		}
		else if ( utf8.getString().equals( AttributesConstants.BootstrapMethods ) ) {
			return new BootstrapMethodsAttribute( reader );
		}

		throw new RuntimeException( "Unknown attribute type: " + utf8.getString() );
	}

}
