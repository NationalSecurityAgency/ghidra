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

public final class ConstantPoolTagsJava {

	public final static byte CONSTANT_Class = 7;
	public final static byte CONSTANT_Fieldref = 9;
	public final static byte CONSTANT_Methodref = 10;
	public final static byte CONSTANT_InterfaceMethodref = 11;
	public final static byte CONSTANT_String = 8;
	public final static byte CONSTANT_Integer = 3;
	public final static byte CONSTANT_Float = 4;
	public final static byte CONSTANT_Long = 5;
	public final static byte CONSTANT_Double = 6;
	public final static byte CONSTANT_NameAndType = 12;
	public final static byte CONSTANT_Utf8 = 1;
	public final static byte CONSTANT_MethodHandle = 15;
	public final static byte CONSTANT_MethodType = 16;
	public final static byte CONSTANT_Dynamic = 17;
	public final static byte CONSTANT_InvokeDynamic = 18;
	public final static byte CONSTANT_Module = 19;
	public final static byte CONSTANT_Package = 20;

}
