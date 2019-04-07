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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.*;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.javaclass.format.JavaClassConstants;
import ghidra.javaclass.format.constantpool.*;

public class TestClassFileCreator {

	private static final String RESOURCE_DIRECTORY = File.separator + "resources" + File.separator;
	public static final int CLASS_INFO_SIZE = 3;
	public static final int METHODREF_INFO_SIZE = 5;
	public static final int STRING_INFO_SIZE = 3;
	public static final int INTEGER_INFO_SIZE = 5;
	public static final int FLOAT_INFO_SIZE = 5;
	public static final int LONG_INFO_SIZE = 9;
	public static final int DOUBLE_INFO_SIZE = 9;
	public static final int FIELDREF_INFO_SIZE = 5;
	public static final int INTERFACEMETHODREF_INFO_SIZE = 5;
	public static final int INVOKEDYNAMIC_INFO_SIZE = 5;
	public static final int NAMEANDTYPE_INFO_SIZE = 5;

	private TestClassFileCreator(){
		//private constructor to enforce noninstantiability
	}
	
	public static AbstractConstantPoolInfoJava[] getConstantPoolFromBytes(byte[] bytes) throws IOException{
		ByteProvider provider = new ByteArrayProvider(bytes);
		return getConstantPoolFromByteProvider(provider);
	}
	
	public static AbstractConstantPoolInfoJava[] getConstantPoolFromFile(String testFileName) throws IOException{
		Application.initializeApplication(new GhidraApplicationLayout(),
			new ApplicationConfiguration());
		ResourceFile moduleRoot = Application.getMyModuleRootDirectory();

		File testFile = new File(moduleRoot.getAbsolutePath() + RESOURCE_DIRECTORY + testFileName);
		ByteProvider provider = new RandomAccessByteProvider(testFile);
		return getConstantPoolFromByteProvider(provider);
	}
		
	public static AbstractConstantPoolInfoJava[] getConstantPoolFromByteProvider(ByteProvider provider) throws IOException{
		//java is big endian
		BinaryReader reader = new BinaryReader(provider, false);

		int magic = reader.readNextInt();
		if (magic != JavaClassConstants.MAGIC) {
			throw new IOException("Invalid Java Class File.");
		}

		@SuppressWarnings("unused") //just advance past it
		short minorVersion = reader.readNextShort();
		@SuppressWarnings("unused") //just advance past it
		short majorVersion = reader.readNextShort();
		short constantPoolCount = reader.readNextShort();
		
		AbstractConstantPoolInfoJava[] constantPool = new AbstractConstantPoolInfoJava[constantPoolCount+1];
		//NOTE: start at index 1 per JVM specification!!!
		for (int i = 1; i < constantPoolCount; i++) {
			constantPool[i] = ConstantPoolFactory.get(reader);
			if (constantPool[i] instanceof ConstantPoolLongInfo ||
					constantPool[i] instanceof ConstantPoolDoubleInfo) {
				++i;
			}
		}
		provider.close();
		return constantPool;
	}

	public static void appendMagic(ArrayList<Byte> classFile) {
		classFile.add((byte)0xca);
		classFile.add((byte)0xfe);
		classFile.add((byte)0xba);
		classFile.add((byte)0xbe);
	}

	public static void appendVersions(ArrayList<Byte> classFile) {
		classFile.add((byte) 0);
		classFile.add((byte) 0);
		classFile.add((byte) 0);
		classFile.add((byte) 0x34);
		
	}

	public static void appendCount(ArrayList<Byte> classFile, short	s) {
		appendShort(classFile,s);
	}
	
	public static void appendInteger(ArrayList<Byte> classFile, int i){
		classFile.add(ConstantPoolTagsJava.CONSTANT_Integer);
		appendInt(classFile,i);
		
	}

	public static byte[] getByteArray(ArrayList<Byte> classFile) {
		int length = classFile.size();
		byte[] bytes = new byte[length];
		for (int i = 0; i < length; ++i){
			bytes[i] = classFile.get(i);
		}
		return bytes;
	}

	public static void appendFloat(ArrayList<Byte> classFile, float input) {
		int i = (int) input;
		classFile.add(ConstantPoolTagsJava.CONSTANT_Float);
		appendInt(classFile,i);
	}
	
	public static void appendDouble(ArrayList<Byte> classFile, double input){
		long l = (long) input;
		classFile.add(ConstantPoolTagsJava.CONSTANT_Double);
		appendLongValue(classFile, l);
	}

	public static void appendLong(ArrayList<Byte> classFile, long l) {
		classFile.add(ConstantPoolTagsJava.CONSTANT_Long);
		appendLongValue(classFile, l);
		
	}

	public static void appendString(ArrayList<Byte> classFile, short string_index) {
		classFile.add(ConstantPoolTagsJava.CONSTANT_String);
		appendShort(classFile, string_index);
	}
	
	public static void appendUtf8(ArrayList<Byte> classFile, String input){
		classFile.add(ConstantPoolTagsJava.CONSTANT_Utf8);
		byte[] bytes = input.getBytes();
		classFile.add((byte) ((input.length() >> 8) & 0xff));
		classFile.add((byte) (input.length() & 0xff));
		for (byte b : bytes) {
			classFile.add(b);
		}
	}
	
	public static void appendClass(ArrayList<Byte> classFile, short name_index){
		classFile.add(ConstantPoolTagsJava.CONSTANT_Class);
		appendShort(classFile, name_index);
	}
	
	public static void appendMethodType(ArrayList<Byte> classFile, short s){
		classFile.add(ConstantPoolTagsJava.CONSTANT_MethodType);
		appendShort(classFile, s);
	}

	public static void appendFieldRef(ArrayList<Byte> classFile, short class_index, short name_and_type_index) {
	    classFile.add( ConstantPoolTagsJava.CONSTANT_Fieldref);
	    appendShort(classFile, class_index);
	    appendShort(classFile, name_and_type_index);	
	}
	
	public static void appendMethodRef(ArrayList<Byte> classFile, short class_index, short name_and_type_index) {
	    classFile.add( ConstantPoolTagsJava.CONSTANT_Methodref);
	    appendShort(classFile, class_index);
	    appendShort(classFile, name_and_type_index);	
	}
	
	public static void appendInterfaceMethodRef(ArrayList<Byte> classFile, short class_index, short name_and_type_index) {
	    classFile.add( ConstantPoolTagsJava.CONSTANT_InterfaceMethodref);
	    appendShort(classFile, class_index);
	    appendShort(classFile, name_and_type_index);	
	}
	
	public static void appendInvokeDynamicInfo(ArrayList<Byte> classFile, short bootstrap_method_attr_index, short name_and_type_index){
		classFile.add( ConstantPoolTagsJava.CONSTANT_InvokeDynamic);
		appendShort(classFile, bootstrap_method_attr_index);
		appendShort(classFile, name_and_type_index);
	}
	
	
	public static void appendNameAndType(ArrayList<Byte> classFile, short name_index, short descriptor_index){
		classFile.add( ConstantPoolTagsJava.CONSTANT_NameAndType);
		appendShort(classFile, name_index);
		appendShort(classFile, descriptor_index);
	}

	private static void appendShort(ArrayList<Byte> classFile, short s){
		classFile.add((byte) ((s >> 8) & 0xff));
		classFile.add((byte) (s & 0xff));	
	}
	
	private static void appendInt(ArrayList<Byte> classFile, int i){
		classFile.add((byte) ((i >> 24) & 0xff));
		classFile.add((byte) ((i >> 16) & 0xff));
		classFile.add((byte) ((i >> 8) & 0xff));
		classFile.add((byte) (i & 0xff));
	}
	
	private static void appendLongValue(ArrayList<Byte> classFile, long l){
		classFile.add((byte) ((l >> 56) & 0xff));
		classFile.add((byte) ((l >> 48) & 0xff));
		classFile.add((byte) ((l >> 40) & 0xff));
		classFile.add((byte) ((l >> 32) & 0xff));
		classFile.add((byte) ((l >> 24) & 0xff));
		classFile.add((byte) ((l >> 16) & 0xff));
		classFile.add((byte) ((l >> 8) & 0xff));
		classFile.add((byte) (l & 0xff));	
	}

	public static void appendMethodHandleFieldRef(ArrayList<Byte> classFile, byte reference_kind, short reference_index ) {
		classFile.add(ConstantPoolTagsJava.CONSTANT_MethodHandle);
		classFile.add(reference_kind);
		appendShort(classFile, reference_index);	
	}
	
	
	
}
