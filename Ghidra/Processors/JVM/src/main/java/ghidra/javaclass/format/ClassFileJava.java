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
import ghidra.javaclass.format.attributes.AbstractAttributeInfo;
import ghidra.javaclass.format.attributes.AttributeFactory;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * A class file consists of a single ClassFile structure:
 * <pre>
 * 	ClassFile {
 * 		u4 magic;
 * 		u2 minor_version;
 * 		u2 major_version;
 * 		u2 constant_pool_count;
 * 		cp_info constant_pool[constant_pool_count-1];
 * 		u2 access_flags;
 * 		u2 this_class;
 * 		u2 super_class;
 * 		u2 interfaces_count;
 * 		u2 interfaces[interfaces_count];
 * 		u2 fields_count;
 * 		field_info fields[fields_count];
 * 		u2 methods_count;
 * 		method_info methods[methods_count];
 * 		u2 attributes_count;
 * 		attribute_info attributes[attributes_count];
 * 	}
 * </pre>
 */
public class ClassFileJava implements StructConverter {

	private int magic;
	private short minorVersion;
	private short majorVersion;
	private short constantPoolCount;
	private AbstractConstantPoolInfoJava[] constantPool;
	private short accessFlags;
	private short thisClass;
	private short superClass;
	private short interfacesCount;
	private short[] interfaces;
	private short fieldsCount;
	private FieldInfoJava[] fields;
	private short methodsCount;
	private MethodInfoJava[] methods;
	private short attributesCount;
	private AbstractAttributeInfo[] attributes;

	public ClassFileJava(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();

		if (magic != JavaClassConstants.MAGIC) {
			throw new IOException("Invalid Java Class File.");
		}

		minorVersion = reader.readNextShort();
		majorVersion = reader.readNextShort();
		constantPoolCount = reader.readNextShort();
		constantPool = new AbstractConstantPoolInfoJava[getConstantPoolCount()];
		//NOTE: start at index 1 per JVM specification!!!
		for (int i = 1; i < getConstantPoolCount(); i++) {
			constantPool[i] = ConstantPoolFactory.get(reader);

			//From section 4.4.5 of JVM specification:
			//All 8-byte constants take up two entries in the constant_pool table of the class
			//file. If a CONSTANT_Long_info or CONSTANT_Double_info structure is the item
			//in the constant_pool table at index n, then the next usable item in the pool is
			///located at index n+2. The constant_pool index n+1 must be valid but is considered
			//unusable.
			if (constantPool[i] instanceof ConstantPoolLongInfo ||
				constantPool[i] instanceof ConstantPoolDoubleInfo) {
				++i;
			}
		}
		accessFlags = reader.readNextShort();
		thisClass = reader.readNextShort();
		superClass = reader.readNextShort();
		interfacesCount = reader.readNextShort();
		interfaces = reader.readNextShortArray(getInterfacesCount());
		fieldsCount = reader.readNextShort();
		fields = new FieldInfoJava[getFieldsCount()];
		for (int i = 0; i < getFieldsCount(); i++) {
			fields[i] = new FieldInfoJava(reader, this);
		}
		methodsCount = reader.readNextShort();
		methods = new MethodInfoJava[getMethodsCount()];
		for (int i = 0; i < getMethodsCount(); i++) {
			methods[i] = new MethodInfoJava(reader, this);
		}
		attributesCount = reader.readNextShort();
		attributes = new AbstractAttributeInfo[getAttributesCount()];
		for (int i = 0; i < getAttributesCount(); i++) {
			attributes[i] = AttributeFactory.get(reader, getConstantPool());
		}
	}

	/**
	 * The magic item supplies the magic number identifying the class file format;
	 * it has the value 0xCAFEBABE.
	 * @return the magic number identifying the class file format
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * Returns the minor version number of this class.
	 * <p>
	 * If a class file has major version number M and minor 
	 * version number m, we denote the version of its
	 * class file format as M.m. Thus, class file format versions may be ordered
	 * lexicographically, for example, 1.5 < 2.0 < 2.1.
	 * <p>
	 * A Java virtual machine implementation can support a class file format of
	 * version v if and only if v lies in some contiguous range Mi.0 ? v ? Mj.m.
	 * <p>
	 * @return the minor version number of this class.
	 */
	public short getMinorVersion() {
		return minorVersion;
	}

	/**
	 * Returns the major version number of this class.
	 * <p>
	 * If a class file has major version number M and minor 
	 * version number m, we denote the version of its
	 * class file format as M.m. Thus, class file format versions may be ordered
	 * lexicographically, for example, 1.5 < 2.0 < 2.1.
	 * <p>
	 * A Java virtual machine implementation can support a class file format of
	 * version v if and only if v lies in some contiguous range Mi.0 ? v ? Mj.m.
	 * <p>
	 * @return the major version number of this class.
	 */
	public short getMajorVersion() {
		return majorVersion;
	}

	/**
	 * The value of the constant_pool_count item is equal to the number of entries
	 * in the constant_pool table plus one. A constant_pool index is considered
	 * valid if it is greater than zero and less than constant_pool_count, with the
	 * exception for constants of type long and double noted in ?4.4.5.
	 * @return the number of entries in the constant_pool table plus one
	 */
	public int getConstantPoolCount() {
		return constantPoolCount & 0xffff;
	}

	/**
	 * The constant_pool is a table of structures (?4.4) representing various string
	 * constants, class and interface names, field names, and other constants that are
	 * referred to within the ClassFile structure and its substructures. The format of
	 * each constant_pool table entry is indicated by its first "tag" byte.
	 * <p>
	 * The constant_pool table is indexed from 1 to constant_pool_count-1.
	 * @return the constant pool table
	 */
	public AbstractConstantPoolInfoJava[] getConstantPool() {
		return constantPool;
	}

	/**
	 * The value of the access_flags item is a mask of flags used to denote access
	 * permissions to and properties of this class or interface. The interpretation of
	 * each flag, when set, is as shown in Table 4.1.
	 * @return a mask of flags used to denote access permissions to and properties of this class or interface
	 */
	public short getAccessFlags() {
		return accessFlags;
	}

	/**
	 * The value of the this_class item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Class_info (?4.4.1) structure representing the class or interface
	 * defined by this class file.
	 * @return a valid index into the constant_pool table to a CONSTANT_Class_info
	 */
	public int getThisClass() {
		return thisClass & 0xffff;
	}

	/**
	 * For a class, the value of the super_class item either must be zero or
	 * must be a valid index into the constant_pool table. If the value of the
	 * super_class item is nonzero, the constant_pool entry at that index must be
	 * a CONSTANT_Class_info (?4.4.1) structure representing the direct superclass
	 * of the class defined by this class file. Neither the direct superclass nor any of
	 * its superclasses may have the ACC_FINAL flag set in the access_flags item of
	 * its ClassFile structure.
	 * <p>
	 * If the value of the super_class item is zero, then this class file must represent
	 * the class Object, the only class or interface without a direct superclass.
	 * <p>
	 * For an interface, the value of the super_class item must always be a valid
	 * index into the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Class_info structure representing the class Object.
	 * @return a valid index into the constant_pool table to a CONSTANT_Class_info
	 */
	public int getSuperClass() {
		return superClass & 0xffff;
	}

	/**
	 * The value of the interfaces_count item gives the number of direct
	 * superinterfaces of this class or interface type.
	 * @return the number of direct superinterfaces of this class
	 */
	public int getInterfacesCount() {
		return interfacesCount & 0xffff;
	}

	/**
	 * Each value in the interfaces array must be a valid index into
	 * the constant_pool table. The constant_pool entry at each value
	 * of interfaces[i], where 0 ? i < interfaces_count, must be a
	 * CONSTANT_Class_info (?4.4.1) structure representing an interface that is a
	 * direct superinterface of this class or interface type, in the left-to-right order
	 * given in the source for the type.
	 * @param i entry
	 * @return interface index
	 */
	public int getInterfacesEntry(int i) {
		return interfaces[i] & 0xffff;
	}

	/**
	 * The value of the fields_count item gives the number of field_info
	 * structures in the fields table. The field_info (?4.5) structures represent all
	 * fields, both class variables and instance variables, declared by this class or
	 * interface type.
	 * @return the number of field_info structures in the fields table
	 */
	public int getFieldsCount() {
		return fieldsCount & 0xffff;
	}

	/**
	 * Each value in the fields table must be a field_info (?4.5) structure giving
	 * a complete description of a field in this class or interface. The fields table
	 * includes only those fields that are declared by this class or interface. It does
	 * not include items representing fields that are inherited from superclasses or
	 * superinterfaces.
	 * @return an array of fields
	 */
	public FieldInfoJava[] getFields() {
		return fields;
	}

	/**
	 * The value of the methods_count item gives the number of method_info
	 * structures in the methods table.
	 * @return the number of method_info structures in the methods table
	 */
	public int getMethodsCount() {
		return methodsCount & 0xffff;
	}

	/**
	 * Each value in the methods table must be a method_info (?4.6) structure giving
	 * a complete description of a method in this class or interface. If neither of the
	 * ACC_NATIVE and ACC_ABSTRACT flags are set in the access_flags item of a
	 * method_info structure, the Java virtual machine instructions implementing the
	 * method are also supplied.
	 * <p>
	 * The method_info structures represent all methods declared by this class
	 * or interface type, including instance methods, class methods, instance
	 * initialization methods (?2.9), and any class or interface initialization method
	 * (?2.9). The methods table does not include items representing methods that are
	 * inherited from superclasses or superinterfaces.
	 * @return an array of methods
	 */
	public MethodInfoJava[] getMethods() {
		return methods;
	}

	/**
	 * The value of the attributes_count item gives the number of attributes
	 * in the attributes table of this class.
	 * @return the number of attributes in the attributes table
	 */
	public int getAttributesCount() {
		return attributesCount & 0xffff;
	}

	/**
	 * Each value of the attributes table must be an attribute_info structure.
	 * <p>
	 * The attributes defined by this specification as appearing in
	 * the attributes table of a ClassFile structure are the
	 * InnerClasses (?4.7.6), EnclosingMethod (?4.7.7), Synthetic (?4.7.8),
	 * Signature (?4.7.9), SourceFile (?4.7.10), SourceDebugExtension
	 * (?4.7.11), Deprecated (?4.7.15), RuntimeVisibleAnnotations (?4.7.16),
	 * RuntimeInvisibleAnnotations (?4.7.17), and BootstrapMethods (?4.7.21) attributes.
	 * <p>
	 * If a Java virtual machine implementation recognizes class files whose
	 * version number is 49.0 or above, it must recognize and correctly
	 * read Signature (?4.7.9), RuntimeVisibleAnnotations (?4.7.16), and
	 * RuntimeInvisibleAnnotations (?4.7.17) attributes found in the attributes
	 * table of a ClassFile structure of a class file whose version number is 49.0
	 * or above.
	 * <p>
	 * If a Java virtual machine implementation recognizes class files whose
	 * version number is 51.0 or above, it must recognize and correctly read
	 * BootstrapMethods (?4.7.21) attributes found in the attributes table of a
	 * ClassFile structure of a class file whose version number is 51.0 or above.
	 * A Java virtual machine implementation is required to silently ignore any or
	 * all attributes in the attributes table of a ClassFile structure that it does
	 * not recognize. Attributes not defined in this specification are not allowed to
	 * affect the semantics of the class file, but only to provide additional descriptive
	 * information (?4.7.1).
	 * @return an array of attributes
	 */
	public AbstractAttributeInfo[] getAttributes() {
		return attributes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "ClassFile";

		Structure structure = new StructureDataType(name, 0);
		structure.add(DWORD, "magic", null);

		structure.add(WORD, "minor_version", null);
		structure.add(WORD, "major_version", null);
		structure.add(WORD, "constant_pool_count", null);

		Structure constantPoolStruct = new StructureDataType("constant_pool", 0);
		for (int i = 0; i < constantPool.length; ++i) {
			if (constantPool[i] != null) {
				constantPoolStruct.add(constantPool[i].toDataType(),
					"constant_pool_0x" + Integer.toHexString(i), null);
			}
		}
		structure.add(constantPoolStruct, "constant_pool", null);

		structure.add(WORD, "access_flags", null);
		structure.add(WORD, "this_class", null);
		structure.add(WORD, "super_class", null);
		structure.add(WORD, "interfaces_count", null);

		if (getInterfacesCount() > 0) {
			DataType array = new ArrayDataType(WORD, getInterfacesCount(), WORD.getLength());
			structure.add(array, "interfaces", null);
		}

		structure.add(WORD, "field_count", null);

		if (getFieldsCount() > 0) {
			Structure fieldStruct = new StructureDataType("fields", 0);
			for (int i = 0; i < fields.length; ++i) {
				fieldStruct.add(fields[i].toDataType(), "field_" + i, null);
			}
			structure.add(fieldStruct, "fields", null);
		}

		structure.add(WORD, "method_count", null);

		if (getMethodsCount() > 0) {
			Structure methodsStruct = new StructureDataType("methods", 0);
			for (int i = 0; i < methods.length; ++i) {
				methodsStruct.add(methods[i].toDataType(), "methods_" + i, null);
			}
			structure.add(methodsStruct, "methods", null);
		}

		structure.add(WORD, "attributes_count", null);
		if (getAttributesCount() > 0) {
			Structure attributesStruct = new StructureDataType("attributes", 0);
			for (int i = 0; i < attributes.length; ++i) {
				attributesStruct.add(attributes[i].toDataType(), "attributes_" + i, null);
			}
			structure.add(attributesStruct, "attributes", null);
		}

		return structure;
	}
}
