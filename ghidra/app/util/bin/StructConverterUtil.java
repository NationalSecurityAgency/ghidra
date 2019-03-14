/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin;

import ghidra.program.model.data.*;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public final class StructConverterUtil {

	/**
	 * This is a convenience method for converting a class into structure.
	 * The class is reflected to extract the field members.
	 * Only private non-static fields are considered.
	 * Any field names that start with underscore ("_") are ignored.
	 * @param object the object to reflect
	 * @return a structure representing the class fields.
	 */
	public static DataType toDataType(Object object) {
		return toDataType(object.getClass(), object);
	}

	/**
	 * This is a convenience method for converting a class into structure.
	 * The class is reflected to extract the field members.
	 * Only private non-static fields are considered.
	 * Any field names that start with underscore ("_") are ignored.
	 * @param clazz the class to reflect
	 * @return a structure representing the class fields.
	 */
	public static DataType toDataType(Class<?> clazz) {
		return toDataType(clazz, null);
	}

	private static DataType toDataType(Class<?> clazz, Object object) {
		String name = parseName(clazz);
		Structure struct = new StructureDataType(name, 0);
		List<Field> fields = getFields(clazz);
		for (Field field : fields) {
			if (isValidField(field)) {
				DataType dt = getDataType(field, object);
				struct.add(dt, field.getName(), null);
			}
		}
		return struct;
	}

	private static List<Field> getFields(Class<?> clazz) {
		List<Field> fieldList = new ArrayList<Field>();
		if (clazz != null) {
			fieldList.addAll( getFields(clazz.getSuperclass()) );
			Field [] fields = clazz.getDeclaredFields();
			for (Field field : fields) {
				fieldList.add( field );
			}
		}
		return fieldList;
	}

	private static boolean isValidField(Field field) {
		int modifiers = field.getModifiers();
		if (Modifier.isStatic(modifiers)) {
			return false;
		}
		if (!Modifier.isPrivate(modifiers) &&
			!Modifier.isProtected(modifiers)) {
			return false;
		}
		if (field.getName().startsWith("_")) {
			return false;
		}
		return true;
	}

	private static DataType getDataType(Field field, Object object) {
		Class<?> fieldClazz = field.getType();
		if (fieldClazz.isArray()) {
			return getArrayDataType(field, object, fieldClazz);
		}
		if (fieldClazz.equals(byte.class) || fieldClazz.equals(Byte.class)) {
			return new ByteDataType();
		}
		if (fieldClazz.equals(short.class) || fieldClazz.equals(Short.class)) {
			return new WordDataType();
		}
		if (fieldClazz.equals(int.class) || fieldClazz.equals(Integer.class)) {
			return new DWordDataType();
		}
		if (fieldClazz.equals(long.class) || fieldClazz.equals(Long.class)) {
			return new QWordDataType();
		}
		if (fieldClazz.equals(float.class) || fieldClazz.equals(Float.class)) {
			return new FloatDataType();
		}
		if (fieldClazz.equals(double.class) || fieldClazz.equals(Double.class)) {
			return new DoubleDataType();
		}
		if (StructConverter.class.isAssignableFrom(fieldClazz)) {
			return toDataType(fieldClazz);
		}
		throw new RuntimeException("Unsupported datatype for automatic structure conversion - "+fieldClazz);
	}

	private static DataType getArrayDataType(Field field, Object object, Class<?> clazz) {
		Class<?> arrayClazz = clazz.getComponentType();

		if (arrayClazz.equals(byte.class)) {
			try {
				field.setAccessible(true);
				byte [] array = (byte [])field.get(object);
				int nElements = array.length;
				DataType arrayDataType = new ByteDataType();
				return new ArrayDataType(arrayDataType, nElements, arrayDataType.getLength());
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		else if (arrayClazz.equals(int.class)) {
			try {
				field.setAccessible(true);
				int [] array = (int [])field.get(object);
				int nElements = array.length;
				DataType arrayDataType = new DWordDataType();
				return new ArrayDataType(arrayDataType, nElements, arrayDataType.getLength());
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		throw new RuntimeException("Unsupported array datatype for automatic structure conversion - "+clazz);
	}

	public static String parseName(Class<?> clazz) {
		String fullyQualifiedName = clazz.getName();
		int pos = fullyQualifiedName.lastIndexOf('.');
		if (pos == -1) {//in a default package
			return fullyQualifiedName;
		}
		return fullyQualifiedName.substring(pos+1);
	}

	public static void main(String [] args) {

		Object [] objectArray = new Byte[25];

		System.out.println("here " + objectArray.length);
	}
}
