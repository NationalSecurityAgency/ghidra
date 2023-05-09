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
package ghidra.app.util.bin.format.golang.structmapping;

import java.util.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;

/**
 * Immutable information needed to deserialize a field in a structure mapped class.
 * 
 * @param <T>
 */
public class FieldMappingInfo<T> {
	/**
	 * Creates a FieldMappingInfo instance, used when the structure is not variable length.
	 *  
	 * @param <T>
	 * @param field
	 * @param dtc
	 * @param signedness
	 * @param length
	 * @return
	 */
	public static <T> FieldMappingInfo<T> createEarlyBinding(Field field, DataTypeComponent dtc,
			Signedness signedness, int length) {

		signedness = signedness == Signedness.Unspecified
				? ReflectionHelper.getDataTypeSignedness(dtc.getDataType())
				: signedness;
		length = length != -1 ? length : dtc.getLength();

		return new FieldMappingInfo<>(field, dtc.getFieldName(), dtc, signedness, length);
	}

	/**
	 * Creates a FieldMappingInfo instance, used when the structure is variable length and there is
	 * no pre-defined Ghidra Structure data type.
	 * 
	 * @param <T>
	 * @param field
	 * @param fieldName
	 * @param signedness
	 * @param length
	 * @return
	 */
	public static <T> FieldMappingInfo<T> createLateBinding(Field field, String fieldName,
			Signedness signedness, int length) {

		return new FieldMappingInfo<>(field, fieldName, null, signedness, length);
	}

	private final Field field;
	private final String dtcFieldName;
	private final DataTypeComponent dtc;
	private final Signedness signedness;
	private final int length;
	private final List<FieldMarkupFunction<T>> markupFuncs = new ArrayList<>();

	private FieldReadFunction<T> readerFunc;

	private FieldMappingInfo(Field field, String dtcFieldName, DataTypeComponent dtc,
			Signedness signedness, int length) {
		this.field = field;
		this.dtcFieldName = dtcFieldName;
		this.dtc = dtc;
		this.signedness = signedness;
		this.length = length;
	}

	public Field getField() {
		return field;
	}

	public String getFieldName() {
		return dtcFieldName;
	}

	public DataTypeComponent getDtc() {
		return dtc;
	}

	public DataTypeComponent getDtc(Structure structure) {
		return dtc != null
				? dtc
				: findDtc(structure);
	}

	public DataTypeComponent findDtc(Structure struct) {
		for (DataTypeComponent dtc : struct.getDefinedComponents()) {
			if (dtcFieldName.equals(dtc.getFieldName())) {
				return dtc;
			}
		}
		return null;
	}

	public FieldReadFunction<T> getReaderFunc() {
		return readerFunc;
	}

	public List<FieldMarkupFunction<T>> getMarkupFuncs() {
		return markupFuncs;
	}

	public void addMarkupFunc(FieldMarkupFunction<T> func) {
		markupFuncs.add(func);
	}

	public int getLength() {
		return length;
	}

	public Signedness getSignedness() {
		return signedness;
	}

	public boolean isUnsigned() {
		return signedness == Signedness.Unsigned;
	}

	public boolean isStructureMappedType() {
		return ReflectionHelper.hasStructureMapping(field.getType());
	}

	public <R> R getValue(T structInstance, Class<R> expectedType) throws IOException {
		return ReflectionHelper.getFieldValue(structInstance, field, expectedType);
	}

	public void addMarkupNestedFuncs() {
		Markup ma = field.getAnnotation(Markup.class);
		if (ma != null) {
			Class<?> fieldType = field.getType();
			if (!ReflectionHelper.hasStructureMapping(fieldType)) {
				throw new IllegalArgumentException("Invalid @Markup, %s is not structure mapped. %s"
						.formatted(field.getType().getSimpleName(), field));
			}
			markupFuncs.add(this::markupNestedStructure);
		}
	}

	public void addMarkupReferenceFunc() {
		MarkupReference mufa = field.getAnnotation(MarkupReference.class);
		if (mufa != null) {
			markupFuncs.add(makeMarkupReferenceFunc(mufa.value()));
		}

	}

	public void addCommentMarkupFuncs() {
		Class<?> clazz = field.getDeclaringClass();
		PlateComment pca = field.getAnnotation(PlateComment.class);
		if (pca != null) {
			Method commentGetter =
				ReflectionHelper.getCommentMethod(clazz, pca.value(), field.getName());
			markupFuncs.add(createCommentMarkupFunc(commentGetter, CodeUnit.PLATE_COMMENT, "\n"));
		}

		EOLComment eca = field.getAnnotation(EOLComment.class);
		if (eca != null) {
			Method commentGetter =
				ReflectionHelper.getCommentMethod(clazz, eca.value(), field.getName());
			markupFuncs.add(createCommentMarkupFunc(commentGetter, CodeUnit.EOL_COMMENT, ";"));
		}
	}

	private FieldMarkupFunction<T> createCommentMarkupFunc(Method commentGetter, int commentType,
			String sep) {
		return context -> {
			T obj = context.getStructureInstance();
			Object val = ReflectionHelper.callGetter(commentGetter, obj);
			if (val != null) {
				if (val instanceof Collection<?> c && c.isEmpty()) {
					return;
				}
				context.appendComment(commentType, null, val.toString(), sep);
			}
		};
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void setReadFuncClass(Class<? extends FieldReadFunction> readFuncClass) {
		if (readFuncClass != FieldReadFunction.class) {
			this.readerFunc = ReflectionHelper.createInstance(readFuncClass, this);
			return;
		}

		Class<?> fieldType = field.getType();
		if (ReflectionHelper.isPrimitiveType(fieldType)) {
			this.readerFunc = getReadPrimitiveValueFunc(fieldType);
			return;
		}

		if (ReflectionHelper.hasStructureMapping(fieldType)) {
			this.readerFunc = this::readStructureMappedTypeFunc;
			return;
		}

	}

	private FieldReadFunction<T> getReadPrimitiveValueFunc(Class<?> destClass) {

		if (destClass == Long.class || destClass == Long.TYPE) {
			return (context) -> context.fieldInfo().isUnsigned()
					? context.reader().readNextUnsignedValue(context.fieldInfo().getLength())
					: context.reader().readNextValue(context.fieldInfo().getLength());
		}
		if (destClass == Integer.class || destClass == Integer.TYPE) {
			return (context) -> context.fieldInfo().isUnsigned()
					? (int) context.reader().readNextUnsignedValue(context.fieldInfo().getLength())
					: (int) context.reader().readNextValue(context.fieldInfo().getLength());
		}
		if (destClass == Short.class || destClass == Short.TYPE) {
			return (context) -> context.fieldInfo().isUnsigned()
					? (short) context.reader()
							.readNextUnsignedValue(context.fieldInfo().getLength())
					: (short) context.reader().readNextValue(context.fieldInfo().getLength());
		}
		if (destClass == Byte.class || destClass == Byte.TYPE) {
			return (context) -> context.fieldInfo().isUnsigned()
					? (byte) context.reader().readNextUnsignedValue(context.fieldInfo().getLength())
					: (byte) context.reader().readNextValue(context.fieldInfo().getLength());
		}
		if (destClass == Character.class || destClass == Character.TYPE) {
			return (context) -> context.fieldInfo().isUnsigned()
					? (char) context.reader().readNextUnsignedValue(context.fieldInfo().getLength())
					: (char) context.reader().readNextValue(context.fieldInfo().getLength());
		}
		return null;
	}

	private Object readStructureMappedTypeFunc(FieldContext<T> context) throws IOException {
		return context.structureContext()
				.getDataTypeMapper()
				.readStructure(field.getType(), context.reader());
	}

//	@SuppressWarnings({ "unchecked", "rawtypes" })
//	private FieldMarkupFunction<T> makeMarkupFunc(
//			Class<? extends FieldMarkupFunction> markupFuncClass, String getterName) {
//		if (markupFuncClass != FieldMarkupFunction.class) {
//			return ReflectionHelper.createInstance(markupFuncClass, this);
//		}
//
//		if (getterName != null && !getterName.isBlank()) {
//			Method getter = ReflectionHelper.findGetter(field.getDeclaringClass(), getterName);
//			if (getter == null) {
//				throw new IllegalArgumentException(
//					"Missing FieldMarkup getter %s for %s".formatted(getterName, field));
//			}
//			getter.setAccessible(true);
//			return (context) -> markupFieldWithGetter(getter, context);
//		}
//
//		Class<?> fieldType = field.getType();
//		if (ReflectionHelper.hasStructureMapping(fieldType)) {
//			return this::markupNestedStructure;
//		}
//
//		Method getter = ReflectionHelper.findGetter(field.getDeclaringClass(), field.getName());
//		if (getter != null) {
//			getter.setAccessible(true);
//			return (context) -> markupFieldWithGetter(getter, context);
//		}
//
//		throw new IllegalArgumentException("Invalid FieldMarkup: " + field);
//	}

//	private void markupFieldWithGetter(Method getterMethod, FieldContext<T> fieldContext)
//			throws IOException {
//		Object getterValue =
//			ReflectionHelper.callGetter(getterMethod, fieldContext.getStructureInstance());
//		if (getterValue != null) {
//			if (getterValue instanceof Collection<?> c && c.isEmpty()) {
//				return;
//			}
//			fieldContext.appendComment(CodeUnit.EOL_COMMENT, "", getterValue.toString(), ";");
//		}
//	}

	private void markupNestedStructure(FieldContext<T> fieldContext) throws IOException {
		fieldContext.getDataTypeMapper().markup(fieldContext.getValue(Object.class), true);
	}

	private FieldMarkupFunction<T> makeMarkupReferenceFunc(String getterName) {
		getterName = getterName == null || getterName.isBlank() ? field.getName() : getterName;

		Method getter = ReflectionHelper.requireGetter(field.getDeclaringClass(), getterName);
		getter.setAccessible(true);
		return (context) -> addRefToFieldWithGetter(getter, context);
	}

	private void addRefToFieldWithGetter(Method getterMethod, FieldContext<T> fieldContext)
			throws IOException {
		Object getterValue =
			ReflectionHelper.callGetter(getterMethod, fieldContext.getStructureInstance());
		if (getterValue != null) {
			Address addr = getterValue instanceof Address getterAddr
					? getterAddr
					: fieldContext.getDataTypeMapper().getExistingStructureAddress(getterValue);
			if (addr != null) {
				fieldContext.addReference(addr);
			}
		}
	}

}
