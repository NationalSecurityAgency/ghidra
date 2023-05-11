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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ghidra.program.model.data.*;

/**
 * Immutable information needed to create fields in a Ghidra structure data type, using information
 * from a java field.
 * 
 * @param <T>
 */
public class FieldOutputInfo<T> {
	private final FieldMappingInfo<T> fmi;
	private final String dataTypeName;
	private final int fieldOffset;
	private final boolean isVariableLength;
	private final int ordinal;
	private FieldOutputFunction<T> outputFunc;

	public FieldOutputInfo(FieldMappingInfo<T> fmi, String dataTypeName, boolean isVariableLength,
			int ordinal, int fieldOffset) {
		this.fmi = fmi;
		this.dataTypeName = dataTypeName;
		this.isVariableLength = isVariableLength;
		this.ordinal = ordinal;
		this.fieldOffset = fieldOffset;
	}

	public Field getField() {
		return fmi.getField();
	}

	public int getOrdinal() {
		return ordinal;
	}

	public boolean isVariableLength() {
		return isVariableLength;
	}

	public FieldOutputFunction<T> getOutputFunc() {
		return outputFunc;
	}

	/**
	 * Returns the value of this java field.
	 * 
	 * @param <R>
	 * @param structInstance object containing the field
	 * @param expectedType expected class of the value 
	 * @return value of the field
	 * @throws IOException 
	 */
	public <R> R getValue(T structInstance, Class<R> expectedType) throws IOException {
		try {
			Object val = fmi.getField().get(structInstance);
			if (expectedType.isInstance(val)) {
				return expectedType.cast(val);
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new IOException(e);
		}
		return null;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void setOutputFuncClass(Class<? extends FieldOutputFunction> funcClass,
			String getterName) {

		if (funcClass != FieldOutputFunction.class) {
			this.outputFunc = ReflectionHelper.createInstance(funcClass, this);
			return;
		}

		if (getterName != null && !getterName.isBlank()) {
			Method getter =
				ReflectionHelper.requireGetter(fmi.getField().getDeclaringClass(), getterName);
			getter.setAccessible(true);
			this.outputFunc =
				(context, structure, unused) -> outputFuncWithGetter(getter, context, structure);
			return;
		}

		if (dataTypeName != null && !dataTypeName.isBlank()) {
			this.outputFunc = this::dataTypeNameOutputFunc;
			return;
		}

		Class<?> fieldType = fmi.getField().getType();
		if (ReflectionHelper.isPrimitiveType(fieldType)) {
			this.outputFunc = this::primitiveOutputFunc;
			return;
		}
		if (fieldType.isArray() && ReflectionHelper.isPrimitiveType(fieldType.getComponentType())) {
			this.outputFunc = this::arrayOutputFunc;
			return;
		}

		if (ReflectionHelper.hasStructureMapping(fieldType)) {
			this.outputFunc = this::nestedStructureOutputFunc;
			return;
		}

		throw new IllegalArgumentException("Invalid FieldOutput " + fmi.getField());
	}

	private void preAddField(Structure structure) throws IOException {
		if (fieldOffset >= 0) {
			int currentOffset = getStructLength(structure);
			if (currentOffset > fieldOffset) {
				throw new IOException("Invalid field offset %d, structure is already %d"
						.formatted(fieldOffset, currentOffset));
			}
			if (currentOffset < fieldOffset) {
				structure.add(Undefined.getUndefinedDataType(fieldOffset - currentOffset), -1);
			}
		}
	}

	private void outputFuncWithGetter(Method getter, StructureContext<T> context,
			Structure structure) throws IOException {
		Object getterResult =
			ReflectionHelper.callGetter(getter, context.getStructureInstance(), Object.class);
		if (getterResult == null) {
			//do nothing
		}
		else if (getterResult instanceof DataType dt) {
			preAddField(structure);
			structure.add(dt, fmi.getFieldName(), null);
		}
		else if (getterResult instanceof DataTypeInstance dti) {
			preAddField(structure);
			structure.add(dti.getDataType(), dti.getLength(), fmi.getFieldName(), null);
		}
		else {
			throw new IOException("Bad result type for FieldOutput.getter: %s"
					.formatted(getterResult.getClass().getSimpleName()));
		}
	}

	private void dataTypeNameOutputFunc(StructureContext<T> context, Structure structure,
			FieldOutputInfo<T> foi) throws IOException {
		DataType dt = context.getDataTypeMapper().getType(dataTypeName, DataType.class);
		if (dt == null) {
			throw new IOException(
				"Missing data type %s for field %s".formatted(dataTypeName, fmi.getFieldName()));
		}
		preAddField(structure);
		if (dt instanceof Dynamic) {
			throw new IOException("Invalid dynamic sized data type %s for field %s"
					.formatted(dt.getName(), fmi.getFieldName()));
		}
		structure.add(dt, fmi.getFieldName(), null);
	}

	private void primitiveOutputFunc(StructureContext<T> context, Structure structure,
			FieldOutputInfo<T> foi) throws IOException {
		DataType dt = ReflectionHelper.getPrimitiveOutputDataType(fmi.getField().getType(),
			fmi.getLength(), fmi.getSignedness(), context.getDataTypeMapper());
		preAddField(structure);
		structure.add(dt, fmi.getFieldName(), null);
	}

	private void arrayOutputFunc(StructureContext<T> context, Structure structure,
			FieldOutputInfo<T> foi) throws IOException {
		// only outputs array of primitive value
		Object fieldValue = foi.getValue(context.getStructureInstance(), Object.class);
		DataType dt = ReflectionHelper.getArrayOutputDataType(fieldValue, fmi.getField().getType(),
			fmi.getLength(), fmi.getSignedness(), context.getDataTypeMapper());
		preAddField(structure);
		structure.add(dt, fmi.getFieldName(), null);
	}

	private void nestedStructureOutputFunc(StructureContext<T> context, Structure structure,
			FieldOutputInfo<T> foi) throws IOException {
		Object nestedStruct = foi.getValue(context.getStructureInstance(), Object.class);
		if (nestedStruct == null) {
			return;
		}

		StructureContext<?> nestedStructContext =
			context.getDataTypeMapper().getExistingStructureContext(nestedStruct);
		if (nestedStructContext == null) {
			throw new IOException(
				"Missing StructureContext for " + nestedStruct.getClass().getSimpleName());
		}
		DataType nestedStructDT = nestedStructContext.getStructureDataType();
		preAddField(structure);
		structure.add(nestedStructDT, fmi.getFieldName(), null);
	}

	private static int getStructLength(Structure struct) {
		return struct.isZeroLength() ? 0 : struct.getLength();
	}

}
