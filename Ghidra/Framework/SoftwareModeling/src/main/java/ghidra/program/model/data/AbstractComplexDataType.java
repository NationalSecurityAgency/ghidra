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
package ghidra.program.model.data;

import java.math.BigDecimal;

import generic.complex.Complex;
import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.WrappedMemBuffer;

/**
 * Base class for a variety of Complex data types of different sizes and types.
 */
public abstract class AbstractComplexDataType extends BuiltIn {

	protected static AbstractComplexDataType getDefaultComplexDataType(int size) {
		if (size == 8) {
			return Complex8DataType.dataType;
		}
		if (size == 16) {
			return Complex16DataType.dataType;
		}
		if (size == 32) {
			return Complex32DataType.dataType;
		}
		return null;
	}

	public static DataType getComplexDataType(int size, DataTypeManager dtm) {
		if (size < 1) {
			return DefaultDataType.dataType;
		}
		if (size % 2 != 0) {
			return Undefined.getUndefinedDataType(size);
		}
		int floatSize = size / 2;
		if (dtm != null) {
			DataOrganization dataOrganization = dtm.getDataOrganization();
			if (dataOrganization != null) {
				if (floatSize == dataOrganization.getFloatSize()) {
					return FloatComplexDataType.dataType.clone(dtm);
				}
				if (floatSize == dataOrganization.getDoubleSize()) {
					return DoubleComplexDataType.dataType.clone(dtm);
				}
				if (floatSize == dataOrganization.getLongDoubleSize()) {
					return LongDoubleComplexDataType.dataType.clone(dtm);
				}
			}
		}
		DataType dt = getDefaultComplexDataType(size);
		if (dt == null) {
			return Undefined.getUndefinedDataType(size);
		}
		return dt;
	}

	private final AbstractFloatDataType floatType;

	public AbstractComplexDataType(String name, AbstractFloatDataType floats, DataTypeManager dtm) {
		super(null, name, dtm);
		this.floatType = floats;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public int getLength() {
		return floatType.getLength() * 2;
	}

	@Override
	public String getDescription() {
		return "The data type for a complex number: a + bi";
	}

	private static double toDouble(Object obj) {
		if (obj instanceof Double) {
			return (Double) obj;
		}
		if (obj instanceof Float) {
			return (Float) obj;
		}
		if (obj instanceof Short) {
			// Looking at AbstractFloatDataType#getValue, this makes no sense to me
			return (Short) obj;
		}
		if (obj instanceof BigDecimal) {
			BigDecimal bd = (BigDecimal) obj;
			return bd.doubleValue();
		}
		throw new IllegalArgumentException(obj + "(" + obj.getClass() + ")");
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		Object a = floatType.getValue(buf, settings, length / 2);
		MemBuffer wrp = new WrappedMemBuffer(buf, length / 2);
		Object b = floatType.getValue(wrp, settings, length / 2);

		return new Complex(toDouble(a), toDouble(b));
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Object val = getValue(buf, settings, length);
		if (val == null) {
			return "??";
		}
		return val.toString();
	}
}
