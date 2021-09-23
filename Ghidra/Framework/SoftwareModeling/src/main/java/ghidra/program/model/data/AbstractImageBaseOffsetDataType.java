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

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

abstract class AbstractImageBaseOffsetDataType extends BuiltIn {

	AbstractImageBaseOffsetDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	abstract DataType getScalarDataType();

	static String generateName(DataType dt) {
		return "ImageBaseOffset" + dt.getLength() * 8;
	}

	static String generateMnemonic(DataType dt) {
		return "ibo" + dt.getLength() * 8;
	}

	static String generateDescription(DataType dt) {
		return (dt.getLength() * 8) + "-bit Image Base Offset";
	}

	@Override
	public String getDescription() {
		DataType dt = getScalarDataType();
		return generateDescription(dt);
	}

	@Override
	public String getMnemonic(Settings settings) {
		DataType dt = getScalarDataType();
		return generateMnemonic(dt);
	}

	@Override
	public int getLength() {
		return getScalarDataType().getLength();
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Address addr = (Address) getValue(buf, settings, length);
		if (addr == null) { // could not create address, so return "Not a pointer (NaP)"
			return "NaP";
		}
		return addr.toString();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		DataType dt = getScalarDataType();
		Address imageBase = buf.getMemory().getProgram().getImageBase();
		Scalar value = (Scalar) dt.getValue(buf, settings, length);
		if (value != null && value.getUnsignedValue() != 0) {
			try {
				return imageBase.add(value.getUnsignedValue());
			}
			catch (AddressOutOfBoundsException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public boolean isEncodable() {
		return getScalarDataType().isEncodable();
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		if (!(value instanceof Address)) {
			throw new DataTypeEncodeException("Requires Address", value, this);
		}
		Address addressValue = (Address) value;
		Address imageBase = buf.getMemory().getProgram().getImageBase();
		long offset;
		try {
			offset = addressValue.subtract(imageBase);
		}
		catch (IllegalArgumentException e) {
			throw new DataTypeEncodeException(value, this, e);
		}
		Scalar scalarOffset = new Scalar(imageBase.getSize(), offset, false);
		DataType dt = getScalarDataType();
		return dt.encodeValue(scalarOffset, buf, settings, length);
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		Address address = buf.getMemory().getProgram().getAddressFactory().getAddress(repr);
		if (address == null) {
			throw new DataTypeEncodeException("Cannot parse address", repr, this);
		}
		return encodeValue(address, buf, settings, length);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}
}
