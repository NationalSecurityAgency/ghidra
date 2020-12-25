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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliElementType;
import ghidra.program.model.data.*;

public class CliBlobMarshalSpec extends CliBlob {
	private static final int INIT_VALUE = -1;

	private CliNativeType nativeIntrinsic;
	private CliNativeType arrayElemType;
	private int paramNum = INIT_VALUE;
	private int paramNumBytes;
	private int numElem = INIT_VALUE;
	private int numElemBytes;

	public enum CliNativeType {
		NATIVE_TYPE_END(0x00),
		NATIVE_TYPE_VOID(0x01),
		NATIVE_TYPE_BOOLEAN(0x02),
		NATIVE_TYPE_I1(0x03),
		NATIVE_TYPE_U1(0x04),
		NATIVE_TYPE_I2(0x05),
		NATIVE_TYPE_U2(0x06),
		NATIVE_TYPE_I4(0x07),
		NATIVE_TYPE_U4(0x08),
		NATIVE_TYPE_I8(0x09),
		NATIVE_TYPE_U8(0xa),
		NATIVE_TYPE_R4(0x0b),
		NATIVE_TYPE_R8(0x0c),
		NATIVE_TYPE_SYSCHAR(0x0d),
		NATIVE_TYPE_VARIANT(0x0e),
		NATIVE_TYPE_CURRENCY(0x0f),
		NATIVE_TYPE_PTR(0x10),

		NATIVE_TYPE_DECIMAL(0x11),
		NATIVE_TYPE_DATE(0x12),
		NATIVE_TYPE_BSTR(0x13),
		NATIVE_TYPE_LPSTR(0x14),
		NATIVE_TYPE_LPWSTR(0x15),
		NATIVE_TYPE_LPTSTR(0x16),
		NATIVE_TYPE_FIXEDSYSSTRING(0x17),
		NATIVE_TYPE_OBJECTREF(0x18),
		NATIVE_TYPE_IUNKNOWN(0x19),
		NATIVE_TYPE_IDISPATCH(0x1a),
		NATIVE_TYPE_STRUCT(0x1b),
		NATIVE_TYPE_INTF(0x1c),
		NATIVE_TYPE_SAFEARRAY(0x1d),
		NATIVE_TYPE_FIXEDARRAY(0x1e),
		NATIVE_TYPE_INT(0x1f),
		NATIVE_TYPE_UINT(0x20),

		NATIVE_TYPE_NESTEDSTRUCT(0x21),
		NATIVE_TYPE_BYVALSTR(0x22),
		NATIVE_TYPE_ANSIBSTR(0x23),
		NATIVE_TYPE_TBSTR(0x24),
		NATIVE_TYPE_VARIANTBOOL(0x25),
		NATIVE_TYPE_FUNC(0x26),

		NATIVE_TYPE_ASANY(0x28),
		NATIVE_TYPE_ARRAY(0x2a),
		NATIVE_TYPE_LPSTRUCT(0x2b),
		NATIVE_TYPE_CUSTOMMARSHALER(0x2c),
		NATIVE_TYPE_ERROR(0x2d),
		NATIVE_TYPE_IINSPECTABLE(0x2e),
		NATIVE_TYPE_HSTRING(0x2f),

		NATIVE_TYPE_MAX(0x50);

		private final int id;

		CliNativeType(int id) {
			this.id = id;
		}

		public int id() {
			return id;
		}

		public static CliNativeType fromInt(int id) {
			CliNativeType[] values = CliNativeType.values();
			for (CliNativeType value : values) {
				if (value.id == id) {
					return value;
				}
			}
			return null;
		}
	}

	public static class CliNativeTypeDataType extends EnumDataType {

		public final static CliNativeTypeDataType dataType = new CliNativeTypeDataType();

		public CliNativeTypeDataType() {
			super(new CategoryPath(PATH), "NativeType", 1);

			for (CliElementType c : CliElementType.values()) {
				add(c.toString(), c.id());
			}
		}
	}

	public CliBlobMarshalSpec(CliBlob blob) throws IOException {
		super(blob);

		BinaryReader reader = blob.getContentsReader();
		nativeIntrinsic = CliNativeType.fromInt(reader.readNextByte());
		if (nativeIntrinsic == CliNativeType.NATIVE_TYPE_ARRAY ||
			nativeIntrinsic == CliNativeType.NATIVE_TYPE_FIXEDARRAY) {
			arrayElemType = CliNativeType.fromInt(reader.readNextByte());

			// There is no sentinel other than blob size that indicates whether 0, 1, or 2 compressed unsigned ints follow
			if (contentsSize > 2) {
				long origIndex = reader.getPointerIndex();
				paramNum = decodeCompressedUnsignedInt(reader);
				paramNumBytes = (int) (reader.getPointerIndex() - origIndex);
				if (contentsSize > (2 + paramNumBytes)) {
					origIndex = reader.getPointerIndex();
					numElem = decodeCompressedUnsignedInt(reader);
					numElemBytes = (int) (reader.getPointerIndex() - origIndex);
				}
			}
		}
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(CliNativeTypeDataType.dataType, "NativeIntrinsic", "Type");
		if (arrayElemType != null) {
			struct.add(CliNativeTypeDataType.dataType, "ArrayElemTyp", null);
			if (paramNum != INIT_VALUE) {
				struct.add(getDataTypeForBytes(paramNumBytes), "ParamNum",
					"which parameter provides number of elems for this array");
				if (numElem != INIT_VALUE) {
					struct.add(getDataTypeForBytes(numElemBytes), "NumElem",
						"number of elements or additional elements");
				}
			}
		}
		return struct;
	}

	@Override
	public String getContentsName() {
		return "MarshalSpec";
	}

	@Override
	public String getContentsComment() {
		return "Defines a native type for marshalling between managed/unmanaged code";
	}

	@Override
	public String getRepresentation() {
		return "Blob (" + getContentsDataType().getDisplayName() + ")";
	}

}
