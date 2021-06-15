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

	// Underlying marshal type
	private CliNativeType nativeIntrinsic;

	// Element type of an underlying SafeArray
	private CliSafeArrayElemType safeArrayElemType;

	// FixedString ID of an underlying FIXEDSYSSTRING
	private int fixedStringId;

	// Parameters in an underlying CUSTOMMARSHALLER
	private String customMarshallerGuidOrTypeName;
	private String customMarshallerTypeName;
	private String customMarshallerCookie;

	// Type, count, and byte size of count of an underlying array
	private CliNativeType arrayElemType;
	private int arrayParamNum = INIT_VALUE;
	private int arrayParamNumBytes;
	private int arrayNumElem = INIT_VALUE;
	private int arrayNumElemBytes;

	private static final int INIT_VALUE = -1;
	private static final int CLIBLOBMARSHALSPEC_GUID_LENGTH = 0x26;

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

	public enum CliSafeArrayElemType {
		VT_I2(0x2),
		VT_I4(0x3),
		VT_R4(0x4),
		VT_R8(0x5),
		VT_CY(0x6),
		VT_DATE(0x7),
		VT_BSTR(0x8),
		VT_DISPATCH(0x9),
		VT_ERROR(0xA),
		VT_BOOL(0xB),
		VT_VARIANT(0xC),
		VT_UNKNOWN(0xD),
		VT_DECIMAL(0xE),
		VT_I1(0x10),
		VT_UI1(0x11),
		VT_UI2(0x12),
		VT_UI4(0x13),
		VT_INT(0x16),
		VT_UINT(0x17);

		private final int id;

		CliSafeArrayElemType(int id) {
			this.id = id;
		}

		public int id() {
			return id;
		}

		public static CliSafeArrayElemType fromInt(int id) {
			CliSafeArrayElemType[] values = CliSafeArrayElemType.values();
			for (CliSafeArrayElemType value : values) {
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
			// TODO: specify CategoryPath, etc.
			for (CliElementType c : CliElementType.values()) {
				add(c.toString(), c.id());
			}
		}
	}

	public static class CliSafeArrayElemTypeDataType extends EnumDataType {

		public final static CliNativeTypeDataType dataType = new CliNativeTypeDataType();

		public CliSafeArrayElemTypeDataType() {
			super(new CategoryPath(PATH), "ElemType", 1);
			// TODO: specify CategoryPath, etc.
			for (CliSafeArrayElemType c : CliSafeArrayElemType.values()) {
				add(c.toString(), c.id());
			}
		}
	}

	public CliBlobMarshalSpec(CliBlob blob) throws IOException {
		super(blob);

		BinaryReader reader = blob.getContentsReader();

		nativeIntrinsic = CliNativeType.fromInt(reader.readNextByte());

		switch (nativeIntrinsic) {
			case NATIVE_TYPE_ARRAY:
			case NATIVE_TYPE_FIXEDARRAY:
				arrayElemType = CliNativeType.fromInt(reader.readNextByte());

				// There is no sentinel other than blob size that indicates whether
				// 0, 1, or 2 compressed unsigned ints follow
				if (contentsSize > 2) {
					long origIndex = reader.getPointerIndex();
					arrayParamNum = decodeCompressedUnsignedInt(reader);
					arrayParamNumBytes = (int) (reader.getPointerIndex() - origIndex);
					if (contentsSize > (2 + arrayParamNumBytes)) {
						origIndex = reader.getPointerIndex();
						arrayNumElem = decodeCompressedUnsignedInt(reader);
						arrayNumElemBytes = (int) (reader.getPointerIndex() - origIndex);
					}
				}
				break;

			case NATIVE_TYPE_FIXEDSYSSTRING:
				fixedStringId = reader.readNextByte();
				break;

			case NATIVE_TYPE_CUSTOMMARSHALER:
				customMarshallerGuidOrTypeName =
					reader.readTerminatedString(reader.getPointerIndex(), '\0');
				customMarshallerTypeName =
					reader.readTerminatedString(reader.getPointerIndex(), '\0');
				if (reader.peekNextByte() > 0) {
					customMarshallerCookie =
						reader.readTerminatedString(reader.getPointerIndex(), '\0');
				}
				break;

			case NATIVE_TYPE_SAFEARRAY:
				safeArrayElemType = CliSafeArrayElemType.fromInt(reader.readNextByte());
				break;

			default:
				break;
		}
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(CliNativeTypeDataType.dataType, nativeIntrinsic.name(), "NativeIntrinsic");

		switch (nativeIntrinsic) {
			case NATIVE_TYPE_ARRAY:
			case NATIVE_TYPE_FIXEDARRAY:
				struct.add(CliNativeTypeDataType.dataType, arrayElemType.name(), "ArrayElemTyp");
				if (arrayParamNum != INIT_VALUE) {
					struct.add(getDataTypeForBytes(arrayParamNumBytes), "ParamNum",
						"which parameter provides number of elems for this array");
					if (arrayNumElem != INIT_VALUE) {
						struct.add(getDataTypeForBytes(arrayNumElemBytes), "NumElem",
							"number of elements or additional elements");
					}
				}
				break;

			case NATIVE_TYPE_FIXEDSYSSTRING:
				struct.add(BYTE, "Fixed String Identifier", "");
				break;

			case NATIVE_TYPE_SAFEARRAY:
				struct.add(CliSafeArrayElemTypeDataType.dataType, "ElemType", "Type");
				break;

			case NATIVE_TYPE_CUSTOMMARSHALER:
				struct.add(UTF8, customMarshallerGuidOrTypeName.length(), "", "GUID or Type Name");
				struct.add(UTF8, customMarshallerGuidOrTypeName.length(), "", "Type Name");
				if (customMarshallerCookie.compareTo("") != 0) {
					struct.add(UTF8, customMarshallerGuidOrTypeName.length(), "", "Cookie");
				}
				else {
					struct.add(BYTE, "Terminator for absent Cookie", "");
				}
				break;

			default:
				break;
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
