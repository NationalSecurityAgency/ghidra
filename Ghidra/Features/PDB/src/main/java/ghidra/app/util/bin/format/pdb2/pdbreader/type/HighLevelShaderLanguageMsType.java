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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of High Level Shader Language type.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class HighLevelShaderLanguageMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1517;

	public enum Kind {
		INVALID("invalid", -1),
		INTERFACE_POINTER("InterfacePointer", 0x0200),
		TEXTURE_1D("Texture1D", 0x0201),
		TEXTURE_1D_ARRAY("Texture1DArray", 0x0202),
		TEXTURE_2D("Texture2D", 0x0203),
		TEXTURE_2D_ARRAY("Texture2DArray", 0x0204),
		TEXTURE_3D("Texture3D", 0x0205),
		TEXTURE_CUBE("TextureCube", 0x0206),
		TEXTURE_CUBE_ARRAY("TextureCubeArray", 0x0207),
		TEXTURE_2D_MS("Texture2DMs", 0x0208),
		TEXTURE_2D_MS_ARRAY("Texture2DMsArray", 0x0209),
		SAMPLER("Sampler", 0x020a),
		SAMPLER_COMPARISON("SamplerComparison", 0x020b),
		BUFFER("Buffer", 0x020c),
		POINT_STREAM("PointStream", 0x020d),
		LINE_STREAM("LineStream", 0x020e),
		TRIANGLE_STREAM("TriangleStream", 0x020f),
		INPUT_PATCH("InputPatch", 0x0210),
		OUTPUT_PATCH("OutputPatch", 0x0211),
		RW_TEXTURE_1D("RwTexture1D", 0x0212),
		RW_TEXTURE_1D_ARRAY("RwTexture1DArray", 0x0213),
		RW_TEXTURE_2D("RwTexture2D", 0x0214),
		RW_TEXTURE_2D_ARRAY("RwTexture2DArray", 0x0215),
		RW_TEXTURE_3D("RwTexture3D", 0x0216),
		RW_BUFFER("RwBuffer", 0x0217),
		BYTE_ADDRESS_BUFFER("ByteAddressBuffer", 0x0218),
		RW_BYTE_ADDRESS_BUFFER("RwByteAddressBuffer", 0x0219),
		STRUCTURED_BUFFER("StructuredBuffer", 0x021a),
		RW_STRUCTURED_BUFFER("RwStructuredBuffer", 0x021b),
		APPEND_STRUCTURED_BUFFER("AppendStructuredBuffer", 0x021c),
		CONSUME_STRUCTURED_BUFFER("ConsumeStructuredBuffer", 0x021d),
		MIN_8FLOAT("Min8Float", 0x021e),
		MIN_10FLOAT("Min10Float", 0x021f),
		MIN_16FLOAT("Min16Float", 0x0220),
		MIN_12INT("Min12Int", 0x0221),
		MIN_16INT("Min16Int", 0x0222),
		MIN_16UINT("Min16UInt", 0x0223);

		private static final Map<Integer, Kind> BY_VALUE = new HashMap<>();
		static {
			for (Kind val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Kind fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private Kind(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private RecordNumber subtypeRecordNumber;
	private Kind kind;
	private int numNumericProperties;
	private byte[] data;

	//==============================================================================================
	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public HighLevelShaderLanguageMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		subtypeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		kind = Kind.fromValue(reader.parseUnsignedShortVal());
		numNumericProperties = reader.parseUnsignedShortVal() & 0x000f;
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the record number of the subtype for this class.
	 * @return Record number of the subtype for this class.
	 */
	public RecordNumber getSubtypeRecordNumber() {
		return subtypeRecordNumber;
	}

	/**
	 * Returns the {@link Kind} attribute.
	 * @return The {@link Kind} attribute.
	 */
	public Kind getKind() {
		return kind;
	}

	/**
	 * Returns {@code byte[]} of the additional Data for this class.
	 * @return Additional data for this class.
	 */
	public byte[] getData() {
		return data;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No API for this.  Just outputting something that might be useful.
		// At this time, not doing anything with bind here; don't think it is warranted.
		builder.append("Built-In HLSL: ");
		builder.append(kind);
		builder.append(String.format(" <numProperties=%d>", numNumericProperties));
		// TODO: output more?  What does it mean?
	}

}
