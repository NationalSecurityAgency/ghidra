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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

public class HighLevelShaderLanguageMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1517;

	private static final int BUILTIN_HLSL_INTERFACE_POINTER = 0x0200;
	private static final int BUILTIN_HLSL_TEXTURE_1D = 0x0201;
	private static final int BUILTIN_HLSL_TEXTURE_1D_ARRAY = 0x0202;
	private static final int BUILTIN_HLSL_TEXTURE_2D = 0x0203;
	private static final int BUILTIN_HLSL_TEXTURE_2D_ARRAY = 0x0204;
	private static final int BUILTIN_HLSL_TEXTURE_3D = 0x0205;
	private static final int BUILTIN_HLSL_TEXTURE_CUBE = 0x0206;
	private static final int BUILTIN_HLSL_TEXTURE_CUBE_ARRAY = 0x0207;
	private static final int BUILTIN_HLSL_TEXTURE_2D_MS = 0x0208;
	private static final int BUILTIN_HLSL_TEXTURE_2D_MS_ARRAY = 0x0209;
	private static final int BUILTIN_HLSL_SAMPLER = 0x020a;
	private static final int BUILTIN_HLSL_SAMPLER_COMPARISON = 0x020b;
	private static final int BUILTIN_HLSL_BUFFER = 0x020c;
	private static final int BUILTIN_HLSL_POINT_STREAM = 0x020d;
	private static final int BUILTIN_HLSL_LINE_STREAM = 0x020e;
	private static final int BUILTIN_HLSL_TRIANGLE_STREAM = 0x020f;
	private static final int BUILTIN_HLSL_INPUT_PATCH = 0x0210;
	private static final int BUILTIN_HLSL_OUTPUT_PATCH = 0x0211;
	private static final int BUILTIN_HLSL_RW_TEXTURE_1D = 0x0212;
	private static final int BUILTIN_HLSL_RW_TEXTURE_1D_ARRAY = 0x0213;
	private static final int BUILTIN_HLSL_RW_TEXTURE_2D = 0x0214;
	private static final int BUILTIN_HLSL_RW_TEXTURE_2D_ARRAY = 0x0215;
	private static final int BUILTIN_HLSL_RW_TEXTURE_3D = 0x0216;
	private static final int BUILTIN_HLSL_RW_BUFFER = 0x0217;
	private static final int BUILTIN_HLSL_BYTE_ADDRESS_BUFFER = 0x0218;
	private static final int BUILTIN_HLSL_RW_BYTE_ADDRESS_BUFFER = 0x0219;
	private static final int BUILTIN_HLSL_STRUCTURED_BUFFER = 0x021a;
	private static final int BUILTIN_HLSL_RW_STRUCTURED_BUFFER = 0x021b;
	private static final int BUILTIN_HLSL_APPEND_STRUCTURED_BUFFER = 0x021c;
	private static final int BUILTIN_HLSL_CONSUME_STRUCTURED_BUFFER = 0x021d;
	private static final int BUILTIN_HLSL_MIN_8FLOAT = 0x021e;
	private static final int BUILTIN_HLSL_MIN_10FLOAT = 0x021f;
	private static final int BUILTIN_HLSL_MIN_16FLOAT = 0x0220;
	private static final int BUILTIN_HLSL_MIN_12INT = 0x0221;
	private static final int BUILTIN_HLSL_MIN_16INT = 0x0222;
	private static final int BUILTIN_HLSL_MIN_16UINT = 0x0223;

	//==============================================================================================
	private AbstractTypeIndex subtypeIndex;
	private int kind;
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
		subtypeIndex = new TypeIndex32();
		subtypeIndex.parse(reader);
		kind = reader.parseUnsignedShortVal();
		numNumericProperties = reader.parseUnsignedShortVal() & 0x000f;
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the type index of the subtype for this class.
	 * @return Type index of the subtype for this class.
	 */
	public int getSubtypeIndex() {
		return subtypeIndex.get();
	}

	/**
	 * Returns the integer "kind" value for this class.
	 * @return The "kind" value.
	 */
	public int getKind() {
		return kind;
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindInterfacePointer() {
		return (kind == BUILTIN_HLSL_INTERFACE_POINTER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTexture1D() {
		return (kind == BUILTIN_HLSL_TEXTURE_1D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTexture1DArray() {
		return (kind == BUILTIN_HLSL_TEXTURE_1D_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTexture2D() {
		return (kind == BUILTIN_HLSL_TEXTURE_2D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTecture2DArray() {
		return (kind == BUILTIN_HLSL_TEXTURE_2D_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTexture3D() {
		return (kind == BUILTIN_HLSL_TEXTURE_3D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTextureCube() {
		return (kind == BUILTIN_HLSL_TEXTURE_CUBE);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTextureCubeArray() {
		return (kind == BUILTIN_HLSL_TEXTURE_CUBE_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTexture2DMs() {
		return (kind == BUILTIN_HLSL_TEXTURE_2D_MS);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKind2DMsArray() {
		return (kind == BUILTIN_HLSL_TEXTURE_2D_MS_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindSampler() {
		return (kind == BUILTIN_HLSL_SAMPLER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindSamplerComparison() {
		return (kind == BUILTIN_HLSL_SAMPLER_COMPARISON);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindBuffer() {
		return (kind == BUILTIN_HLSL_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindPointStream() {
		return (kind == BUILTIN_HLSL_POINT_STREAM);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindLineStream() {
		return (kind == BUILTIN_HLSL_LINE_STREAM);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindTriangleStream() {
		return (kind == BUILTIN_HLSL_TRIANGLE_STREAM);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindInputPatch() {
		return (kind == BUILTIN_HLSL_INPUT_PATCH);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindOutputPatch() {
		return (kind == BUILTIN_HLSL_OUTPUT_PATCH);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwTexture1D() {
		return (kind == BUILTIN_HLSL_RW_TEXTURE_1D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwTexture1DArray() {
		return (kind == BUILTIN_HLSL_RW_TEXTURE_1D_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwTexture2D() {
		return (kind == BUILTIN_HLSL_RW_TEXTURE_2D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwTexture2DArray() {
		return (kind == BUILTIN_HLSL_RW_TEXTURE_2D_ARRAY);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwTexture3D() {
		return (kind == BUILTIN_HLSL_RW_TEXTURE_3D);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwBuffer() {
		return (kind == BUILTIN_HLSL_RW_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindByteAddressBuffer() {
		return (kind == BUILTIN_HLSL_BYTE_ADDRESS_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwByteAddressBuffer() {
		return (kind == BUILTIN_HLSL_RW_BYTE_ADDRESS_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindStructuredBuffer() {
		return (kind == BUILTIN_HLSL_STRUCTURED_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindRwStructuredBuffer() {
		return (kind == BUILTIN_HLSL_RW_STRUCTURED_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindAppendStructuredBuffer() {
		return (kind == BUILTIN_HLSL_APPEND_STRUCTURED_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindConsumeStructuredBuffer() {
		return (kind == BUILTIN_HLSL_CONSUME_STRUCTURED_BUFFER);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin8Float() {
		return (kind == BUILTIN_HLSL_MIN_8FLOAT);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin10Float() {
		return (kind == BUILTIN_HLSL_MIN_10FLOAT);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin16Float() {
		return (kind == BUILTIN_HLSL_MIN_16FLOAT);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin12Int() {
		return (kind == BUILTIN_HLSL_MIN_12INT);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin16Int() {
		return (kind == BUILTIN_HLSL_MIN_16INT);
	}

	/**
	 * Tells whether the "kind" property is true.
	 * @return Truth about this "kind" property.
	 */
	public boolean isKindMin16Uint() {
		return (kind == BUILTIN_HLSL_MIN_16UINT);
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
		switch (kind) {
			case BUILTIN_HLSL_INTERFACE_POINTER:
				builder.append("InterfacePointer");
				break;
			case BUILTIN_HLSL_TEXTURE_1D:
				builder.append("Texture1D");
				break;
			case BUILTIN_HLSL_TEXTURE_1D_ARRAY:
				builder.append("Texture1DArray");
				break;
			case BUILTIN_HLSL_TEXTURE_2D:
				builder.append("Texture2D");
				break;
			case BUILTIN_HLSL_TEXTURE_2D_ARRAY:
				builder.append("Texture2DArray");
				break;
			case BUILTIN_HLSL_TEXTURE_3D:
				builder.append("Texture3D");
				break;
			case BUILTIN_HLSL_TEXTURE_CUBE:
				builder.append("TextureCube");
				break;
			case BUILTIN_HLSL_TEXTURE_CUBE_ARRAY:
				builder.append("TextureCubeArray");
				break;
			case BUILTIN_HLSL_TEXTURE_2D_MS:
				builder.append("Texture2DMs");
				break;
			case BUILTIN_HLSL_TEXTURE_2D_MS_ARRAY:
				builder.append("Texture2DMsArray");
				break;
			case BUILTIN_HLSL_SAMPLER:
				builder.append("Sampler");
				break;
			case BUILTIN_HLSL_SAMPLER_COMPARISON:
				builder.append("SamplerComparison");
				break;
			case BUILTIN_HLSL_BUFFER:
				builder.append("Buffer");
				break;
			case BUILTIN_HLSL_POINT_STREAM:
				builder.append("PointStream");
				break;
			case BUILTIN_HLSL_LINE_STREAM:
				builder.append("LineStream");
				break;
			case BUILTIN_HLSL_TRIANGLE_STREAM:
				builder.append("TriangleStream");
				break;
			case BUILTIN_HLSL_INPUT_PATCH:
				builder.append("InputPatch");
				break;
			case BUILTIN_HLSL_OUTPUT_PATCH:
				builder.append("OutputPatch");
				break;
			case BUILTIN_HLSL_RW_TEXTURE_1D:
				builder.append("RwTexture1D");
				break;
			case BUILTIN_HLSL_RW_TEXTURE_1D_ARRAY:
				builder.append("RwTexture1DArray");
				break;
			case BUILTIN_HLSL_RW_TEXTURE_2D:
				builder.append("RwTexture2D");
				break;
			case BUILTIN_HLSL_RW_TEXTURE_2D_ARRAY:
				builder.append("RwTexture2DArray");
				break;
			case BUILTIN_HLSL_RW_TEXTURE_3D:
				builder.append("RwTexture3D");
				break;
			case BUILTIN_HLSL_RW_BUFFER:
				builder.append("RwBuffer");
				break;
			case BUILTIN_HLSL_BYTE_ADDRESS_BUFFER:
				builder.append("ByteAddressBuffer");
				break;
			case BUILTIN_HLSL_RW_BYTE_ADDRESS_BUFFER:
				builder.append("RwByteAddressBuffer");
				break;
			case BUILTIN_HLSL_STRUCTURED_BUFFER:
				builder.append("StructuredBuffer");
				break;
			case BUILTIN_HLSL_RW_STRUCTURED_BUFFER:
				builder.append("RwStructuredBuffer");
				break;
			case BUILTIN_HLSL_APPEND_STRUCTURED_BUFFER:
				builder.append("AppendStructuredBuffer");
				break;
			case BUILTIN_HLSL_CONSUME_STRUCTURED_BUFFER:
				builder.append("ConsumeStructuredBuffer");
				break;
			case BUILTIN_HLSL_MIN_8FLOAT:
				builder.append("Min8Float");
				break;
			case BUILTIN_HLSL_MIN_10FLOAT:
				builder.append("Min10Float");
				break;
			case BUILTIN_HLSL_MIN_16FLOAT:
				builder.append("Min16Float");
				break;
			case BUILTIN_HLSL_MIN_12INT:
				builder.append("Min12Int");
				break;
			case BUILTIN_HLSL_MIN_16INT:
				builder.append("Min16Int");
				break;
			case BUILTIN_HLSL_MIN_16UINT:
				builder.append("Min16UInt");
				break;
		}
		builder.append(String.format(" <numProperties=%d>", numNumericProperties));
		// TODO: output more?  What does it mean?
	}

}
