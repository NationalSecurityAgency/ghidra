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
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.*;
import ghidra.util.exception.InvalidInputException;

public class CliSigMethodRef extends CliAbstractSig {
	private long dataOffset;
	private CliRetType retType;
	private CliParam params[];
	private int sizeOfCount;
	private byte flags;
	private int genericParamCount;
	private int sizeOfGenericCount;

	private int sentinelIndex; // SENTINEL is before the parameter index in this field

	private final int METHODREFSIG_FLAGS_DEFAULT = 0x00;
	private final int METHODREFSIG_FLAGS_VARARG = 0x05;
	private final int METHODREFSIG_FLAGS_GENERIC = 0x10;
	private final int METHODREFSIG_FLAGS_HASTHIS = 0x20;
	private final int METHODREFSIG_FLAGS_EXPLICITTHIS = 0x40;

	public CliSigMethodRef(CliBlob blob) throws IOException {
		super(blob);
		sentinelIndex = -1;

		// Flags is similar to a MethodDef unless vararg is used.
		BinaryReader reader = getContentsReader();
		dataOffset = reader.getPointerIndex();

		flags = reader.readNextByte();

		if ((flags & METHODREFSIG_FLAGS_GENERIC) == METHODREFSIG_FLAGS_GENERIC) {
			long origIndex = reader.getPointerIndex();
			genericParamCount = decodeCompressedUnsignedInt(reader);
			sizeOfGenericCount = (int) (reader.getPointerIndex() - origIndex);
		}

		long origIndex = reader.getPointerIndex();
		int paramCount = decodeCompressedUnsignedInt(reader);
		this.sizeOfCount = (int) (reader.getPointerIndex() - origIndex);
		try {
			retType = new CliRetType(reader);
		}
		catch (InvalidInputException e) {
			retType = null;
		}
		params = new CliParam[paramCount];
		for (int i = 0; i < paramCount; i++) {
			if (reader.peekNextByte() == CliElementType.ELEMENT_TYPE_SENTINEL.id()) {
				reader.readNextByte();
				sentinelIndex = i;
			}
			try {
				params[i] = new CliParam(reader);
			}
			catch (InvalidInputException e) {
				params[i] = null;
			}
		}
	}

	@Override
	public String getContentsName() {
		return "MethodRefSig";
	}

	@Override
	public String getContentsComment() {
		return "Type info for imported method return and params";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "Flags", "ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS");
		if (genericParamCount > 0) {
			struct.add(getDataTypeForBytes(sizeOfGenericCount), "GenParamCount",
				"Number of generic paramameters for the method");
		}
		struct.add(getDataTypeForBytes(sizeOfCount), "ParamCount",
			"Number of parameter types to follow RetType");
		struct.add(retType.getDefinitionDataType(), "RetType", null);
		for (int i = 0; i < params.length; i++) {
			if (sentinelIndex == i) {
				struct.add(CliTypeCodeDataType.dataType,
					CliElementType.ELEMENT_TYPE_SENTINEL.toString(), "SENTINEL");
			}

			struct.add(params[i].getDefinitionDataType(), "Param" + i, null);
		}
		return struct;
	}

	public CliRetType getReturnType() {
		return retType;
	}

	public CliParam[] getParams() {
		return params.clone();
	}

	public boolean hasThis() {
		return (flags & METHODREFSIG_FLAGS_HASTHIS) == METHODREFSIG_FLAGS_HASTHIS;
	}

	public boolean hasExplicitThis() {
		return (flags & METHODREFSIG_FLAGS_EXPLICITTHIS) == METHODREFSIG_FLAGS_EXPLICITTHIS;
	}

	public boolean hasVarArgs() {
		return (flags & METHODREFSIG_FLAGS_VARARG) == METHODREFSIG_FLAGS_VARARG;
	}

	@Override
	protected String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String rep = getRepresentationOf(retType, stream, isShort);
		rep += " fn(";

		for (CliParam param : params) {
			if (param == null) {
				rep += "unidentified_param_type, ";
			}
			else {
				rep += getRepresentationOf(param, stream, isShort) + ", ";
			}
		}
		if (params.length > 0) {
			rep = rep.substring(0, rep.length() - 2); // Take off last comma+space
		}
		rep += ")";
		return rep;
	}

}
