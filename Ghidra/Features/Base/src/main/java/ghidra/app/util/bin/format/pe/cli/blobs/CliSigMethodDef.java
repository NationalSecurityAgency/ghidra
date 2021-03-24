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

public class CliSigMethodDef extends CliAbstractSig {

	private CliRetType retType;
	private CliParam params[];
	private int sizeOfCount;
	private int genericParamCount;
	private byte flags;
	private int sizeOfGenericCount;

	private final int METHODDEFSIG_FLAGS_DEFAULT = 0x00;
	private final int METHODDEFSIG_FLAGS_VARARG = 0x05;
	private final int METHODDEFSIG_FLAGS_GENERIC = 0x10;
	private final int METHODDEFSIG_FLAGS_HASTHIS = 0x20;
	private final int METHODDEFSIG_FLAGS_EXPLICITTHIS = 0x40;

	public CliSigMethodDef(CliBlob blob) throws IOException {
		super(blob);

		// Read and determine meaning of flag byte
		BinaryReader reader = getContentsReader();
		flags = reader.readNextByte();

		if ((flags & METHODDEFSIG_FLAGS_GENERIC) == METHODDEFSIG_FLAGS_GENERIC) {
			long origIndex = reader.getPointerIndex();
			genericParamCount = decodeCompressedUnsignedInt(reader);
			sizeOfGenericCount = (int) (reader.getPointerIndex() - origIndex);
		}

		// Get parameter count and return type
		long origIndex = reader.getPointerIndex();
		int paramCount = decodeCompressedUnsignedInt(reader);
		this.sizeOfCount = (int) (reader.getPointerIndex() - origIndex);
		try {
			retType = new CliRetType(reader);
		}
		catch (InvalidInputException e) {
			retType = null;
		}

		// Get parameters
		params = new CliParam[paramCount];
		for (int i = 0; i < paramCount; i++) {
			try {
				params[i] = new CliParam(reader);
			}
			catch (InvalidInputException e) {
				/* Do not add to params[] */ }
		}
	}

	@Override
	public String getContentsName() {
		return "MethodDefSig";
	}

	@Override
	public String getContentsComment() {
		return "Type info for method return and params";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "Flags", "ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS"); // TODO: enum
		if (genericParamCount > 0) {
			struct.add(getDataTypeForBytes(sizeOfGenericCount), "GenParamCount",
				"Number of generic paramameters for the method");
		}
		struct.add(getDataTypeForBytes(sizeOfCount), "Count",
			"Number of parameter types to follow RetType");
		struct.add(retType.getDefinitionDataType(), "RetType", null);

		for (int i = 0; i < params.length; i++) {
			struct.add(params[i].getDefinitionDataType(), "Param" + i, null);
		}

		return struct;
	}

	public CliRetType getReturnType() {
		return retType;
	}

	public CliParam[] getParamTypes() {
		return params.clone();
	}

	public boolean hasThis() {
		return (flags & METHODDEFSIG_FLAGS_HASTHIS) == METHODDEFSIG_FLAGS_HASTHIS;
	}

	public boolean hasExplicitThis() {
		return (flags & METHODDEFSIG_FLAGS_EXPLICITTHIS) == METHODDEFSIG_FLAGS_EXPLICITTHIS;
	}

	public boolean hasVarArgs() {
		return (flags & METHODDEFSIG_FLAGS_VARARG) == METHODDEFSIG_FLAGS_VARARG;
	}

	public Boolean hasGenericArgs() {
		return (flags & METHODDEFSIG_FLAGS_GENERIC) == METHODDEFSIG_FLAGS_GENERIC;
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
