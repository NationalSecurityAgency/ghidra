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

public class CliSigStandAloneMethod extends CliAbstractSig {

	private CliRetType retType;
	private CliParam params[];
	private byte flags;
	private int sizeOfCount;
	private int sentinelIndex; // SENTINEL is before the parameter index in this field

	// Note: The only difference between this and the MethodRefSig is the number of
	// values that can be included in the first byte

	private final int STANDALONEMETHODSIG_FLAGS_DEFAULT = 0x0;
	private final int STANDALONEMETHODSIG_FLAGS_HASTHIS = 0x20;
	private final int STANDALONEMETHODSIG_FLAGS_EXPLICITTHIS = 0x40;
	private final int STANDALONEMETHODSIG_FLAGS_VARARG = 0x5;
	private final int STANDALONEMETHODSIG_FLAGS_C = 0x01;
	private final int STANDALONEMETHODSIG_FLAGS_STDCALL = 0x02;
	private final int STANDALONEMETHODSIG_FLAGS_THISCALL = 0x03;
	private final int STANDALONEMETHODSIG_FLAGS_FASTCALL = 0x04;

	public enum CallingConvention {
		MANAGED, C, STDCALL, THISCALL, FASTCALL
	}

	public CliSigStandAloneMethod(CliBlob blob) throws IOException {
		super(blob);
		sentinelIndex = -1;

		// Read the flags
		BinaryReader reader = getContentsReader();
		flags = reader.readNextByte();

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
		return "StandAloneMethodSig";
	}

	@Override
	public String getContentsComment() {
		return "Typically for calli instruction; Type info for method return and params";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "flags",
			"ORed VARARG/DEFAULT/C/STDCALL/THISCALL/FASTCALL and HASTHIS/EXPLICITTHIS");
		struct.add(getDataTypeForBytes(sizeOfCount), "Count",
			"Number of param types to follow RetType");
		struct.add(retType.getDefinitionDataType(), "RetType", null);
		for (CliParam param : params) {
			struct.add(param.getDefinitionDataType(), null, null);
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
		return (flags & STANDALONEMETHODSIG_FLAGS_HASTHIS) == STANDALONEMETHODSIG_FLAGS_HASTHIS;
	}

	public boolean hasExplicitThis() {
		return (flags &
			STANDALONEMETHODSIG_FLAGS_EXPLICITTHIS) == STANDALONEMETHODSIG_FLAGS_EXPLICITTHIS;
	}

	public boolean hasVarArgs() {
		return (flags & STANDALONEMETHODSIG_FLAGS_VARARG) == STANDALONEMETHODSIG_FLAGS_VARARG;
	}

	public CallingConvention getCallingConvention() {
		if ((flags & STANDALONEMETHODSIG_FLAGS_C) == STANDALONEMETHODSIG_FLAGS_C) {
			// cdecl
			return CallingConvention.C;
		}
		else if ((flags & STANDALONEMETHODSIG_FLAGS_STDCALL) == STANDALONEMETHODSIG_FLAGS_STDCALL) {
			// stdcall
			return CallingConvention.STDCALL;
		}
		else if ((flags &
			STANDALONEMETHODSIG_FLAGS_THISCALL) == STANDALONEMETHODSIG_FLAGS_THISCALL) {
			// ecx/rcx is this pointer
			return CallingConvention.THISCALL;
		}
		else if ((flags &
			STANDALONEMETHODSIG_FLAGS_FASTCALL) == STANDALONEMETHODSIG_FLAGS_FASTCALL) {
			// ecx/rcx and edx/rdx are the first two parameters, standard x64 convention
			return CallingConvention.FASTCALL;
		}

		// Managed code call
		return CallingConvention.MANAGED;
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String rep = getRepresentationOf(retType, stream, isShort) + " fn(";

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
