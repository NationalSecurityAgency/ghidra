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
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class CliSigLocalVar extends CliAbstractSig {
	private int sizeOfCount;
	private CliParam types[];

	private static final int CLISIGLOCALVAR_PROLOG = 0x07;

	public CliSigLocalVar(CliBlob blob) throws IOException {
		super(blob);

		BinaryReader reader = getContentsReader();

		// Check the prolog byte
		byte prolog = reader.readNextByte();
		if (prolog != CLISIGLOCALVAR_PROLOG) {
			Msg.warn(this,
				"LocalVarSig had unexpected prolog (0x" + Integer.toHexString(prolog) + ")");
			return;
		}

		long origIndex = reader.getPointerIndex();
		int typesCount = decodeCompressedUnsignedInt(reader);
		sizeOfCount = (int) (reader.getPointerIndex() - origIndex);
		types = new CliParam[typesCount];

		// CliParam will parse modifiers, constraints, and ByRef notations
		for (byte i = 0; i < typesCount; i++) {
			try {
				types[i] = new CliParam(reader);
			}
			catch (InvalidInputException e) {
				types[i] = null;
				e.printStackTrace();
			}
		}
	}

	/**
	 * Checks whether this could *possibly* be a LocalVarSig. Only looks at the identifier byte. Useful for signature index
	 * that could be to different kinds of signatures.
	 * @param blob
	 * @return
	 * @throws IOException
	 */
	public static boolean isLocalVarSig(CliBlob blob) throws IOException {
		return blob.getContentsReader().readNextByte() == CLISIGLOCALVAR_PROLOG;
	}

	@Override
	public String getContentsName() {
		return "LocalVarSig";
	}

	@Override
	public String getContentsComment() {
		return "Contains signature for function locals";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "LOCAL_SIG", "Magic (0x07)");
		struct.add(getDataTypeForBytes(sizeOfCount), "Count", "Number of types to follow");
		for (CliParam param : types) {
			struct.add(param.getDefinitionDataType(), "Type", null);
		}
		return struct;
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String rep = "";
		for (CliParam param : types) {
			rep += getRepresentationOf(param, stream, isShort) + ", ";
		}
		if (types.length > 0) {
			rep = rep.substring(0, rep.length() - 2); // remove comma+space
		}
		return rep;
	}

}
