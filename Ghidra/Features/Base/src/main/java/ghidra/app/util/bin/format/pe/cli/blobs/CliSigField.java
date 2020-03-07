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

public class CliSigField extends CliAbstractSig {
	public static final byte identifier = 0x06; 
	
	public CliParam type;
	
	public CliSigField(CliBlob blob) throws IOException {
		super(blob);

		// Now read our special data from the blob!
		BinaryReader reader = getContentsReader();
		byte firstByte = reader.readNextByte();
		if (firstByte != identifier)
			return; // Do something worse than just return?
		try {
			type = new CliParam(reader);
		}
		catch (InvalidInputException e) {
			type = null;
		}
	}

	/**
	 * Checks whether this could *possibly* be a FieldSig. Only looks at the identifier byte. Useful for signature index
	 * that could be to different kinds of signatures.
	 * @param blob
	 * @return
	 * @throws IOException
	 */
	public static boolean isFieldSig(CliBlob blob) throws IOException {
		return blob.getContentsReader().readNextByte() == identifier;
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct =
			new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "FIELD", "0x06");
		struct.add(type.getDefinitionDataType(), "Type", null);
		return struct;
	}

	@Override
	public String getContentsName() {
		return "FieldSig";
	}

	@Override
	public String getContentsComment() {
		return "Type information for Field";
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		return getRepresentationOf(type, stream, isShort);
	}
	
}
