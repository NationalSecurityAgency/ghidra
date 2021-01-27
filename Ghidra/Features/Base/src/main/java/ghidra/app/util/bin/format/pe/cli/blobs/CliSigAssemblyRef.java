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

/*
 * At this time an example of how to decode the AssemblyRef blob hasn't
 * been located so this is to serve as an identifier of the content and
 * a placeholder for later processing.
 */

public class CliSigAssemblyRef extends CliAbstractSig {
	byte[] content;

	public CliSigAssemblyRef(CliBlob blob) throws IOException {
		super(blob);
		BinaryReader reader = blob.getContentsReader();
		content = reader.readNextByteArray(contentsSize);
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(new ArrayDataType(BYTE, contentsSize, 1), "", "AssemblyRef Content");
		return struct;
	}

	@Override
	public String getContentsName() {
		return "AssemblyRefSig";
	}

	@Override
	public String getContentsComment() {
		return "Data stored in an AssemblyRef blob";
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		return content.toString();
	}
}
