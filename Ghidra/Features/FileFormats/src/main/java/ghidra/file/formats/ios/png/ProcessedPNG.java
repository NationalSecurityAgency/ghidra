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
package ghidra.file.formats.ios.png;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ProcessedPNG implements StructConverter {

	private byte[] fileSignature;
	private List<PNGChunk> chunks;
	private int totalLength;
	private IHDRChunk ihdrChunk;

	/**
	 * Processes PNG data finding each of the PNG chunks
	 * @param reader BinaryReader for the PNG data
	 * @throws IOException
	 */
	public ProcessedPNG(BinaryReader reader, TaskMonitor monitor) throws IOException {
		if (reader != null) {
			chunks = new ArrayList<PNGChunk>();

			fileSignature = reader.readNextByteArray(CrushedPNGConstants.SIGNATURE_BYTES.length);
			totalLength += fileSignature.length;

			while (true && !monitor.isCancelled()) {
				PNGChunk chunk = new PNGChunk(reader);
				if (chunk.getIDString().equals(CrushedPNGConstants.IEND_STRING)) {

					//End chunk of the PNG
					chunks.add(chunk);
					totalLength += chunk.getTotalLength();
					break;
				}
				else if (chunk.getIDString().equals(CrushedPNGConstants.IHDR_STRING)) {

					//Important IHDR chunk
					totalLength += chunk.getTotalLength();
					ihdrChunk = new IHDRChunk(chunk);
					chunks.add(chunk);
				}
				else {

					//Any other chunks
					totalLength += chunk.getTotalLength();
					chunks.add(chunk);
				}
			}
		}
		else {
			throw new IOException("Reader is null");
		}

	}

	public IHDRChunk getIHDRChunk() {
		return ihdrChunk;
	}

	public int getTotalLength() {
		return totalLength;
	}

	public byte[] getFileSignature() {
		return fileSignature;
	}

	public List<PNGChunk> getChunkArray() {
		return chunks;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("CrushedPNG", 0);

		struc.add(new ArrayDataType(BYTE, fileSignature.length, 1), "File Signature", new String(
			fileSignature));

		for (PNGChunk chunk : chunks) {
			struc.add(chunk.toDataType());
		}
		return struc;
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		buff.append("Type: Crushed PNG Image\n");
		buff.append("Size: " + totalLength + " bytes\n");
		buff.append("PNG Chunks: \n");
		for (PNGChunk chunk : chunks) {
			buff.append("    " + chunk.getIDString() + "\n");
		}
		return buff.toString();
	}

}
