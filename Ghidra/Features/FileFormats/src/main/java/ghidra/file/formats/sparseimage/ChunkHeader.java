/* ###
 * IP: Apache License 2.0
 * NOTE: Based on the simg2img code from The Android Open Source Project
 */
/*
 * Copyright (C) 2012 The Android Open Source Project
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
package ghidra.file.formats.sparseimage;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ChunkHeader implements StructConverter {

	private short chunk_type;	// See SparseConstants.CHUNK_TYPE_*
	private short reserved1;
	private int chunk_sz;		// number of blocks in output
	private int total_sz;

	public ChunkHeader(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public ChunkHeader(BinaryReader reader) throws IOException {
		chunk_type = reader.readNextShort();
		reserved1 = reader.readNextShort();
		chunk_sz = reader.readNextInt();
		total_sz = reader.readNextInt();
	}

	public short getChunk_type() {
		return chunk_type;
	}

	public short getReserved1() {
		return reserved1;
	}

	public int getChunk_sz() {
		return chunk_sz;
	}

	public int getTotal_sz() {
		return total_sz;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("chunk_header", 0);
		structure.add(WORD, "chunk_type", null);
		structure.add(WORD, "reserved1", null);
		structure.add(DWORD, "chunk_sz", null);
		structure.add(DWORD, "total_sz", null);
		return structure;
	}

}
