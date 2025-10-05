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
package ghidra.app.util.bin.format.golang;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

/**
 * This class represents a Go build id string, along with a magic header.
 * <p>
 * Similar to {@link NoteGoBuildId}, but re-implemented here because of the different
 * serialization used.
 */
public class GoBuildId {
	private static final byte[] GO_BUILDID_MAGIC =
		"\u00ff Go build ID: \"".getBytes(StandardCharsets.ISO_8859_1);
	private static final int BUILDID_STR_LEN = 83;

	public static ItemWithAddress<GoBuildId> findBuildId(Program program) {
		MemoryBlock txtBlock = GoRttiMapper.getGoSection(program, "text");
		ItemWithAddress<GoBuildId> wrappedItem =
			readItemFromSection(program, txtBlock, GoBuildId::read);
		return wrappedItem;
	}


	/**
	 * Attempts to read a GoBuildId from the specified stream.
	 * 
	 * @param br BinaryReader stream (typically the beginning of the ".text" section)
	 * @param program_notused not used, but needed to match functional interface
	 * @return GoBuildId instance, or null if not present
	 */
	public static GoBuildId read(BinaryReader br, Program program_notused) {
		try {
			byte[] magic = br.readNextByteArray(GO_BUILDID_MAGIC.length);
			if (!Arrays.equals(magic, GO_BUILDID_MAGIC)) {
				return null;
			}
			String buildIdStr = br.readNextAsciiString(BUILDID_STR_LEN);
			return new GoBuildId(buildIdStr);
		}
		catch (IOException e) {
			// fall thru and return null
		}
		return null;
	}

	/**
	 * Attempts to read a GoBuildId from the specified InputStream (useful for early compiler
	 * detection before file is loaded).
	 * 
	 * @param is {@link InputStream} providing access to the ".text" section of a PE binary 
	 * @return GoBuildId instance, or null if not present
	 */
	public static GoBuildId read(InputStream is) {
		byte[] buffer = new byte[GO_BUILDID_MAGIC.length + BUILDID_STR_LEN];
		try {
			int bytesRead = is.read(buffer);
			if (bytesRead == buffer.length) {
				ByteArrayProvider bap = new ByteArrayProvider(buffer);
				return read(new BinaryReader(bap, false /* doesn't matter */), null);
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return null;
	}

	private final String buildId;

	public GoBuildId(String buildId) {
		this.buildId = buildId;
	}

	public String getBuildId() {
		return buildId;
	}

	public void markupProgram(Program program, Address address) {
		program.getOptions(Program.PROGRAM_INFO)
				.setString(NoteGoBuildId.PROGRAM_INFO_KEY, getBuildId());

		try {
			StructureDataType struct = toStructure(program.getDataTypeManager());
			if (struct != null) {
				DataUtilities.createData(program, address, struct, -1, false,
					ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
			}
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Failed to markup GoBuildId at %s: %s".formatted(address, this));
		}

	}

	private StructureDataType toStructure(DataTypeManager dtm) {
		StructureDataType result =
			new StructureDataType(GoConstants.GOLANG_CATEGORYPATH, "GoBuildId", 0, dtm);
		result.add(StringDataType.dataType, GO_BUILDID_MAGIC.length, "magic", null);
		result.add(StringDataType.dataType, BUILDID_STR_LEN, "buildId", null);

		return result;
	}

	//----------------------------------------------------------------------------------------------
	static <T> ItemWithAddress<T> readItemFromSection(Program program, MemoryBlock memBlock,
			ReaderFunc<T> readFunc) {
		if (memBlock != null) {
			try (ByteProvider bp =
				MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(), memBlock)) {
				BinaryReader br = new BinaryReader(bp, !program.getMemory().isBigEndian());

				T item = readFunc.read(br, program);
				return item != null ? new ItemWithAddress<>(item, memBlock.getStart()) : null;
			}
			catch (IOException e) {
				Msg.warn(GoBuildId.class,
					"Unable to read GoBuildId in section: %s".formatted(memBlock.getName()), e);
			}
		}
		return null;
	}

}
