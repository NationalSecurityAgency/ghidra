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
package ghidra.file.formats.android.art;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/image.h
 */
public abstract class ArtHeader implements StructConverter {

	protected String magic_;
	protected String version_;

	protected List<Long> imageMethodsList = new ArrayList<>();

	protected ArtHeader(BinaryReader reader) throws IOException {
		magic_ = new String(reader.readNextByteArray(ArtConstants.MAGIC.length()));
		version_ = reader.readNextAsciiString(ArtConstants.VERSION_LENGTH);
	}

	/**
	 * Returns the magic string: "art\n".
	 * @return the magic string
	 */
	public final String getMagic() {
		return magic_;
	}

	/**
	 * Returns the version string: eg, "001", "017"
	 * @return the version
	 */
	public final String getVersion() {
		return version_;
	}

	/**
	 * Required base address for mapping the image.
	 * 
	 * Base address of the ART file.
	 * -1 indicates unsupported
	 * @return image base address
	 */
	abstract public int getImageBegin();

	/**
	 * Required base size for mapping the image.
	 * -1 indicates unsupported
	 * @return image size
	 */
	abstract public int getImageSize();

	/**
	 * Returns the checksum of the matching OAT file.
	 * The checksum is stored in the OAT header and is generated using Adler32.
	 * -1 indicates unsupported
	 * @return oat checksum
	 */
	abstract public int getOatChecksum();

	/**
	 *  -1 indicates unsupported
	 * @return the oat file begin address
	 */
	abstract public int getOatFileBegin();

	/**
	 * -1 indicates unsupported
	 * @return the oat file end address
	 */
	abstract public int getOatFileEnd();

	/**
	 * Returns the offset to the start of the .oatdata section,
	 * usually defined within the ".rodata" section.
	 * -1 indicates unsupported
	 * @return the oat data begin address
	 */
	abstract public int getOatDataBegin();

	/**
	 * -1 indicates unsupported
	 * @return the oat data end address
	 */
	abstract public int getOatDataEnd();

	/**
	 * Pointer size (in bytes).
	 * @return the pointer size
	 */
	abstract public int getPointerSize();

	abstract public int getArtMethodCountForVersion();

	/**
	 * Parses the ART header data.
	 * @param reader the binary reader
	 * @throws IOException if an error occurs parsing the header
	 */
	abstract protected void parse(BinaryReader reader) throws IOException;

	protected final void parseImageMethods(BinaryReader reader) throws IOException {
		for (int i = 0; i < getArtMethodCountForVersion(); ++i) {
			imageMethodsList.add(reader.readNextLong());
		}
	}

	/**
	 * Allows each specific version to mark-up the specified program.
	 * @param program the program to markup
	 * @param monitor the task monitor
	 * @throws Exception if an error occurs while marking up the program
	 */
	abstract public void markup(Program program, TaskMonitor monitor) throws Exception;

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(ArtHeader.class);
		Structure structure = new StructureDataType(className, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "version_", null);
		structure.setCategoryPath(new CategoryPath("/art"));
		return structure;
	}

}
