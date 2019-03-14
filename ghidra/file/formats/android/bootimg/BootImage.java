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
package ghidra.file.formats.android.bootimg;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class BootImage implements StructConverter {

	private String magic;
	private int kernelSize;
	private int kernelAddress;
	private int ramDiskSize;
	private int ramDiskAddress;
	private int secondStageSize;
	private int secondStageAddress;
	private int tagsAddress;
	private int pageSize;
	private int [] unused;
	private String name;
	private String commandLine;
	private int [] id;

	public BootImage(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}

	public BootImage(BinaryReader reader) throws IOException {
		magic                = reader.readNextAsciiString( BootImageConstants.BOOT_IMAGE_MAGIC_SIZE );
		kernelSize           = reader.readNextInt();
		kernelAddress        = reader.readNextInt();
		ramDiskSize          = reader.readNextInt();
		ramDiskAddress       = reader.readNextInt();
		secondStageSize      = reader.readNextInt();
		secondStageAddress   = reader.readNextInt();
		tagsAddress          = reader.readNextInt();
		pageSize             = reader.readNextInt();
		unused               = reader.readNextIntArray( 2 );
		name                 = reader.readNextAsciiString( BootImageConstants.BOOT_NAME_SIZE );
		commandLine          = reader.readNextAsciiString( BootImageConstants.BOOT_ARGS_SIZE );
		id                   = reader.readNextIntArray( 8 );
	}

	public String getMagic() {
		return magic;
	}

	public int getKernelSize() {
		return kernelSize;
	}

	public int getKernelAddress() {
		return kernelAddress;
	}

	public int getKernelOffset() {
		return getPageSize();
	}

	public int getKernelSizePageAligned() {
		int remainder = getPageSize() - ( getKernelSize() % getPageSize() );
		return getKernelSize() + remainder;
	}

	public int getRamDiskSize() {
		return ramDiskSize;
	}

	public int getRamDiskAddress() {
		return ramDiskAddress;
	}

	public int getRamDiskOffset() {
		return getKernelOffset() + getKernelSizePageAligned();
	}

	public int getRamDiskSizePageAligned() {
		int remainder = getPageSize() - ( getRamDiskSize() % getPageSize() );
		return getRamDiskSize() + remainder;
	}

	public int getSecondStageSize() {
		return secondStageSize;
	}

	public int getSecondStageAddress() {
		return secondStageAddress;
	}

	public int getSecondStageOffset() {
		return getRamDiskOffset() + ( getRamDiskSizePageAligned() * getPageSize() );
	}

	public int getSecondStageSizePageAligned() {
		int remainder = getPageSize() - ( getSecondStageSize() % getPageSize() );
		return getSecondStageSize() + remainder;
	}

	public int getTagsAddress() {
		return tagsAddress;
	}

	public int getPageSize() {
		return pageSize;
	}

	public int [] getUnused() {
		return unused;
	}

	public String getName() {
		return name;
	}

	public String getCommandLine() {
		return commandLine;
	}

	public int [] getId() {
		return id;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "boot_img_hdr", 0 );
		structure.add( UTF8, BootImageConstants.BOOT_IMAGE_MAGIC_SIZE, "magic", null );
		structure.add( DWORD, "kernelSize", null );
		structure.add( DWORD, "kernelAddress", null );
		structure.add( DWORD, "ramDiskSize", null );
		structure.add( DWORD, "ramDiskAddress", null );
		structure.add( DWORD, "secondStageSize", null );
		structure.add( DWORD, "secondStageAddress", null );
		structure.add( DWORD, "tagsAddress", null );
		structure.add( DWORD, "pageSize", null );
		structure.add(new ArrayDataType(DWORD, 2, DWORD.getLength()), "unused", null);
		structure.add( UTF8, BootImageConstants.BOOT_NAME_SIZE, "name", null );
		structure.add( UTF8, BootImageConstants.BOOT_ARGS_SIZE, "commandLine", null );
		structure.add(new ArrayDataType(DWORD, 8, DWORD.getLength()), "id", null);
		return structure;
	}
}
