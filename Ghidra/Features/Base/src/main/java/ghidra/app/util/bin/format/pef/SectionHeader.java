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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;

/**
 * See Apple's -- PEFBinaryFormat
 * <pre>
 * struct PEFSectionHeader {
 *     SInt32   nameOffset;             // Offset of name within the section name table, -1 =&gt; none.
 *     UInt32   defaultAddress;         // Default address, affects relocations.
 *     UInt32   totalLength;            // Fully expanded size in bytes of the section contents.
 *     UInt32   unpackedLength;         // Size in bytes of the "initialized" part of the contents.
 *     UInt32   containerLength;        // Size in bytes of the raw data in the container.
 *     UInt32   containerOffset;        // Offset of section's raw data.
 *     UInt8    sectionKind;            // Kind of section contents/usage.
 *     UInt8    shareKind;              // Sharing level, if a writeable section.
 *     UInt8    alignment;              // Preferred alignment, expressed as log 2.
 *     UInt8    reservedA;              // Reserved, must be zero.
 * };
 * </pre>
 */
public class SectionHeader implements StructConverter {
	public final static int NO_NAME_OFFSET = -1;

	private BinaryReader _reader;
	private String _name;

	private int   nameOffset;
	private int   defaultAddress;
	private int   totalLength;
	private int   unpackedLength;
	private int   containerLength;
	private int   containerOffset;
	private byte  sectionKind;
	private byte  shareKind;
	private byte  alignment;
	private byte  reservedA;

	SectionHeader(BinaryReader reader) throws IOException {
		this._reader    = reader;

		nameOffset      = reader.readNextInt();
		defaultAddress  = reader.readNextInt();
		totalLength     = reader.readNextInt();
		unpackedLength  = reader.readNextInt();
		containerLength = reader.readNextInt();
		containerOffset = reader.readNextInt();
		sectionKind     = reader.readNextByte();
		shareKind       = reader.readNextByte();
		alignment       = reader.readNextByte();
		reservedA       = reader.readNextByte();

		if (nameOffset != NO_NAME_OFFSET) {
			Msg.debug(this, "PEF- Named Section");//TODO
			//_name = reader.readAsciiString(nameOffset);
		}
	}

	/**
	 * The offset from the start of the section name table
	 * to the name of this section.
	 * A value of -1 indicates an unnamed section.
	 * @return the offset from the start of the section name table
	 */
	public int getNameOffset() {
		return nameOffset;
	}
	/**
	 * Returns the name of this section.
	 * @return the name of this section
	 */
	public String getName() {
		if (_name == null) {
			return getSectionKind().toString();
		}
		return _name;
	}
    /**
     * Returns an input stream to underlying bytes of this section.
     * @return an input stream to underlying bytes of this section
     * @throws IOException if an i/o error occurs.
     */
    public InputStream getData() throws IOException {
        return _reader.getByteProvider().getInputStream(containerOffset);
    }
    /**
     * Unpack the data in a packed section.
     * Calling this method is only valid on a packed section.
     * @param monitor the task monitor
     * @return the unpacked data
     * @throws IOException if an i/o error occurs or the section is not packed.
     */
    public byte [] getUnpackedData(TaskMonitor monitor) throws IOException {
		if (getSectionKind() != SectionKind.PackedData) {
			throw new IOException("Attempt to unpack a section that is not packed.");
		}
		try (InputStream input = getData()) {
			byte[] data = new byte[getUnpackedLength()];
			int index = 0;
			while (index < data.length) {
				if (monitor.isCancelled()) {
					break;
				}
				int value = input.read();
				if (value == -1) {
					throw new IllegalStateException();
				}
				int count = value & 0x1f;//count is the lower 5 bits...
				if (count == 0) {
					count = unpackNextValue(input);
				}
				PackedDataOpcodes opcode = PackedDataOpcodes.get(value >> 5);
				if (opcode == PackedDataOpcodes.kPEFPkDataZero) {
					index += count;
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataBlock) {
					byte[] rawData = new byte[count];
					int nRead = input.read(rawData);
					if (nRead != count) {
						throw new IllegalStateException(
							"Unable to read enough bytes for " + opcode);
					}
					System.arraycopy(rawData, 0, data, index, rawData.length);
					index += rawData.length;
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeat) {
					int repeatCount = unpackNextValue(input);
					byte[] rawData = new byte[count];
					int nRead = input.read(rawData);
					if (nRead != rawData.length) {
						throw new IllegalStateException(
							"Unable to read enough bytes for " + opcode);
					}
					for (int i = 0; i < repeatCount - 1; ++i) {
						System.arraycopy(rawData, 0, data, index, rawData.length);
						index += rawData.length;
					}
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeatBlock) {
					int commonSize = count;
					int customSize = unpackNextValue(input);
					int repeatCount = unpackNextValue(input);

					byte[] commonData = new byte[commonSize];
					int nCommonRead = input.read(commonData);
					if (nCommonRead != commonData.length) {
						throw new IllegalStateException(
							"Unable to read enough common data bytes for " + opcode);
					}

					for (int i = 0; i < repeatCount; ++i) {
						System.arraycopy(commonData, 0, data, index, commonData.length);
						index += commonData.length;

						byte[] customData = new byte[customSize];
						int nCustomRead = input.read(customData);
						if (nCustomRead != customData.length) {
							throw new IllegalStateException(
								"Unable to read enough custom data bytes for " + opcode);
						}
						System.arraycopy(customData, 0, data, index, customData.length);
						index += customData.length;
					}

					//a final common data pattern is added at end...
					System.arraycopy(commonData, 0, data, index, commonData.length);
					index += commonData.length;
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeatZero) {
					int commonSize = count;
					int customSize = unpackNextValue(input);
					int repeatCount = unpackNextValue(input);

					for (int i = 0; i < repeatCount; ++i) {
						index += commonSize;//skip common size of zero bytes...

						byte[] customData = new byte[customSize];
						int nCustomRead = input.read(customData);
						if (nCustomRead != customData.length) {
							throw new IllegalStateException(
								"Unable to read enough custom data bytes for " + opcode);
						}
						System.arraycopy(customData, 0, data, index, customData.length);
						index += customData.length;
					}

					index += commonSize;//a final common size of zero bytes...
				}
				else {
					Msg.error(this, "Unrecognized packed data opcode: " + opcode);
				}
			}
			return data;
		}
    }

	private int unpackNextValue(InputStream input) throws IOException {
		int unpacked = 0;
		while (true) {
			unpacked <<= 7;
			int value = input.read();
			unpacked += (value & 0x7f);
			if ((value & 0x80) == 0x00) {
				break;
			}
		}
		return unpacked;
	}

	/**
	 * Returns the preferred address of this section.
	 * @return the preferred address of this section
	 */
	public int getDefaultAddress() {
		return defaultAddress;
	}

	public int getTotalLength() {
		return totalLength;
	}
	/**
	 * Returns the size in bytes of the "initialized" part of the contents.
	 * @return the size in bytes of the "initialized" part of the contents
	 */
	public int getUnpackedLength() {
		return unpackedLength;
	}
	/**
	 * Returns the size in bytes of the raw data in the container.
	 * @return the size in bytes of the raw data in the container
	 */
	public int getContainerLength() {
		return containerLength;
	}

	public int getContainerOffset() {
		return containerOffset;
	}

	public SectionKind getSectionKind() {
		return SectionKind.get(sectionKind);
	}

	public SectionShareKind getShareKind() {
		return SectionShareKind.get(shareKind);
	}

	public byte getAlignment() {
		return alignment;
	}
	/**
	 * Reserved!
	 * @return Reserved!
	 */
	public byte getReservedA() {
		return reservedA;
	}

	/**
	 * Returns true if this section has read permissions.
	 * @return true if this section has read permissions
	 */
	public boolean isRead() {
		return true;
	}
	/**
	 * Returns true if this section has write permissions.
	 * @return true if this section has write permissions
	 */
	public boolean isWrite() {
		SectionKind kind = getSectionKind();
		return kind == SectionKind.UnpackedData || 
			   kind == SectionKind.PackedData || 
			   kind == SectionKind.ExecutableData;
	}
	/**
	 * Returns true if this section has execute permissions.
	 * @return true if this section has execute permissions
	 */
	public boolean isExecute() {
		SectionKind kind = getSectionKind();
		return kind == SectionKind.Code || 
			   kind == SectionKind.ExecutableData;
	}

	@Override
	public String toString() {
		return "Name="+_name+" Kind="+getSectionKind()+" Share="+getShareKind();
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
