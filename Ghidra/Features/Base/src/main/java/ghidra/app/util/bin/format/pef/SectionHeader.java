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

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

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
	 * @throws IllegalStateException an an unexpected state occurs
	 */
	public byte[] getUnpackedData(TaskMonitor monitor) throws IOException, IllegalStateException {
		if (getSectionKind() != SectionKind.PackedData) {
			throw new IOException("Attempt to unpack a section that is not packed.");
		}
		if (getUnpackedLength() < 0) {
			throw new IllegalStateException("Invalid unpacked length: " + getUnpackedLength());
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
					throw new IllegalStateException("Unexpectedly reached end-of-file");
				}
				int count = value & 0x1f;//count is the lower 5 bits...
				if (count == 0) {
					count = unpackNextValue(input);
				}
				PackedDataOpcodes opcode = PackedDataOpcodes.get(value >> 5);
				if (opcode == PackedDataOpcodes.kPEFPkDataZero) {
					index = skip(data, index, count, opcode);
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataBlock) {
					byte[] rawData = readFully(input, count, data, index, opcode);
					index = copy(rawData, data, index, opcode);
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeat) {
					int repeatCount = unpackNextValue(input);
					byte[] rawData = readFully(input, count, data, index, opcode);
					for (int i = 0; i < repeatCount + 1; ++i) {
						index = copy(rawData, data, index, opcode);
					}
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeatBlock) {
					int commonSize = count;
					int customSize = unpackNextValue(input);
					int repeatCount = unpackNextValue(input);

					byte[] commonData = readFully(input, commonSize, data, index, opcode);

					for (int i = 0; i < repeatCount; ++i) {
						index = copy(commonData, data, index, opcode);

						byte[] customData = readFully(input, customSize, data, index, opcode);
						index = copy(customData, data, index, opcode);
					}

					//a final common data pattern is added at end...
					index = copy(commonData, data, index, opcode);
				}
				else if (opcode == PackedDataOpcodes.kPEFPkDataRepeatZero) {
					int commonSize = count;
					int customSize = unpackNextValue(input);
					int repeatCount = unpackNextValue(input);

					for (int i = 0; i < repeatCount; ++i) {
						index = skip(data, index, commonSize, opcode);//skip common size of zero bytes...

						byte[] customData = readFully(input, customSize, data, index, opcode);
						index = copy(customData, data, index, opcode);
					}

					index = skip(data, index, commonSize, opcode);//a final common size of zero bytes...
				}
				else {
					Msg.error(this, "Unrecognized packed data opcode: " + opcode);
				}
			}
			return data;
		}
	}

	/**
	 * Reads exactly {@code size} bytes from the packed data stream, after verifying that they
	 * will fit in the remaining unpacked data buffer (prevents excessive allocations caused by
	 * corrupted size values).
	 */
	private static byte[] readFully(InputStream input, int size, byte[] data, int index,
			PackedDataOpcodes opcode) throws IOException, IllegalStateException {
		ensureFits(data, index, size, opcode);
		byte[] bytes = input.readNBytes(size);
		if (bytes.length != size) {
			throw new IllegalStateException("Unable to read enough bytes for " + opcode);
		}
		return bytes;
	}

	private static int copy(byte[] src, byte[] data, int index, PackedDataOpcodes opcode)
			throws IllegalStateException {
		ensureFits(data, index, src.length, opcode);
		System.arraycopy(src, 0, data, index, src.length);
		return index + src.length;
	}

	private static int skip(byte[] data, int index, int size, PackedDataOpcodes opcode)
			throws IllegalStateException {
		if (size < 0) {
			ensureFits(data, index, size, opcode); // throws
		}
		// zero-fill past the end is harmless (buffer is already zeroed), clamp to preserve
		// historical tolerance and avoid int overflow of the index
		return (int) Math.min((long) index + size, data.length);
	}

	private static void ensureFits(byte[] data, int index, int size, PackedDataOpcodes opcode)
			throws IllegalStateException {
		if (size < 0 || size > data.length - index) {
			throw new IllegalStateException(
				"Packed data for %s exceeds unpacked length: index=%d, size=%d, length=%d"
						.formatted(opcode, index, size, data.length));
		}
	}

	private int unpackNextValue(InputStream input) throws IOException, IllegalStateException {
		int unpacked = 0;
		while (true) {
			if ((unpacked & ~(Integer.MAX_VALUE >>> 7)) != 0) {
				throw new IllegalStateException("Packed value is too large");
			}
			unpacked <<= 7;
			int value = input.read();
			if (value == -1) {
				throw new IllegalStateException("Unexpectedly reached end-of-file");
			}
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

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
