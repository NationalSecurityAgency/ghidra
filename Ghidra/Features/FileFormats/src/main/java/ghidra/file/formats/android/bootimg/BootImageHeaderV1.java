/* ###
 * IP: LICENSE
 */
package ghidra.file.formats.android.bootimg;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#156
 */
public class BootImageHeaderV1 extends BootImageHeaderV0 {

	private int recovery_dtbo_size;
	private long recovery_dtbo_offset;
	private int header_size;

	public BootImageHeaderV1(BinaryReader reader) throws IOException {
		super(reader);
		recovery_dtbo_size = reader.readNextInt();
		recovery_dtbo_offset = reader.readNextLong();
		header_size = reader.readNextInt();
	}

	/**
	 * Size in bytes for recovery DTBO/ACPIO image
	 * @return recovery DTBO/ACPIO image byte size
	 */
	public int getRecoveryDtboSize() {
		return recovery_dtbo_size;
	}

	/**
	 * p = (recovery_dtbo_size + page_size - 1) / page_size
	 * @return the recovery DTBO adjusted size, as page counts
	 */
	public int getRecoveryDtboSizeAdjusted() {
		return (int) (pageAlign(Integer.toUnsignedLong(recovery_dtbo_size)) / getPageSize());
	}

	/**
	 * Offset to recovery dtbo/acpio in boot image
	 * @return the recover DTBO offset
	 */
	public long getRecoveryDtboOffset() {
		return recovery_dtbo_offset;
	}

	public int getHeaderSize() {
		return header_size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		try {
			structure.setName("boot_img_hdr_v1");
		}
		catch (InvalidNameException e) {
			//ignore
		}
		structure.add(DWORD, "recovery_dtbo_size", null);
		structure.add(QWORD, "recovery_dtbo_offset", null);
		structure.add(DWORD, "header_size", null);
		return structure;
	}

}
