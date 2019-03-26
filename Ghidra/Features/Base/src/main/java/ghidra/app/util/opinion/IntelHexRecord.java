/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.opinion;

import java.util.Arrays;

public class IntelHexRecord {
	public static final int MAX_RECORD_LENGTH = 255;

	public static final int DATA_RECORD_TYPE = 0x00;
	public static final int END_OF_FILE_RECORD_TYPE = 0x01;
	public static final int EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE = 0x02;
	public static final int START_SEGMENT_ADDRESS_RECORD = 0x03;
	public static final int EXTENDED_LINEAR_ADDRESS_RECORD_TYPE = 0x04;
	public static final int START_LINEAR_ADDRESS_RECORD_TYPE = 0x05;

	private final int recordLength;
	private final int loadOffset;
	private final int recordType;
	private final byte[] data;
	private final int checksum;
	private final int actualChecksum;

	/**
	 * Use this constructor when reading, so you know if the record's checksum is correct.
	 * @param recordLength
	 * @param loadOffset
	 * @param recordType
	 * @param data
	 * @param checksum
	 */
	public IntelHexRecord(int recordLength, int loadOffset, int recordType, byte[] data,
			int checksum) {
		this.recordLength = recordLength;
		this.loadOffset = loadOffset;
		this.recordType = recordType;
		this.data = new byte[data.length];
		System.arraycopy(data, 0, this.data, 0, data.length);
		this.checksum = checksum;
		this.actualChecksum = checksum(recordLength, loadOffset, recordType, data);

		checkValidity();
	}

	/**
	 * Only use this constructor when writing...it computes the checksum for you (cheating)!
	 * @param recordLength
	 * @param loadOffset
	 * @param recordType
	 * @param data
	 */
	public IntelHexRecord(int recordLength, int loadOffset, int recordType, byte[] data) {
		this(recordLength, loadOffset, recordType, data, checksum(recordLength, loadOffset,
			recordType, data));
	}

	private void checkValidity() {
		checkRecordLength();
		checkLoadOffset();
		checkRecordType();
	}

	private void checkLoadOffset() {
		if (getLoadOffset() < 0) {
			throw new IllegalArgumentException("loadOffset < 0");
		}
		if (getLoadOffset() > 0xffff) {
			throw new IllegalArgumentException("loadOffset > 0xffff");
		}
	}

	private void checkRecordType() {
		switch (getRecordType()) {
			case DATA_RECORD_TYPE:
				// valid, no real restrictions
				break;
			case END_OF_FILE_RECORD_TYPE:
				if (getRecordLength() != 0) {
					throw new IllegalArgumentException("bad length (" + getRecordLength() +
						") for End Of File Record");
				}
				if (getLoadOffset() != 0) {
					throw new IllegalArgumentException("bad load offset (" + getLoadOffset() +
						") for End Of File Record");
				}
				break;
			case EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE:
				if (getRecordLength() != 2) {
					throw new IllegalArgumentException("bad length (" + getRecordLength() +
						") for Extended Segment Address Record");
				}
				if (getLoadOffset() != 0) {
					throw new IllegalArgumentException("bad load offset (" + getLoadOffset() +
						") for Extended Segment Address Record");
				}
				break;
			case START_SEGMENT_ADDRESS_RECORD:
				if (getRecordLength() != 4) {
					throw new IllegalArgumentException("bad length (" + getRecordLength() +
						") for Start Segment Address Record");
				}
				if (getLoadOffset() != 0) {
					throw new IllegalArgumentException("bad load offset (" + getLoadOffset() +
						") for Start Segment Address Record");
				}
				break;
			case EXTENDED_LINEAR_ADDRESS_RECORD_TYPE:
				if (getRecordLength() != 2) {
					throw new IllegalArgumentException("bad length (" + getRecordLength() +
						") for Extended Linear Address Record");
				}
				if (getLoadOffset() != 0) {
					throw new IllegalArgumentException("bad load offset (" + getLoadOffset() +
						") for Extended Linear Address Record");
				}
				break;
			case START_LINEAR_ADDRESS_RECORD_TYPE:
				if (getRecordLength() != 4) {
					throw new IllegalArgumentException("bad length (" + getRecordLength() +
						") for Start Linear Address Record");
				}
				if (getLoadOffset() != 0) {
					throw new IllegalArgumentException("bad load offset (" + getLoadOffset() +
						") for Start Linear Address Record");
				}
				break;
			default:
				throw new IllegalArgumentException("illegal record type - " + getRecordType());
		}
	}

	private void checkRecordLength() {
		// inadvertently checks for < 0 because array size must be positive
		if (getRecordLength() != data.length) {
			throw new IllegalArgumentException("recordLength != data.length");
		}
		if (getRecordLength() > MAX_RECORD_LENGTH) {
			throw new IllegalArgumentException("recordLength > " + MAX_RECORD_LENGTH);
		}
	}

	private static int checksum(int recordLength, int loadOffset, int recordType, byte[] data) {
		int accum = 0;
		accum += recordLength & 0xff;
		accum += loadOffset & 0xff;
		accum += (loadOffset >> 8) & 0xff;
		accum += recordType & 0xff;
		for (int ii = 0; ii < data.length; ++ii) {
			final int t = data[ii] & 0xff;
			accum += t;
		}
		final int lowest = accum & 0xff;
		final int chk = (0x100 - lowest) & 0xff;
		return chk;
	}

	public int getRecordLength() {
		return recordLength;
	}

	public int getLoadOffset() {
		return loadOffset;
	}

	public int getRecordType() {
		return recordType;
	}

	public byte[] getData() {
		byte[] result = new byte[data.length];
		System.arraycopy(data, 0, result, 0, data.length);
		return result;
	}

	public String getDataString() {
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < data.length; i++) {
			buffy.append(String.format("%02X", data[i]));
		}
		return buffy.toString();
	}

	public int getReportedChecksum() {
		return checksum;
	}

	public int getActualChecksum() {
		return actualChecksum;
	}

	public boolean isReportedChecksumCorrect() {
		return checksum == actualChecksum;
	}

	public String format() {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format(":%02X%04X%02X", getRecordLength(), getLoadOffset(),
			getRecordType()));
		// warning: careful with that axe, Eugene
		for (int ii = 0; ii < data.length; ++ii) {
			sb.append(String.format("%02X", data[ii]));
		}
		sb.append(String.format("%02X", getActualChecksum()));
		return sb.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + actualChecksum;
		result = prime * result + checksum;
		result = prime * result + Arrays.hashCode(data);
		result = prime * result + loadOffset;
		result = prime * result + recordLength;
		result = prime * result + recordType;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		IntelHexRecord other = (IntelHexRecord) obj;
		if (actualChecksum != other.actualChecksum)
			return false;
		if (checksum != other.checksum)
			return false;
		if (!Arrays.equals(data, other.data))
			return false;
		if (loadOffset != other.loadOffset)
			return false;
		if (recordLength != other.recordLength)
			return false;
		if (recordType != other.recordType)
			return false;
		return true;
	}
}
