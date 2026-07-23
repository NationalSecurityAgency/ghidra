package ghidra.app.util.bin.format.stabs;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.Msg;

/** Container to hold a StabTypeDescriptor's type number */
public class StabsTypeNumber {

	/** The typeNumber used when none is present */
	public static final long NO_FILE_NUMBER = -1L;

	/** The file number */
	public final Long fileNumber;
	/** The type number */
	public final Long typeNumber;

	/** The regex pattern used for matching a type number */
	public static final Pattern TYPE_NUMBER_PATTERN =
		Pattern.compile("(\\d+)|(\\((\\d+),(\\d+)\\))");

	/**
	 * Constructs a new StabsTypeNumber
	 * @param stab the stab containing the type number
	 */
	public StabsTypeNumber(String stab) {
		Matcher matcher = TYPE_NUMBER_PATTERN.matcher(stab);
		if (matcher.find()) {
			if (matcher.group().contains(",")) {
				fileNumber = Long.parseLong(matcher.group(3));
				typeNumber = Long.parseLong(matcher.group(4));
			} else {
				fileNumber = NO_FILE_NUMBER;
				typeNumber = Long.parseLong(matcher.group());
			}
		} else {
			Msg.error(this, "remaining stub doesn't match expected pattern.\n"+stab);
			fileNumber = null;
			typeNumber = null;
		}
	}

	/**
	 * Constructs a new StabsTypeNumber
	 * @param file the file number to use or {@value #NO_FILE_NUMBER}
	 * @param index the type number to use
	 */
	public StabsTypeNumber(long file, long index) {
		fileNumber = file;
		typeNumber = index;
	}

	static long getFileNumber(String stab) {
		Matcher matcher = TYPE_NUMBER_PATTERN.matcher(stab);
		if (matcher.matches()) {
			if (matcher.group(1).contains(",")) {
				return Long.parseLong(matcher.group(4));
			}
		}
		return NO_FILE_NUMBER;
	}

	@Override
	public String toString() {
		if (fileNumber == NO_FILE_NUMBER) {
			return typeNumber.toString();
		}
		return String.format("(%d,%d)", fileNumber, typeNumber);
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof StabsTypeNumber) {
			final StabsTypeNumber other = (StabsTypeNumber) o;
			return other.fileNumber == fileNumber && other.typeNumber == typeNumber;
		}
		return false;
	}

	/**
	 * Checks if this StabTypeNumber has a valid file number.
	 * @return true if a file number is present
	 */
	public boolean hasFileNumber() {
		return fileNumber != NO_FILE_NUMBER;
	}

	/**
	 * @return the fileNumber
	 */
	public Long getFileNumber() {
		return fileNumber;
	}

	/**
	 * @return the typeNumber
	 */
	public Long getTypeNumber() {
		return typeNumber;
	}
}
