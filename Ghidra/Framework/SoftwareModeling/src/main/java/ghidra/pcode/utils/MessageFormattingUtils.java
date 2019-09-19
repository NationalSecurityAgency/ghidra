package ghidra.pcode.utils;

import ghidra.sleigh.grammar.Location;

public final class MessageFormattingUtils {

	/**
	 * Format a log message.
	 *
	 * @param location Referenced file location
	 * @param message Message
	 * @return Formatted string with location prepended to message.
	 */
	public static String format(Location location, CharSequence message) {
		StringBuilder sb = new StringBuilder();
		if (location != null) {
			sb.append(location).append(": ");
		}
		sb.append(message);
		return sb.toString().trim();
	}

}
