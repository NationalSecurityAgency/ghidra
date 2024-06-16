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
package ghidra.util.html;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.HTMLUtilities;

/**
 * Splits into lines a given String that is meant to be rendered as HTML.
 * 
 * <P>Really, this class exists simply to remove hundreds of lines of code from 
 * {@link HTMLUtilities}, which is what this code supports.  The methods in here could easily
 * be in {@link StringUtils}, but to keep dependencies low on code that has such a specific use, 
 * it lives here, with a name that implies you shouldn't use it unless you are working with 
 * HTML.
 */
public class HtmlLineSplitter {

	/** Used when trying to split on word boundaries; the value past which to give up */
	public static final int MAX_WORD_LENGTH = 10;

	/**
	 * Splits the given line into multiple lines based upon the given max length.  This method
	 * will first split on each newline and then wrap each of the lines returned from that split.
	 * 
	 * <P>The wrapping routine will attempt to wrap at word boundaries.
	 * 
	 * <P>This method does not retain leading whitespace.
	 * 
	 * @param text the text to wrap
	 * @param maxLineLength the max desired length of each output line; 0 or less signals not
	 *        to wrap the line based upon length
	 * @return the new lines
	 * @see #wrap(String, int, WhitespaceHandler)
	 * @see #split(String, int, boolean)
	 */
	public static List<String> split(String text, int maxLineLength) {
		return split(text, maxLineLength, false);
	}

	/**
	 * Splits the given line into multiple lines based upon the given max length.  This method
	 * will first split on each newline and then wrap each of the lines returned from that split.
	 * 
	 * <P>The wrapping routine will attempt to wrap at word boundaries.
	 * 
	 * @param text the text to wrap
	 * @param maxLineLength the max desired length of each output line; 0 or less signals not
	 *        to wrap the line based upon length
	 * @param retainSpacing true signals to keep whitespace on line breaks; false discards 
	 *        leading whitespace
	 * @return the new lines
	 * @see #wrap(String, int, WhitespaceHandler)
	 */
	public static List<String> split(String text, int maxLineLength, boolean retainSpacing) {

		List<String> lines = new ArrayList<>();
		int limit = -1;
		String[] newlines = text.split("\n", limit);
		if (maxLineLength <= 0) {
			// no wrapping to length needed
			lines.addAll(Arrays.asList(newlines));
			return lines;
		}

		WhitespaceHandler counter =
			retainSpacing ? new PreservingWhitespaceHandler() : new TrimmingWhitespaceHandler();

		for (String line : newlines) {
			if (line.length() == 0) {
				// this was a newline character
				lines.add(line);
				continue;
			}

			List<String> subLines = wrap(line, maxLineLength, counter);
			lines.addAll(subLines);
		}

		return lines;
	}

	/**
	 * Splits the given line into multiple lines based upon the given max length.
	 * 
	 * <P>Once the maximum provided length is passed, the algorithm attempts to split on a word
	 * boundary by first looking backwards in the given line (since the last split value) to
	 * find a space.  If no space is found in that direction, then the the algorithm will
	 * keep walking forward until either a space is found or {@link #MAX_WORD_LENGTH} is
	 * passed, at which point the line will be ended, splitting any word that surrounds 
	 * that index.
	 * 
	 * @param text the text to wrap
	 * @param maxLineLength the max desired length of each output line
	 * @param whitespacer the object that knows how to manipulate whitespace depending 
	 *        upon client preferences
	 * @return the new lines
	 */
	private static List<String> wrap(String text, int maxLineLength,
			WhitespaceHandler whitespacer) {

		List<String> lines = new ArrayList<>();
		int start = 0;
		int size = 0;
		boolean breakNeeded = false;
		boolean hasForcedBreak = false;

		int length = text.length();
		for (int i = 0; i < length; i++) {
			char c = text.charAt(i);
			size += (c == '\t') ? 4 : 1;

			boolean hitMaxLength = size >= maxLineLength;
			boolean isWhitespace = Character.isWhitespace(c);
			if (breakNeeded) {
				if (isWhitespace) { // we found a whitespace--break!
					String line = text.substring(start, i);
					lines.add(line);

					// left-justify by moving past spaces
					i += whitespacer.countSpaces(text, i);
					start = i;
					size = 0;
					breakNeeded = false;
				}
				// looking for a break; no whitespace--are we past the hard limit?
				else if (size - maxLineLength >= MAX_WORD_LENGTH) {

					// past hard limit; just chop at the original desired length
					hasForcedBreak = true;
					breakNeeded = false;
					int end = start + maxLineLength;
					lines.add(text.substring(start, end));
					start = end;
					size = i - start;
				}
			}
			else if (hitMaxLength) {

				breakNeeded = false;
				String line = text.substring(start, i);
				if (!isWhitespace) { // not on a whitespace; look for whitespace to split on

					int end = StringUtils.lastIndexOfAny(line, " ", "\t");
					if (end < 0) {
						// delay breaking for whitespace
						breakNeeded = true;
						continue;
					}

					// +1 to include the space; it will get trimmed below as needed
					line = line.substring(0, end + 1);
				}

				lines.add(whitespacer.trim(line));
				start = start + line.length();

				// left-justify by moving past spaces
				start += whitespacer.countSpaces(text, start);
				i = Math.max(i, start); // adjust for removed spaces

				// i != start when we chopped the line on a space before 'i'
				size = i - start;
			}
		}

		// handle any trailing text; don't split if no breaks were forced (this keeps the text
		// consistent--either break all text or break none)
		String line = whitespacer.trim(text.substring(start, length));
		int splitOn = hasForcedBreak ? maxLineLength : -1;
		List<String> remainder = forceSplitOn(line, splitOn);
		lines.addAll(remainder);

		return lines;
	}

	private static List<String> forceSplitOn(String s, int size) {

		List<String> lines = new ArrayList<>();
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			buffy.append(s.charAt(i));
			if (buffy.length() == size) {
				lines.add(buffy.toString());
				buffy.delete(0, buffy.length());
			}
		}

		if (buffy.length() > 0) {
			lines.add(buffy.toString());
		}

		return lines;
	}

}
