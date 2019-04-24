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
package ghidra.program.database.code;

import java.util.LinkedList;
import java.util.List;

class StringDiffer {

	/**
	 * Returns the list of StringDiff objects that if applied to s1 would result in s2;  The
	 * given text will look only for whole lines using '\n'.
	 *
	 * @param s1 the original string
	 * @param s2 the result string
	 *        this value, then a completely different string will be returned
	 * @return an array of StringDiff objects that change s1 into s2;
	 */
	static StringDiff[] getLineDiffs(String s1, String s2) {

		/**
		 * Minimum size used to determine whether a new StringDiff object will be
		 * created just using a string (no positions)
		 * in the <code>getDiffs(String, String)</code> method.
		 * @see #getLineDiffs(String, String)
		 */
		int MINIMUM_DIFF_SIZE = 100;
		return StringDiffer.getLineDiffs(s1, s2, MINIMUM_DIFF_SIZE);
	}

	/**
	 * Returns the list of StringDiff objects that if applied to s1 would result in s2;  The
	 * given text will look only for whole lines using '\n'.
	 *
	 * @param s1 the original string
	 * @param s2 the result string
	 * @param minimumDiffSize the minimum length of s2 required for a diff; if s2 is less than
	 *        this value, then a completely different string will be returned
	 * @return an array of StringDiff objects that change s1 into s2;
	 */
	static StringDiff[] getLineDiffs(String s1, String s2, int minimumDiffSize) {
		if (s2.length() < minimumDiffSize) {
			return new StringDiff[] { StringDiff.allTextReplaced(s2) };
		}

		List<StringDiff> results = new LinkedList<>();
		int cursor1 = 0;
		int cursor2 = 0;
		int len1 = s1.length();
		int len2 = s2.length();

		/*
		 	-look at each line in 'line' chunks using '\n'
		 */

		// walk each string until the end...
		while (cursor1 < len1 || cursor2 < len2) {
			String line1 = getLine(s1, cursor1);
			String line2 = getLine(s2, cursor2);
			if (line1.equals(line2)) {
				cursor1 += line1.length();
				cursor2 += line2.length();
				continue;
			}

			// look for line1 in s2...
			int line1PosInOther = findLine(s2, cursor2, line1);
			int mark = cursor1;
			while (line1PosInOther < 0) {

				// line1 is not in s2; scan for the next line
				cursor1 += line1.length();
				line1 = getLine(s1, cursor1);
				line1PosInOther = findLine(s2, cursor2, line1);
			}
			if (cursor1 > mark) {
				// the original line1 was not in s2; add all that was different up to current cursor1
				results.add(StringDiff.textDeleted(mark, cursor1));
			}

			// now look for line2 in s1
			int line2PosInOther = findLine(s1, cursor1, line2);
			mark = cursor2;
			while (line2PosInOther < 0) {

				// line2 is not in s1; scan for the next line
				cursor2 += line2.length();
				line2 = getLine(s2, cursor2);
				line2PosInOther = findLine(s1, cursor1, line2);
			}
			if (cursor2 > mark) {
				// the original line2 was not in s1; add all that was different up to current cursor2
				results.add(StringDiff.textInserted(s2.substring(mark, cursor2), cursor1));
				continue;
			}

			// move both searches forward
			int delta1 = line2PosInOther - cursor1;
			int delta2 = line1PosInOther - cursor2;
			if (delta1 > delta2) {

				// this can happen when two lines have been rearranged *and* the line length
				// of the moved line is *longer* than the new line at the replaced position
				results.add(
					StringDiff.textInserted(s2.substring(cursor2, line1PosInOther), cursor1));
				cursor2 = line1PosInOther;
			}
			else if (delta2 > delta1) {

				// this can happen when two lines have been rearranged *and* the line length
				// of the moved line is *shorter* than the new line at the replaced position
				results.add(StringDiff.textDeleted(cursor1, line2PosInOther));
				cursor1 = line2PosInOther;
			}
			else { // delta1 == delta2

				if (cursor1 != line2PosInOther) {
					results.add(StringDiff.textDeleted(cursor1, line2PosInOther));
					cursor1 = line2PosInOther;
				}

				if (cursor2 != line1PosInOther) {
					results.add(
						StringDiff.textInserted(s2.substring(cursor2, line1PosInOther), cursor1));
					cursor2 = line1PosInOther;
				}
			}
		}
		return results.toArray(new StringDiff[results.size()]);
	}

	/**
	 * Finds a position in s that contains the string line.  The matching string in
	 * s must be a "complete" line, in other words if pos > 0 then s.charAt(index-1) must be
	 * a newLine character and s.charAt(index+line.length()) must be a newLine or the end of
	 * the string.
	 * @param s the string to scan
	 * @param pos the position to begin the scan.
	 * @param line the line to scan for
	 * @return the position in s containing the line string.
	 */
	static int findLine(String s, int pos, String line) {

		if (line.length() == 0) {
			// this is used as a marker: -1 means not found; non-negative number signals to keep going
			return pos;  // TODO this is odd; why is this a match??
		}

		int n = s.length();
		while (pos < n) {
			int index = s.indexOf(line, pos);
			if (index < 0) {
				return index;
			}

			if (index > 0 && s.charAt(index - 1) != '\n') {
				pos = index + line.length(); // line matched, but not a newline in 's'
				continue;
			}

			//
			// Have a match with at start/0 or have a preceding newline
			//

			if (line.endsWith("\n")) {
				return index; // the match ends with a newline; found line
			}

			// no newline for the current match in 's'
			if (index + line.length() == n) {
				return index; // at the end exactly; found line
			}

			// no newline; not at end; keep going
			pos = index + line.length();
		}

		return -1;
	}

	/**
	 * Returns a substring of s beginning at start and ending at either the end of the string or
	 * the first newLine at or after start
	 * 
	 * @param s the string to scan
	 * @param start the starting position for the scan
	 * @return a string that represents a line within s
	 */
	private static String getLine(String s, int start) {
		int n = s.length();
		if (start >= n) {
			return "";
		}
		int pos = start;
		while (pos < n && s.charAt(pos) != '\n') {
			pos++;
		}

		if (pos < n) {
			pos++; // not at the end; found newline; include the newline
		}
		return s.substring(start, pos);
	}

	/**
	 * Applies the array of StringObjects to the string s to produce a new string. Warning - the
	 * diff objects cannot be applied to an arbitrary string, the Strings must be the original
	 * String used to compute the diffs.
	 * @param s the original string
	 * @param diffs the array of StringDiff object to apply
	 * @return a new String resulting from applying the diffs to s.
	 */
	static String applyDiffs(String s, List<StringDiff> diffs) {

		if (diffs.isEmpty()) {
			return s;
		}

		if (diffs.get(0).start < 0) {
			// all replaced or all deleted
			String data = diffs.get(0).text;
			return data == null ? "" : data;
		}

		int pos = 0;
		StringBuilder buf = new StringBuilder(s.length());
		for (StringDiff element : diffs) {
			if (element.start > pos) {
				buf.append(s.substring(pos, element.start));
				pos = element.start;
			}

			String data = element.text;
			if (data != null) {
				buf.append(data);
			}
			else {
				// null data is a delete; move to the end of the delete
				pos = element.end;
			}
		}

		if (pos < s.length()) {
			buf.append(s.substring(pos));
		}
		return buf.toString();
	}
}
