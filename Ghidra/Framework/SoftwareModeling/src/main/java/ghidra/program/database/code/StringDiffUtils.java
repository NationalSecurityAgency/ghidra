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

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import generic.algorithms.ReducingListBasedLcs;

class StringDiffUtils {

	/**
	 * Minimum size used to determine whether a new StringDiff object will be
	 * created just using a string (no positions)
	 * in the <code>getDiffs(String, String)</code> method.
	 * @see #getLineDiffs(String, String)
	 */
	private static int MINIMUM_DIFF_SIZE = 100;

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
		return getLineDiffs(s1, s2, MINIMUM_DIFF_SIZE);
	}

	static StringDiff[] getLineDiffs(String s1, String s2, int minimumDiffSize) {
		if (s2.length() < minimumDiffSize) {
			return new StringDiff[] { StringDiff.allTextReplaced(s2) };
		}

		List<Line> aList = split(s1);
		List<Line> bList = split(s2);
		LineLcs lcs = new LineLcs(aList, bList);
		List<Line> commons = lcs.getLcs();
		if (commons.isEmpty()) {
			// no common text--complete replacement
			return new StringDiff[] { StringDiff.allTextReplaced(s2) };
		}

		int aIndex = 0;
		int bIndex = 0;
		int aLastIndex = 0;
		int bLastIndex = 0;
		List<StringDiff> results = new LinkedList<>();
		for (Line common : commons) {

			aIndex = indexOf(aList, common, aLastIndex);
			bIndex = indexOf(bList, common, bLastIndex);

			int aDelta = aIndex - aLastIndex;
			int bDelta = bIndex - bLastIndex;

			int aEnd = aIndex;
			int aStart = aEnd - aDelta;
			List<Line> aPrevious = aList.subList(aStart, aEnd);
			StringDiff delete = createDelete(aPrevious);
			if (delete != null) {
				results.add(delete);
			}

			int bEnd = bIndex;
			int bStart = bEnd - bDelta;
			List<Line> bPrevious = bList.subList(bStart, bEnd);
			StringDiff insert = createInsert(bPrevious, charOffset(aList, aIndex));
			if (insert != null) {
				results.add(insert);
			}

			// note: nothing is needed for the 'common' string, since we don't track unchanged text

			aLastIndex = aIndex + 1;
			bLastIndex = bIndex + 1;
		}

		// grab remainder
		StringDiff trailingDeleted = createDeleteAtEnd(aList, aLastIndex, aList.size());
		if (trailingDeleted != null) {
			results.add(trailingDeleted);
		}

		StringDiff trailingInserted =
			createInsertAtEnd(bList, bLastIndex, bList.size(), s1.length());
		if (trailingInserted != null) {
			results.add(trailingInserted);
		}

		return results.toArray(new StringDiff[results.size()]);
	}

	private static int charOffset(List<Line> list, int index) {
		Line line = list.get(index);
		return line.start;
	}

	private static StringDiff createInsertAtEnd(List<Line> list, int start, int end,
			int insertIndex) {
		if (start - 1 == end) {
			return null;
		}

		List<Line> toDo = list.subList(start, end);
		boolean newlineNeeded = true; // we are at the end--need a newline
		StringDiff insert = createInsert(toDo, insertIndex, newlineNeeded);
		return insert;
	}

	private static StringDiff createInsert(List<Line> lines, int insertIndex) {
		return createInsert(lines, insertIndex, false);
	}

	private static StringDiff createInsert(List<Line> lines, int insertIndex, boolean isAtEnd) {
		if (lines.isEmpty()) {
			return null;
		}

		StringBuilder buffy = new StringBuilder();

		// special case: if this insert is for the end of the line, then we want to add 
		//               a newline before the remaining text is added since the original text
		//               did not have this newline
		if (isAtEnd) {
			buffy.append('\n');
		}

		for (Line line : lines) {
			buffy.append(line.getText());
		}

		return StringDiff.textInserted(buffy.toString(), insertIndex);
	}

	private static StringDiff createDeleteAtEnd(List<Line> list, int start, int end) {

		if (start - 1 == end) {
			return null;
		}

		List<Line> toDo = list.subList(start, end);
		boolean includeLastNewline = false; // we are at the end--do not include artificial newline
		StringDiff delete = createDelete(toDo, includeLastNewline);
		return delete;
	}

	private static StringDiff createDelete(List<Line> lines) {
		return createDelete(lines, true);
	}

	private static StringDiff createDelete(List<Line> lines, boolean includeLastNewline) {
		if (lines.isEmpty()) {
			return null;
		}

		int start = 0;
		int end = 0;
		for (Line line : lines) {
			start = line.start;
			end = line.start + line.text.length();
		}

		// special case: if this delete is for the last line, then we want to remove the remaining
		//               trailing newline
		Line last = lines.get(lines.size() - 1);
		if (!includeLastNewline && last.isLastLine) {
			start -= 1; // remove previous newline
		}

		return StringDiff.textDeleted(start, end);
	}

	private static int indexOf(List<Line> list, Line line, int from) {
		for (int i = from; i < list.size(); i++) {
			if (list.get(i).textMatches(line)) {
				return i;
			}
		}
		return list.size(); // should not get here since 's' is known to be in list
	}

	private static List<Line> split(String s) {

		LinkedList<Line> result = new LinkedList<>();
		List<String> lines = Arrays.asList(StringUtils.splitPreserveAllTokens(s, '\n'));
		int start = 0;
		for (String line : lines) {
			Line l = new Line(line + '\n', start);
			result.add(l);
			start += l.text.length();
		}

		if (result.isEmpty()) {
			result.add(new Line("", 0));
		}

		Line last = result.peekLast();
		last.markAsLast(); // this will signal to remove the trailing newline for the last line

		return result;
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

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private static class Line {

		private String text;
		private int start;
		private boolean isLastLine;

		public Line(String line, int start) {
			this.text = line;
			this.start = start;
		}

		String getText() {
			if (isLastLine) {
				return textWithoutNewline(); // last line and do not include the newline
			}
			return text;
		}

		void markAsLast() {
			isLastLine = true;
		}

		private String textWithoutNewline() {
			if (text.charAt(text.length() - 1) == '\n') {
				return text.substring(0, text.length() - 1);
			}
			return text;
		}

		@Override
		public String toString() {
			return textWithoutNewline() + " @ " + start;
		}

		boolean textMatches(Line other) {
			return Objects.equals(text, other.text);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + start;
			result = prime * result + ((text == null) ? 0 : text.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			Line other = (Line) obj;
			if (start != other.start) {
				return false;
			}
			if (text == null) {
				if (other.text != null) {
					return false;
				}
			}
			else if (!text.equals(other.text)) {
				return false;
			}
			return true;
		}
	}

	private static class LineLcs extends ReducingListBasedLcs<Line> {

		LineLcs(List<Line> x, List<Line> y) {
			super(x, y);
		}

		@Override
		protected boolean matches(Line x, Line y) {
			return x.text.equals(y.text);
		}
	}
}
