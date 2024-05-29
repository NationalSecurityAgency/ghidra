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
package ghidra.app.plugin.core.terminal;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldRange;
import ghidra.app.plugin.core.terminal.TerminalPanel.FindOptions;
import ghidra.app.plugin.core.terminal.vt.VtLine;

/**
 * The algorithm for finding text in the terminal buffer.
 * 
 * <p>
 * This is an abstract class, so that text search and regex search are better separated, while the
 * common parts need not be duplicated.
 */
public abstract class TerminalFinder {
	protected final TerminalLayoutModel model;
	protected final FieldLocation cur;
	protected final boolean forward;

	protected final boolean caseSensitive;
	protected final boolean wrap;
	protected final boolean wholeWord;

	protected final StringBuilder sb = new StringBuilder();

	/**
	 * Create a finder on the given model
	 * 
	 * @see TerminalPanel#find(String, Set, FieldLocation, boolean)
	 * @param model the model
	 * @param cur the start of the current selection, or null
	 * @param forward true for forward, false for backward
	 * @param options a set of options, preferably an {@link EnumSet}
	 */
	protected TerminalFinder(TerminalLayoutModel model, FieldLocation cur, boolean forward,
			Set<FindOptions> options) {
		this.model = model;
		if (cur != null) {
			this.cur = cur;
		}
		else if (forward) {
			this.cur = new FieldLocation();
		}
		else {
			BigInteger maxIndex = model.getNumIndexes().subtract(BigInteger.ONE);
			int maxChar = model.getLayout(maxIndex).line.length();
			this.cur = new FieldLocation(maxIndex, 0, 0, maxChar);
		}
		this.forward = forward;
		this.caseSensitive = options.contains(FindOptions.CASE_SENSITIVE);
		this.wrap = options.contains(FindOptions.WRAP);
		this.wholeWord = options.contains(FindOptions.WHOLE_WORD);
	}

	protected abstract void caseBuf(StringBuilder sb);

	protected boolean isWholeWord(int i, String match) {
		if (i > 0 && VtLine.isWordChar(sb.charAt(i - 1))) {
			return false;
		}
		int iAfter = i + match.length();
		if (iAfter < sb.length() && VtLine.isWordChar(sb.charAt(iAfter))) {
			return false;
		}
		return true;
	}

	protected abstract FieldRange findInLine(int start, BigInteger index);

	protected boolean continueIndex(BigInteger index, BigInteger end) {
		if (forward) {
			return index.compareTo(end) <= 0;
		}
		return index.compareTo(end) >= 0;
	}

	/**
	 * Search within the layouts in the given range of indices, inclusive
	 * 
	 * @param start the first index
	 * @param end the last index, inclusive
	 * @param step the step (1 or -1)
	 * @return the field range, if found, or null
	 */
	protected FieldRange findInIndices(BigInteger start, BigInteger end, BigInteger step) {
		for (BigInteger index = start; continueIndex(index, end); index = index.add(step)) {
			TerminalLayout layout = model.getLayout(index);
			VtLine line = layout.line;
			sb.delete(0, sb.length());
			line.gatherText(sb, 0, line.length());
			caseBuf(sb);
			int s;
			if (index.equals(cur.getIndex())) {
				s = cur.getCol();
			}
			else {
				s = forward ? 0 : line.length() - 1;
			}
			FieldRange found = findInLine(s, index);
			if (found != null) {
				return found;
			}
		}
		return null;
	}

	/**
	 * Execute the search
	 * 
	 * @return the range covering the found term, or null if not found
	 */
	public FieldRange find() {
		BigInteger step = forward ? BigInteger.ONE : BigInteger.ONE.negate();
		BigInteger maxIndex = model.getNumIndexes().subtract(BigInteger.ONE);
		FieldRange found = findInIndices(cur.getIndex(),
			forward ? maxIndex : BigInteger.ZERO, step);
		if (found != null) {
			return found;
		}
		if (!wrap) {
			return null;
		}
		return findInIndices(forward ? BigInteger.ZERO : maxIndex,
			cur.getIndex(), step);
	}

	/**
	 * A finder that searches for exact text, case insensitive by default
	 */
	public static class TextTerminalFinder extends TerminalFinder {
		protected final String text;

		/**
		 * @see TerminalPanel#find(String, Set, FieldLocation, boolean)
		 */
		public TextTerminalFinder(TerminalLayoutModel model, FieldLocation cur, boolean forward,
				String text, Set<FindOptions> options) {
			super(model, cur, forward, options);
			if (text.isEmpty()) {
				throw new IllegalArgumentException("Empty text");
			}
			if (!caseSensitive) {
				this.text = text.toLowerCase();
			}
			else {
				this.text = text;
			}
		}

		@Override
		protected FieldRange findInLine(int start, BigInteger index) {
			int length = sb.length();
			int i = Math.min(start, length - 1);
			int step = forward ? 1 : -1;
			while (0 <= i && i < length) {
				i = forward ? sb.indexOf(text, i) : sb.lastIndexOf(text, i);
				if (i == -1) {
					return null;
				}
				if (!wholeWord || isWholeWord(i, text)) {
					return new FieldRange(
						new FieldLocation(index, 0, 0, i),
						new FieldLocation(index, 0, 0, i + text.length()));
				}
				i += step;
			}
			return null;
		}

		protected void lowerBuf(StringBuilder sb) {
			for (int i = 0; i < sb.length(); i++) {
				sb.setCharAt(i, Character.toLowerCase(sb.charAt(i)));
			}
		}

		@Override
		protected void caseBuf(StringBuilder sb) {
			if (!caseSensitive) {
				lowerBuf(sb);
			}
		}
	}

	/**
	 * A find that searches for regex patterns, case insensitive by default
	 */
	public static class RegexTerminalFinder extends TerminalFinder {
		protected final Pattern pattern;

		/**
		 * @see TerminalPanel#find(String, Set, FieldLocation, boolean)
		 */
		public RegexTerminalFinder(TerminalLayoutModel model, FieldLocation cur, boolean forward,
				String pattern, Set<FindOptions> options) {
			super(model, cur, forward, options);
			if (pattern.isEmpty()) {
				throw new IllegalArgumentException("Empty pattern");
			}
			if (!caseSensitive) {
				this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
			}
			else {
				this.pattern = Pattern.compile(pattern);
			}
		}

		@Override
		protected FieldRange findInLine(int start, BigInteger index) {
			Matcher matcher = pattern.matcher(sb);
			int length = sb.length();
			if (length == 0) {
				return null;
			}
			start = Math.min(length - 1, start);
			if (forward) {
				for (int i = start; i < length && matcher.find(i);) {
					if (!wholeWord || isWholeWord(i, matcher.group())) {
						return new FieldRange(
							new FieldLocation(index, 0, 0, matcher.start()),
							new FieldLocation(index, 0, 0, matcher.end()));
					}
					i = matcher.start() + 1;
				}
				return null;
			}
			int lastStart = -1;
			int lastEnd = -1;
			for (int i = 0; i <= start && matcher.find(i);) {
				if (!wholeWord || isWholeWord(i, matcher.group())) {
					if (matcher.start() > start) {
						break;
					}
					lastStart = matcher.start();
					lastEnd = matcher.end();
				}
				i = matcher.start() + 1;
			}
			if (lastStart == -1) {
				return null;
			}
			return new FieldRange(
				new FieldLocation(index, 0, 0, lastStart),
				new FieldLocation(index, 0, 0, lastEnd));
		}

		@Override
		protected void caseBuf(StringBuilder sb) {
			// Nothing. Pattern handles it.
		}
	}
}
