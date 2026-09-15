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
package generic.algorithms;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

/**
 * Finds differences between two words (any two Strings).  The results are available via 
 * {@link #getParts()}.
 */
public class WordDiffer {

	private List<WordPart> parts = List.of();

	/**
	 * Diffs the text between the old and new word.  The new word is the current version of two 
	 * Strings, the old word is the previous version.
	 * 
	 * @param oldWord the previous version of the text
	 * @param newWord the current version of the text
	 */
	public WordDiffer(String oldWord, String newWord) {

		LcsMatch lcs = getLcs(newWord, oldWord);
		if (lcs == null) {
			return;
		}

		TreeMap<Integer, String> wordsByOffset = buildWordOffsets(lcs);

		parts = createWordParts(newWord, wordsByOffset);
	}

	/**
	 * Returns the 'new word' broken into Strings with offsets, with each part being the same text
	 * or different text.
	 * @return the parts; empty if the LCS could not be created
	 */
	public List<WordPart> getParts() {
		return parts;
	}

	/**
	 * The same as {@link #getParts()} except that this method will merge differences that are 
	 * separated only by {@code maxSize} or less characters.  This method allows clients to combine
	 * many smaller differences into larger differences that span similar characters.  Merging parts
	 * can reduce visual clutter when displaying the differences, at the expense of accuracy.
	 * 
	 * @param maxSize the maximum span of characters past which not to merge two differences
	 * @return the parts
	 */
	public List<WordPart> getMergedParts(int maxSize) {

		List<WordPart> newParts = new ArrayList<>();
		DifferentPart lastDiffPart = null;
		for (int i = 0; i < parts.size(); i++) {
			WordPart part = parts.get(i);
			if (part instanceof DifferentPart diffPart) {
				lastDiffPart = diffPart;
				newParts.add(lastDiffPart);
				continue;
			}

			int length = part.length();
			if (length > maxSize) {
				continue;
			}

			if (lastDiffPart != null) {
				WordPart nextPart = i + 1 < parts.size() ? parts.get(i + 1) : null;
				WordPart mergedPart = lastDiffPart.merge(part, nextPart);
				if (mergedPart != null) {
					i++;
					newParts.remove(lastDiffPart);
					newParts.add(mergedPart);
					lastDiffPart = null;
				}
			}
			// add this non-diff part to the last merged diff part, if any exists
			else {
				if (newParts.isEmpty()) {
					continue;
				}

				DifferentPart previousDiffPart = (DifferentPart) newParts.getLast();
				WordPart nextPart = i + 1 < parts.size() ? parts.get(i + 1) : null;
				WordPart mergedPart = previousDiffPart.merge(part, nextPart);
				if (mergedPart != null) {
					i++;
					newParts.remove(previousDiffPart);
					newParts.add(mergedPart);
				}
			}
		}
		return newParts;
	}

	@Override
	public String toString() {
		return parts.stream().map(p -> p.toString()).collect(Collectors.joining());
	}

	/**
	 * Turns the LCS match into one or more words that do not match.  This uses the common 
	 * characters to build a mapping of the different words and their offsets into the new word 
	 * originally passed to the WordDiffer.
	 */
	private TreeMap<Integer, String> buildWordOffsets(LcsMatch match) {
		// break each word into parts, splitting on each character

		TreeMap<Integer, String> wordsByOffset = new TreeMap<>();

		StringBuilder buffy = new StringBuilder();
		String word = match.newWord;
		int wordIndex = 0; // index into the overall 'new word' 
		for (char c : match.lcs) {

			for (; wordIndex < word.length(); wordIndex++) {

				char wordChar = word.charAt(wordIndex);
				if (wordChar == c) {
					int offset = (wordIndex) - buffy.length();
					saveWord(buffy, offset, wordsByOffset);
					wordIndex++;
					break;
				}

				buffy.append(wordChar);
			}
		}

		int offset = wordIndex - buffy.length();
		saveWord(buffy, offset, wordsByOffset);

		if (wordIndex < word.length()) {
			// the LCS ended; get the rest of the original word
			buffy.append(word.substring(wordIndex));
			saveWord(buffy, wordIndex, wordsByOffset);
		}

		return wordsByOffset;
	}

	private void saveWord(StringBuilder buffy, int charPosition,
			TreeMap<Integer, String> wordIndices) {
		if (buffy.length() > 0) {
			wordIndices.put(charPosition, buffy.toString());
			buffy.setLength(0);
		}
	}

	private LcsMatch getLcs(String x, String y) {
		StringReducingLcs lcs = new StringReducingLcs(x, y);
		List<Character> lcsList = lcs.getLcs();
		if (lcsList.isEmpty()) {
			return null;
		}
		if (lcsList.size() < 3) {
			return null; // what is the min size?
		}

		LcsMatch match = new LcsMatch(x, y, lcsList);
		return match;
	}

	private List<WordPart> createWordParts(String newWord, TreeMap<Integer, String> wordIndices) {

		List<WordPart> results = new ArrayList<>();

		int lastWrittenIndex = 0;
		Set<Entry<Integer, String>> entrySet = wordIndices.entrySet();
		for (Entry<Integer, String> entry : entrySet) {
			Integer index = entry.getKey();

			if (lastWrittenIndex < index) {
				String text = newWord.substring(lastWrittenIndex, index);
				results.add(new SamePart(text, lastWrittenIndex));
			}

			String word = entry.getValue();
			results.add(new DifferentPart(word, index));
			lastWrittenIndex = index + word.length();

		}

		if (lastWrittenIndex < newWord.length()) {
			String text = newWord.substring(lastWrittenIndex);
			results.add(new SamePart(text, lastWrittenIndex));
		}
		return results;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	/**
	 * A String that is part of a larger String.  This class also has the offset into the original
	 * String.
	 */
	public abstract class WordPart {
		protected String text;
		protected int index;

		WordPart(String text, int index) {
			this.text = text;
			this.index = index;
		}

		public int getIndex() {
			return index;
		}

		public int length() {
			return text.length();
		}

		public String getText() {
			return text;
		}

		@Override
		public String toString() {
			return text;
		}
	}

	public class SamePart extends WordPart {
		SamePart(String text, int index) {
			super(text, index);
		}
	}

	public class DifferentPart extends WordPart {
		DifferentPart(String text, int index) {
			super(text, index);
		}

		public WordPart merge(WordPart oldPart, WordPart nextPart) {
			if (!(nextPart instanceof DifferentPart)) {
				return null;
			}

			String updatedText = text + oldPart.text + nextPart.text;
			return new DifferentPart(updatedText, index);
		}

		@Override
		public String toString() {
			return " /" + text + "/ ";
		}
	}

	private record LcsMatch(String newWord, String oldWord, List<Character> lcs) {}
}
