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
package ghidra.app.plugin.core.string;

import java.util.Objects;

import ghidra.util.Msg;

/**
 * Storage class for Strings identified by the String Searcher and their associated
 * ngram scores.  The scores, combined with the score thresholds, determine if this 
 * string passes or fails.
 */
public class StringAndScores {

	private String originalString = "", scoredString = "";
	private int[] asciiCodesForString;
	private volatile double ngramScore, scoreThreshold;

	public StringAndScores(String str, boolean isLowerCaseModel) {

		originalString = Objects.requireNonNull(str);
		scoredString = isLowerCaseModel ? originalString.toLowerCase() : originalString;

		normalizeAndStoreAsciiCodes();

		ngramScore = -100d;

		// If score threshold is not set by the code that instantiates the object,
		// the string will never pass the threshold test.
		scoreThreshold = 10d;
	}

	private void normalizeAndStoreAsciiCodes() {

		String intermediateString;

		// Check if all characters are ASCII
		if (scoredString.matches("^\\p{ASCII}*$")) {
			intermediateString = scoredString;
		}
		else {
			intermediateString = replaceInvalidAscii(scoredString);
		}

		scoredString = normalizeSpaces(intermediateString);
		translateToAsciiCodes();
	}

	private String replaceInvalidAscii(String string) {

		char[] stringChars = scoredString.toCharArray();
		char[] asciiStringChars = new char[stringChars.length];

		StringBuilder bad = new StringBuilder();
		for (int i = 0; i < stringChars.length; i++) {
			char currentChar = stringChars[i];

			// If character is not ASCII, replace with space
			if ((currentChar >= 0) && (currentChar <= 127)) {
				asciiStringChars[i] = stringChars[i];
			}
			else {
				bad.append(Character.digit(stringChars[i], 10)).append(' ');
				asciiStringChars[i] = ' ';
			}
		}

		Msg.debug(this, "Warning: found non-ASCII character(s) while analyzing '" + scoredString +
			"' --replacing with space characters during analysis.  Char values: " + bad);

		return new String(asciiStringChars);
	}

	private void translateToAsciiCodes() {

		char[] strChars = scoredString.toCharArray();
		asciiCodesForString = new int[strChars.length];

		for (int i = 0; i < strChars.length; i++) {
			asciiCodesForString[i] = strChars[i];
		}
	}

	private String normalizeSpaces(String str) {
		// Remove leading and trailing spaces
		String newStr = str;
		newStr = newStr.trim();

		// Collapse consecutive spaces into 1 space
		newStr = newStr.replaceAll(" {2,}", " ");

		// Collapse consecutive tabs into 1 tab
		newStr = newStr.replaceAll("\t{2,}", "\t");

		return newStr;
	}

	public void setNgramScore(double ngSc) {
		ngramScore = ngSc;
	}

	public void setScoreThreshold(double thresh) {
		scoreThreshold = thresh;
	}

	public String getOriginalString() {
		return originalString;
	}

	public String getScoredString() {
		return scoredString;
	}

	public double getNgramScore() {
		return ngramScore;
	}

	public double getScoreThreshold() {
		return scoreThreshold;
	}

	public int getScoredStringLength() {
		return asciiCodesForString.length;
	}

	public int[] getAsciiCodes() {
		return asciiCodesForString;
	}

	public boolean isScoreAboveThreshold() {
		return ngramScore > scoreThreshold;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof StringAndScores) {
			StringAndScores other = (StringAndScores) obj;
			return getOriginalString().equals(other.getOriginalString());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return originalString.hashCode();
	}

	@Override
	public String toString() {

		String outStr =
			"OrigString =" + originalString + ",ScoredString =" + scoredString + ",ASCII =";

		for (int code : asciiCodesForString) {
			outStr += code + " ";
		}

		outStr += ",ngScore =" + ngramScore + ", threshold = " + scoreThreshold;

		return outStr;
	}

	public String summaryToString() {
		return ngramScore + "\t" + originalString;
	}
}
