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
package docking.widgets.filter;

import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.StringUtilities;

/**
 * Allows the user to split a string using a regex as the delimiter.
 */
public abstract class AbstractRegexBasedTermSplitter implements TermSplitter {

	private final Pattern pattern;

	private static final String[] EMPTY = new String[0];

	private static String generatePattern(String delim) {
		/*
		 * Split on the delimiter only if that delimiter has zero, or an
		 *  even number of quotes ahead of it.
		 */

		return "\\s*" + Pattern.quote(delim) + "\\s*(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)";
	}

	public AbstractRegexBasedTermSplitter(String delimiter) {
		this.pattern = Pattern.compile(generatePattern(delimiter));
	}

	@Override
	public String[] split(String input) {

		if (StringUtils.isBlank(input)) {
			return EMPTY;
		}

		String[] terms = pattern.split(input);

		for (int i = 0; i < terms.length; i++) {
			terms[i] = StringUtilities.extractFromDoubleQuotes(terms[i]);
		}

		return terms;

	}
}
