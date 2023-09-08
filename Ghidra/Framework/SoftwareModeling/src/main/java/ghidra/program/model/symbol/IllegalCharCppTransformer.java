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
package ghidra.program.model.symbol;

/**
 * Replace illegal characters in the given name with '_'.  The transformer treats the name as a
 * C++ symbol. Letters and digits are generally legal. '~' is allowed at the start of the symbol.
 * Template parameters, surrounded by '&lt;' and '&gt;', allow additional special characters. 
 * Certain special characters are allowed after the keyword "operator".
 */
public class IllegalCharCppTransformer implements NameTransformer {

	private static int[] legalChars = null;
	private static final int AFTER_FIRST_CHAR = 1;	// Legal after the first character
	private static final int TEMPLATE = 2;			// Legal as part of template parameters
	private static final int OPERATOR = 4;			// Legal after the "operator" keyword
	private static final int FIRST_CHAR = 8;		// Legal as the first character

	public IllegalCharCppTransformer() {
		if (legalChars == null) {
			legalChars = new int[128];
			for (int i = 0; i < legalChars.length; ++i) {
				legalChars[i] = 0;
			}
			legalChars['_'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR | FIRST_CHAR;
			legalChars['0'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['1'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['2'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['3'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['4'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['5'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['6'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['7'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['8'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['9'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
			legalChars['*'] = TEMPLATE | OPERATOR;
			legalChars[':'] = TEMPLATE;
			legalChars['('] = TEMPLATE | OPERATOR;
			legalChars[')'] = TEMPLATE | OPERATOR;
			legalChars['['] = TEMPLATE | OPERATOR;
			legalChars[']'] = TEMPLATE | OPERATOR;
			legalChars[','] = TEMPLATE;
			legalChars['&'] = TEMPLATE | OPERATOR;
			legalChars['+'] = OPERATOR;
			legalChars['-'] = OPERATOR;
			legalChars['|'] = OPERATOR;
			legalChars['='] = OPERATOR;
			legalChars['!'] = OPERATOR;
			legalChars['/'] = OPERATOR;
			legalChars['%'] = OPERATOR;
			legalChars['^'] = OPERATOR;
			legalChars['~'] = TEMPLATE | OPERATOR | FIRST_CHAR;
		}
	}

	@Override
	public String simplify(String input) {
		int templateDepth = 0;
		char[] transform = null;
		for (int i = 0; i < input.length(); ++i) {
			char c = input.charAt(i);
			if (Character.isLetter(c)) {
				continue;
			}
			else if (c == '<') {
				templateDepth += 1;
				continue;
			}
			else if (c == '>') {
				templateDepth -= 1;
				if (templateDepth < 0) {
					templateDepth = 0;
				}
				continue;
			}
			else if (c < 128) {
				int val = legalChars[c];
				if (val != 0) {
					if (((val & AFTER_FIRST_CHAR) != 0) && i > 0) {
						continue;		// Legal after first character
					}
					if (((val & FIRST_CHAR) != 0) && i == 0) {
						continue;		// Legal as first character
					}
					if (((val & TEMPLATE) != 0) && templateDepth > 0) {
						continue;		// Legal as template parameter
					}
					if (((val & OPERATOR) != 0) && i >= 8 && i <= 10) {
						if (input.startsWith("operator")) {
							continue;
						}
					}
				}
			}
			// If we reach here, the character is deemed illegal
			if (transform == null) {
				transform = new char[input.length()];
				input.getChars(0, input.length(), transform, 0);
			}
			transform[i] = '_';
		}
		if (transform == null) {
			return input;
		}
		return new String(transform);
	}

}
