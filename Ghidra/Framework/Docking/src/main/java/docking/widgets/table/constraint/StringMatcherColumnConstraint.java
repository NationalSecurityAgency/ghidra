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
package docking.widgets.table.constraint;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * String column constraint for matching column values if they match a full regular expression pattern.
 */
public class StringMatcherColumnConstraint extends StringColumnConstraint {
	/**
	 * Constructor
	 *
	 * <P> This class is for users to enter true regular expression which is why it creates
	 * a pattern directly without using the UserSearchUtils
	 *
	 * @param spec the string to use to create a "matcher" pattern.
	 */
	public StringMatcherColumnConstraint(String spec) {
		super(spec, "Please enter a regular expression.");
	}

	@Override
	public String getName() {
		return "Matches Regex";
	}

	@Override
	public ColumnConstraint<String> copy(String newPatternString) {
		return new StringMatcherColumnConstraint(newPatternString);
	}

	@Override
	protected Pattern generateMatchesPattern(String patternString) {
		return Pattern.compile("^" + patternString.trim() + "$");
	}

	@Override
	public boolean isValidPatternString(String value) {
		if (!super.isValidPatternString(value)) {
			return false;
		}
		try {
			Pattern.compile(value);
			return true;
		}
		catch (PatternSyntaxException e) {
			return false;
		}
	}

	@Override
	protected Pattern generateFindsPattern() {
		return Pattern.compile("(.*)");
	}
}
