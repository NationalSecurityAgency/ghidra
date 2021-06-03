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

import ghidra.util.UserSearchUtils;

/**
 * String column constraint for matching column values if they end with the constraint value pattern.
 */
public class StringEndsWithColumnConstraint extends StringColumnConstraint {

	/**
	 * Constructor
	 * @param patternString the string to use to create an "ends with" pattern.
	 */
	public StringEndsWithColumnConstraint(String patternString) {
		super(patternString);
	}

	@Override
	public String getName() {
		return "Ends With";
	}

	@Override
	public ColumnConstraint<String> copy(String newPatternString) {
		return new StringEndsWithColumnConstraint(newPatternString);
	}

	@Override
	protected Pattern generateMatchesPattern(String patternString) {
		return UserSearchUtils.createEndsWithPattern(patternString, true,
			Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
	}
}
