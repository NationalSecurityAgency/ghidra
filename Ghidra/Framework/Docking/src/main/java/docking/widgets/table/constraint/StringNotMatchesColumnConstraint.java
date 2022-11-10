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

import ghidra.util.UserSearchUtils;

/**
 * String column constraint for matching column values if they do not match a full regular
 * expression pattern.
 */
public class StringNotMatchesColumnConstraint extends StringMatchesColumnConstraint {

	/**
	 * Constructor
	 *
	 * <P> This class is for users to enter true regular expression which is why it creates
	 * a pattern directly without using the {@link UserSearchUtils}
	 *
	 * @param spec the string to use to create a "matcher" pattern.
	 */
	public StringNotMatchesColumnConstraint(String spec) {
		super(spec);
	}

	@Override
	public String getName() {
		return "Does Not Match Regex";
	}

	@Override
	public String getGroup() {
		return "z string";
	}

	@Override
	public ColumnConstraint<String> copy(String newPatternString) {
		return new StringNotMatchesColumnConstraint(newPatternString);
	}

	@Override
	public boolean accepts(String value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return !matchesPattern.matcher(value).matches();
	}
}
