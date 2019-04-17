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

/**
 * String column constraint for matching column values if they don't contain the constraint value pattern.
 */
public class StringNotContainsColumnConstraint extends StringContainsColumnConstraint {

	/**
	 * Constructor
	 * @param spec the string to use to create a "not contains" pattern.
	 */
	public StringNotContainsColumnConstraint(String spec) {
		super(spec);
	}

	@Override
	public String getName() {
		return "Does Not Contain";
	}

	@Override
	public String getGroup() {
		return "z string";
	}

	@Override
	public boolean accepts(String value, TableFilterContext context) {
		return !super.accepts(value, context);
	}

	@Override
	public ColumnConstraint<String> copy(String newPatternString) {
		return new StringNotContainsColumnConstraint(newPatternString);
	}

	@Override
	protected Pattern generateFindsPattern() {
		return Pattern.compile("(.*)");
	}
}
