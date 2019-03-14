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

/**
 * String column constraint for matching column values if they don't end with the constraint value pattern.
 */
public class StringNotEndsWithColumnConstraint extends StringEndsWithColumnConstraint {

	/**
	 * Constructor
	 * @param patternString the string to use to create an "ends with" pattern.
	 */
	public StringNotEndsWithColumnConstraint(String patternString) {
		super(patternString);
	}

	@Override
	public String getName() {
		return "Does Not End With";
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
		return new StringNotEndsWithColumnConstraint(newPatternString);
	}

}
