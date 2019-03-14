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

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.table.constrainteditor.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.UserSearchUtils;

/**
 * Base class for various String constraints.
 */
public abstract class StringColumnConstraint implements ColumnConstraint<String> {
	private static int MAX_AUTO_COMPLETE = 30000; // max size for using auto-completing editor  
	private String patternString;
	private Pattern findsPattern;
	private String errorMessage;
	protected Pattern matchesPattern;

	/**
	 * Constructs a new StringColumnConstraint using the given pattern and patternString.
	 *
	 * @param patternString the user entered string to form the pattern used to accept column values.
	 * @param errorMessage the text to display in an empty editor textfield.
	 */
	protected StringColumnConstraint(String patternString, String errorMessage) {
		this.patternString = patternString;
		this.errorMessage = errorMessage;
		this.matchesPattern = generateMatchesPattern(patternString);
		if (this.matchesPattern == null) {
			throw new IllegalArgumentException();
		}
	}

	/**
	 * Constructs a new StringColumnConstraint using the given pattern and patternString, using
	 * the default hint text that explains that you can use globbing characters.
	 *
	 * @param patternString the user entered string to form the pattern used to accept column values.
	 */
	protected StringColumnConstraint(String patternString) {
		this(patternString,
			"Please enter a search pattern. You may use * and ? globbing characters");
	}

	@Override
	public String getGroup() {
		return "string";
	}

	@Override
	public boolean accepts(String value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return matchesPattern.matcher(value).matches();
	}

	protected abstract Pattern generateMatchesPattern(String value);

	protected Pattern generateFindsPattern() {
		String regexString = UserSearchUtils.createPatternString(patternString, true);
		return Pattern.compile("(" + regexString + ")",
			Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
	}

	@Override
	public ColumnConstraintEditor<String> getEditor(ColumnData<String> columnDataSource) {
		if (columnDataSource.getCount() < MAX_AUTO_COMPLETE) {
			return new AutocompletingStringConstraintEditor(this, columnDataSource);
		}
		return new StringConstraintEditor(this, errorMessage);
	}

	/**
	 * subclasses must override to generate new versions of themselves but with a new pattern string.
	 *
	 * @param newPatternString the new string to use for creating the match pattern.
	 * @return a new ColumnConstraint that is the same type as this constraint but with a new range defined.
	 */
	public abstract ColumnConstraint<String> copy(String newPatternString);

	/**
	 * Returns the pattern string for this constraint.
	 *
	 * @return the pattern string for this constraint.
	 */
	public String getPatternString() {
		return patternString;
	}

	@Override
	public Class<String> getColumnType() {
		return String.class;
	}

	@Override
	public String getConstraintValueTooltip() {
		return "\"" + HTMLUtilities.italic(getConstraintValueString()) + "\"";
	}

	@Override
	public String getConstraintValueString() {
		return patternString;
	}

	@Override
	public ColumnConstraint<String> parseConstraintValue(String newValue, Object dataSource) {
		return copy(newValue);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.getClass(), getPatternString());
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if (o == null) {
			return false;
		}

		if (!(getClass().equals(o.getClass()))) {
			return false;
		}

		StringColumnConstraint otherConstraint = (StringColumnConstraint) o;

		return getPatternString().equals(otherConstraint.getPatternString());

	}

	public Matcher getHighlightMatcher(String value) {
		if (findsPattern == null) {
			findsPattern = generateFindsPattern();
		}
		return findsPattern.matcher(value);
	}

	public boolean isValidPatternString(String value) {
		return value.length() > 0;
	}
}
