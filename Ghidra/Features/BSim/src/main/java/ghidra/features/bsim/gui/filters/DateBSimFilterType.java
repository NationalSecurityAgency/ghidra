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
package ghidra.features.bsim.gui.filters;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * An abstract BsimFilterType for filtering on dates.
 */
public abstract class DateBSimFilterType extends BSimFilterType {
	public static final List<DateTimeFormatter> FORMATTERS = Arrays.asList(
		DateTimeFormatter.ofPattern("yyyy MM dd"), DateTimeFormatter.ofPattern("yyyy-MM-dd"),
		DateTimeFormatter.ofPattern("yyyy/MM/dd"), DateTimeFormatter.ofPattern("MMM dd, yyyy"),
		DateTimeFormatter.ofPattern("MMMM dd, yyyy"), DateTimeFormatter.ofPattern("MM dd yyyy"),
		DateTimeFormatter.ofPattern("MM-dd-yyyy"), DateTimeFormatter.ofPattern("MM/dd/yyyy"),
		DateTimeFormatter.ofPattern("yyyy"));

	/**
	 * 
	 * @param label is the display name of this date filter
	 * @param xmlval is the XML serialization name
	 * @param hint is the pop-up hint
	 */
	public DateBSimFilterType(String label, String xmlval, String hint) {
		super(label, xmlval, hint);
	}

	public DateBSimFilterType() {
		super("default label", "", "");
	}

	@Override
	public boolean isValidValue(String value) {
		return formatDate(value) != null;
	}

	@Override
	public String normalizeValue(String value) {
		LocalDate date = formatDate(value);
		return date == null ? null : date.toString();
	}

	/**
	 * Uses the list of {@link DateTimeFormatter} instances created above to test
	 * the given date value. If a formatter can parse the text, a {@link LocalDate}
	 * object is returned.
	 *
	 * @param value is the date string to format
	 * @return the formatted LocalDate or null
	 */
	protected LocalDate formatDate(String value) {
		for (DateTimeFormatter formatter : FORMATTERS) {
			try {
				return LocalDate.parse(value, formatter);
			}
			catch (DateTimeParseException e) {
				// just go back and parse the next one
			}
		}

		return null;
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null;
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return false;
	}

	/**
	 * @return false, since having more than one date filter is logically inconsistent.
	 */
	@Override
	public boolean isMultipleEntryAllowed() {
		return false;
	}

}
