/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.options;

import java.util.Date;

public class WrappedDate implements WrappedOption {
	private static final String DATE = "date";
	private Date date;

	@Override
	public String toString() {
		return "WrappedDate: " + date;
	}

	public WrappedDate(Date date) {
		this.date = date;
	}

	public WrappedDate() {
		// need default constructor for reflection
	}

	@Override
	public void readState(SaveState saveState) {
		long time = saveState.getLong(DATE, 0);
		date = new Date(time);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putLong(DATE, date.getTime());
	}

	@Override
	public Object getObject() {
		return date;
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.DATE_TYPE;
	}
}
