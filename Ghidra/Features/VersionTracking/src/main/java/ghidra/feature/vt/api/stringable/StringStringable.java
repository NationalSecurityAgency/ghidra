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
package ghidra.feature.vt.api.stringable;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;

public class StringStringable extends Stringable {

	public static final String SHORT_NAME = "STR";

	private static final String EMPTY_STRING = "";
	private String value;

	public StringStringable() {
		this(null);
	}

	public StringStringable(String string) {
		super(SHORT_NAME);
		this.value = string;
	}

	public String getString() {
		return value;
	}

	@Override
	public String getDisplayString() {
		return (value != null) ? value : EMPTY_STRING;
	}

	@Override
	protected String doConvertToString(Program program) {
		if (value == null) {
			return EMPTY_STRING;
		}
		return value;
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		if (EMPTY_STRING.equals(string)) {
			this.value = null;
			return;
		}
		this.value = string;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((value == null) ? 0 : value.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		StringStringable other = (StringStringable) obj;

		return SystemUtilities.isEqual(value, other.value);
	}
}
