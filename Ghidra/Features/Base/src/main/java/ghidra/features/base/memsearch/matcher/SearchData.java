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
package ghidra.features.base.memsearch.matcher;

import java.util.Objects;

import ghidra.features.base.memsearch.gui.SearchSettings;

public class SearchData {
	private final String name;
	private final String input;
	private final SearchSettings settings;

	public SearchData(String name, String input, SearchSettings settings) {
		this.name = name;
		this.input = input == null ? "" : input;
		this.settings = settings;
	}

	public String getName() {
		return name;
	}

	public String getInput() {
		return input;
	}

	public SearchSettings getSettings() {
		return settings;
	}

	@Override
	public String toString() {
		return input;
	}

	@Override
	public int hashCode() {
		return Objects.hash(input, settings);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SearchData other = (SearchData) obj;
		return Objects.equals(input, other.input) && Objects.equals(settings, other.settings);
	}

}
