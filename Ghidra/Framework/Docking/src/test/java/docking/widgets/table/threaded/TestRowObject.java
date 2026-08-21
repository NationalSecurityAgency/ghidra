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
package docking.widgets.table.threaded;

import java.util.Objects;

public class TestRowObject {

	private String s;
	private long l;

	TestRowObject(String s, long l) {
		this.s = s;
		this.l = l;
	}

	public String getStringValue() {
		return s;
	}

	public long getLongValue() {
		return l;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[string=" + s + ", long=" + l + "]";
	}

	@Override
	public int hashCode() {
		return Objects.hash(l, s);
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
		TestRowObject other = (TestRowObject) obj;
		return l == other.l && Objects.equals(s, other.s);
	}
}
