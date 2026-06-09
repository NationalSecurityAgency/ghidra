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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.Objects;

import generic.json.Json;
import ghidra.framework.options.SaveState;

/**
 * A class that holds enabled state for a type and related typedefs.
 */
public class DtTypeFilter {

	private static final String IS_TYPE_ACTIVE_KEY = "IS_TYPE_ACTIVE";
	private static final String IS_TYPE_DEF_ACTIVE_KEY = "IS_TYPE_DEF_ACTIVE";

	private String name;
	private boolean isTypeActive = true;
	private boolean isTypeDefActive = true;

	static DtTypeFilter restore(String typeName, SaveState ss) {
		if (ss == null) {
			return new DtTypeFilter(typeName);
		}
		return new DtTypeFilter(ss);
	}

	DtTypeFilter(String name) {
		this.name = name;
	}

	private DtTypeFilter(SaveState ss) {
		name = ss.getName();
		isTypeActive = ss.getBoolean(IS_TYPE_ACTIVE_KEY, true);
		isTypeDefActive = ss.getBoolean(IS_TYPE_DEF_ACTIVE_KEY, true);
	}

	SaveState save() {
		SaveState ss = new SaveState(name);
		ss.putBoolean(IS_TYPE_ACTIVE_KEY, isTypeActive);
		ss.putBoolean(IS_TYPE_DEF_ACTIVE_KEY, isTypeDefActive);
		return ss;
	}

	DtTypeFilter copy() {
		DtTypeFilter filter = new DtTypeFilter(name);
		filter.isTypeActive = isTypeActive;
		filter.isTypeDefActive = isTypeDefActive;
		return filter;
	}

	public String getName() {
		return name;
	}

	public boolean isTypeActive() {
		return isTypeActive;
	}

	public boolean isTypeDefActive() {
		return isTypeDefActive;
	}

	public void setTypeActive(boolean b) {
		this.isTypeActive = b;
	}

	public void setTypeDefActive(boolean b) {
		this.isTypeDefActive = b;
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}

	@Override
	public int hashCode() {
		return Objects.hash(isTypeActive, isTypeDefActive, name);
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
		DtTypeFilter other = (DtTypeFilter) obj;
		return isTypeActive == other.isTypeActive && isTypeDefActive == other.isTypeDefActive &&
			Objects.equals(name, other.name);
	}
}
