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
package ghidra.app.plugin.core.functionwindow;

import ghidra.program.model.listing.Function;

public class FunctionRowObject implements Comparable<FunctionRowObject> {

	private final Function function;

	public FunctionRowObject(Function function) {
		this.function = function;
	}

	public Function getFunction() {
		return function;
	}

	@Override
	public int hashCode() {
		return (int) function.getID();
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

		long key = function.getID();
		FunctionRowObject other = (FunctionRowObject) obj;
		if (key != other.function.getID()) {
			return false;
		}
		return true;
	}

	public long getKey() {
		return function.getID();
	}

	@Override
	public int compareTo(FunctionRowObject o) {
		return ((Long) function.getID()).compareTo(o.function.getID());
	}
}
