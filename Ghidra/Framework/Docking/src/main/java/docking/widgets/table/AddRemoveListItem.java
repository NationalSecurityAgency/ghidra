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
package docking.widgets.table;

public class AddRemoveListItem<T> {
	private boolean isAdd;
	private boolean isRemove;
	private T value;

	public AddRemoveListItem(boolean isAdd, boolean isRemove, T value) {
		this.isAdd = isAdd;
		this.isRemove = isRemove;
		this.value = value;
	}

	public boolean isAdd() {
		return isAdd;
	}

	public boolean isRemove() {
		return isRemove;
	}

	public boolean isChange() {
		return isAdd && isRemove;
	}

	public T getValue() {
		return value;
	}

	@Override
	public String toString() {

		//@formatter:off
		return "{\n" + 
			"\tvalue: " + value +",\n" +
			"\tisAdd: " + isAdd +",\n" +
			"\tisRemove: " + isRemove +"\n" +
		"}";
		//@formatter:on
	}
}
