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

/**
 * An object that represents and add, remove or change operation for one row of a table
 *
 * @param <T> the row type
 */
public class AddRemoveListItem<T> {

	public enum Type {
		ADD,
		REMOVE,
		CHANGE
	}

	private T value;
	private Type type;

	public AddRemoveListItem(Type type, T value) {
		this.type = type;
		this.value = value;
	}

	public boolean isAdd() {
		return type == Type.ADD;
	}

	public boolean isRemove() {
		return type == Type.REMOVE;
	}

	public boolean isChange() {
		return type == Type.CHANGE;
	}

	public Type getType() {
		return type;
	}

	public T getValue() {
		return value;
	}

	@Override
	public String toString() {

		//@formatter:off
		return "{\n" + 
			"\tvalue: " + value +",\n" +
			"\ttype: " + type +",\n" +
		"}";
		//@formatter:on
	}
}
