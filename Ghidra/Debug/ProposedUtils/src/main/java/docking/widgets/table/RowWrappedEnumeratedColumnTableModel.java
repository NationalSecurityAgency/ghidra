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

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;

public class RowWrappedEnumeratedColumnTableModel<C extends Enum<C> & EnumeratedTableColumn<C, R>, R, T>
		extends DefaultEnumeratedColumnTableModel<C, R> {
	private final Function<T, R> wrapper;
	private final Map<T, R> map = new HashMap<>();

	public RowWrappedEnumeratedColumnTableModel(String name, Class<C> colType,
			Function<T, R> wrapper) {
		super(name, colType);
		this.wrapper = wrapper;
	}

	protected synchronized R rowFor(T t) {
		return map.computeIfAbsent(t, wrapper);
	}

	protected synchronized R delFor(T t) {
		return map.remove(t);
	}

	protected synchronized List<R> rowsFor(Collection<? extends T> c) {
		return c.stream().map(this::rowFor).collect(Collectors.toList());
	}

	public void addItem(T t) {
		add(rowFor(t));
	}

	public void addAllItems(Collection<? extends T> c) {
		addAll(rowsFor(c));
	}

	public void updateItem(T t) {
		notifyUpdated(rowFor(t));
	}

	public void updateAllItems(Collection<T> c) {
		notifyUpdatedWith(rowsFor(c)::contains);
	}

	public void deleteItem(T t) {
		delete(delFor(t));
	}

	public synchronized void deleteAllItems(Collection<T> c) {
		deleteWith(rowsFor(c)::contains);
		map.keySet().removeAll(c);
	}

	public synchronized Map<T, R> getMap() {
		return Map.copyOf(map);
	}
}
