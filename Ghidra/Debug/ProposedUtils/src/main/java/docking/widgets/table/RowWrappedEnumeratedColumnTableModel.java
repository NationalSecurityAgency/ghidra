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
import java.util.stream.Stream;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.util.Msg;

/**
 * A table model where the columns are enumerated, and the rows are wrappers on the objects being
 * displayed
 * 
 * @param <C> the type of columns
 * @param <K> the type of (immutable) keys for uniquely identifying an object
 * @param <R> the type of rows
 * @param <T> the type of objects being wrapped
 */
public class RowWrappedEnumeratedColumnTableModel<C extends Enum<C> & EnumeratedTableColumn<C, R>, K, R, T>
		extends DefaultEnumeratedColumnTableModel<C, R> {
	private final Function<T, K> keyFunc;
	private final Function<T, R> wrapper;
	private final Map<K, R> map = new HashMap<>();

	public RowWrappedEnumeratedColumnTableModel(String name, Class<C> colType,
			Function<T, K> keyFunc, Function<T, R> wrapper) {
		super(name, colType);
		this.keyFunc = keyFunc;
		this.wrapper = wrapper;
	}

	protected synchronized R addRowFor(T t) {
		R row = wrapper.apply(t);
		R exists = map.put(keyFunc.apply(t), row);
		if (exists != null) {
			Msg.warn(this, "Replaced existing row! row=" + exists);
		}
		return row;
	}

	protected synchronized R delRowFor(T t) {
		return delKey(keyFunc.apply(t));
	}

	protected synchronized R delKey(K k) {
		return map.remove(k);
	}

	protected synchronized List<R> addRowsFor(Stream<? extends T> s) {
		return s.map(this::addRowFor).collect(Collectors.toList());
	}

	protected synchronized List<R> addRowsFor(Collection<? extends T> c) {
		return addRowsFor(c.stream());
	}

	public synchronized R getRow(T t) {
		return map.get(keyFunc.apply(t));
	}

	protected synchronized List<R> getRows(Stream<? extends T> s) {
		return s.map(this::getRow).filter(r -> r != null).collect(Collectors.toList());
	}

	protected synchronized List<R> getRows(Collection<? extends T> c) {
		return getRows(c.stream());
	}

	public synchronized void addItem(T t) {
		if (map.containsKey(keyFunc.apply(t))) {
			return;
		}
		add(addRowFor(t));
	}

	public synchronized void addAllItems(Collection<? extends T> c) {
		Stream<? extends T> s = c.stream().filter(t -> {
			K k = keyFunc.apply(t);
			if (map.containsKey(k)) {
				return false;
			}
			return true;
		});
		addAll(addRowsFor(s));
	}

	public void updateItem(T t) {
		R row = getRow(t);
		if (row == null) {
			return;
		}
		notifyUpdated(row);
	}

	public void updateAllItems(Collection<T> c) {
		notifyUpdatedWith(getRows(c)::contains);
	}

	public void deleteItem(T t) {
		R row = delRowFor(t);
		if (row == null) {
			return;
		}
		delete(row);
	}

	public R deleteKey(K k) {
		R r = delKey(k);
		if (r == null) {
			return null;
		}
		delete(r);
		return r;
	}

	public synchronized void deleteAllItems(Collection<T> c) {
		deleteWith(getRows(c)::contains);
		map.keySet().removeAll(c.stream().map(keyFunc).collect(Collectors.toList()));
	}

	public synchronized Map<K, R> getMap() {
		return Map.copyOf(map);
	}

	@Override
	public synchronized void clear() {
		map.clear();
		super.clear();
	}
}
