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
package ghidra.util.datastruct;

import java.util.*;

public class SynchronizedListAccumulator<T> implements Accumulator<T> {

	private List<T> list;

	public SynchronizedListAccumulator() {
		this.list = new ArrayList<T>();
	}

	public SynchronizedListAccumulator(List<T> list) {
		this.list = new ArrayList<T>(list);
	}

	@Override
	public synchronized void add(T t) {
		list.add(t);
	}

	@Override
	public synchronized void addAll(Collection<T> collection) {
		list.addAll(collection);
	}

	@Override
	public synchronized boolean contains(T t) {
		return list.contains(t);
	}

	@Override
	public synchronized Collection<T> get() {
		return new ArrayList<T>(list);
	}

	public synchronized List<T> asList() {
		return new ArrayList<T>(list);
	}

	@Override
	public synchronized int size() {
		return list.size();
	}

	@Override
	public synchronized Iterator<T> iterator() {
		return asList().iterator();
	}

	@Override
	public synchronized String toString() {
		return list.toString();
	}
}
