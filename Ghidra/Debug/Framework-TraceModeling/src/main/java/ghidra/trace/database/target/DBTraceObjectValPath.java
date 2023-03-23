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
package ghidra.trace.database.target;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.trace.model.target.*;

public class DBTraceObjectValPath implements TraceObjectValPath {
	public static final DBTraceObjectValPath EMPTY = new DBTraceObjectValPath(List.of());

	public static DBTraceObjectValPath of() {
		return EMPTY;
	}

	public static DBTraceObjectValPath of(Collection<InternalTraceObjectValue> entryList) {
		return new DBTraceObjectValPath(List.copyOf(entryList));
	}

	public static DBTraceObjectValPath of(InternalTraceObjectValue... entries) {
		return DBTraceObjectValPath.of(Arrays.asList(entries));
	}

	private final List<InternalTraceObjectValue> entryList;
	private List<String> keyList; // lazily computed

	private DBTraceObjectValPath(List<InternalTraceObjectValue> entryList) {
		this.entryList = entryList;
	}

	@Override
	public int compareTo(TraceObjectValPath o) {
		return PathComparator.KEYED.compare(getKeyList(), o.getKeyList());
	}

	@Override
	public List<? extends InternalTraceObjectValue> getEntryList() {
		return entryList;
	}

	protected List<String> computeKeyList() {
		return entryList.stream()
				.map(e -> e.getEntryKey())
				.collect(Collectors.toUnmodifiableList());
	}

	@Override
	public List<String> getKeyList() {
		if (keyList == null) {
			keyList = computeKeyList();
		}
		return keyList;
	}

	@Override
	public boolean contains(TraceObjectValue entry) {
		return entryList.contains(entry);
	}

	@Override
	public DBTraceObjectValPath prepend(TraceObjectValue entry) {
		InternalTraceObjectValue[] arr = new InternalTraceObjectValue[1 + entryList.size()];
		arr[0] = (DBTraceObjectValue) entry;
		for (int i = 1; i < arr.length; i++) {
			arr[i] = entryList.get(i - 1);
		}
		return new DBTraceObjectValPath(Collections.unmodifiableList(Arrays.asList(arr)));
	}

	public DBTraceObjectValPath append(TraceObjectValue entry) {
		InternalTraceObjectValue[] arr = new InternalTraceObjectValue[1 + entryList.size()];
		for (int i = 0; i < arr.length - 1; i++) {
			arr[i] = entryList.get(i);
		}
		arr[arr.length - 1] = (InternalTraceObjectValue) entry;
		return new DBTraceObjectValPath(Collections.unmodifiableList(Arrays.asList(arr)));
	}

	@Override
	public InternalTraceObjectValue getFirstEntry() {
		if (entryList.isEmpty()) {
			return null;
		}
		return entryList.get(0);
	}

	@Override
	public TraceObject getSource(TraceObject ifEmpty) {
		InternalTraceObjectValue first = getFirstEntry();
		return first == null ? ifEmpty : first.getParent();
	}

	@Override
	public InternalTraceObjectValue getLastEntry() {
		if (entryList.isEmpty()) {
			return null;
		}
		return entryList.get(entryList.size() - 1);
	}

	@Override
	public Object getDestinationValue(Object ifEmpty) {
		InternalTraceObjectValue last = getLastEntry();
		return last == null ? ifEmpty : last.getValue();
	}

	@Override
	public TraceObject getDestination(TraceObject ifEmpty) {
		InternalTraceObjectValue last = getLastEntry();
		return last == null ? ifEmpty : last.getChild();
	}
}
