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
package ghidra.trace.model.target;

import java.util.*;

import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;

public final class TraceObjectKeyPath implements Comparable<TraceObjectKeyPath> {

	public static TraceObjectKeyPath of(List<String> keyList) {
		return new TraceObjectKeyPath(List.copyOf(keyList));
	}

	public static TraceObjectKeyPath of(String... keys) {
		return new TraceObjectKeyPath(List.of(keys));
	}

	public static TraceObjectKeyPath parse(String path) {
		return new TraceObjectKeyPath(PathUtils.parse(path));
	}

	private final List<String> keyList;
	private final int hash;

	private TraceObjectKeyPath(List<String> keyList) {
		this.keyList = keyList;
		this.hash = Objects.hash(keyList);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(TraceObjectKeyPath that) {
		if (this == that) {
			return 0;
		}
		return PathComparator.KEYED.compare(this.keyList, that.keyList);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TraceObjectKeyPath)) {
			return false;
		}
		TraceObjectKeyPath that = (TraceObjectKeyPath) obj;
		return this.keyList.equals(that.keyList);
	}

	public List<String> getKeyList() {
		return keyList;
	}

	public boolean isRoot() {
		return keyList.isEmpty();
	}

	public TraceObjectKeyPath key(String name) {
		return new TraceObjectKeyPath(PathUtils.extend(keyList, name));
	}

	public String key() {
		return PathUtils.getKey(keyList);
	}

	public TraceObjectKeyPath index(long index) {
		return index(PathUtils.makeIndex(index));
	}

	public TraceObjectKeyPath index(String index) {
		return new TraceObjectKeyPath(PathUtils.index(keyList, index));
	}

	public String index() {
		return PathUtils.getIndex(keyList);
	}

	@Override
	public String toString() {
		return PathUtils.toString(keyList);
	}

	public TraceObjectKeyPath parent() {
		List<String> pkl = PathUtils.parent(keyList);
		return pkl == null ? null : new TraceObjectKeyPath(pkl);
	}

	public TraceObjectKeyPath extend(List<String> subKeyList) {
		return new TraceObjectKeyPath(PathUtils.extend(keyList, subKeyList));
	}

	public TraceObjectKeyPath extend(String... subKeyList) {
		return extend(Arrays.asList(subKeyList));
	}
}
