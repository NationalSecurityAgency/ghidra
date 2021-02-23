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
package ghidra.dbg.target;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;

public class TargetObjectPath implements Comparable<TargetObjectPath> {
	protected final DebuggerObjectModel model;
	protected final List<String> keyList;
	protected final int hash;

	public TargetObjectPath(DebuggerObjectModel model, List<String> keyList) {
		this.model = model;
		this.keyList = keyList;
		this.hash = Objects.hash(model, keyList);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TargetObjectPath)) {
			return false;
		}
		TargetObjectPath that = (TargetObjectPath) obj;
		return this.getModel() == that.getModel() &&
			Objects.equals(this.getKeyList(), that.getKeyList());
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(TargetObjectPath that) {
		if (this == that) {
			return 0;
		}
		DebuggerObjectModel thisModel = this.getModel();
		DebuggerObjectModel thatModel = that.getModel();
		if (thisModel != thatModel) {
			if (thisModel == null) {
				return -1;
			}
			if (thatModel == null) {
				return 1;
			}
			int result = thisModel.toString().compareTo(thatModel.toString());
			if (result == 0) {
				return Integer.compare(
					System.identityHashCode(thisModel),
					System.identityHashCode(thatModel));
			}
			return result;
		}
		return PathComparator.KEYED.compare(this.getKeyList(), that.getKeyList());
	}

	@Override
	public String toString() {
		return String.format("<%s in %s>", toPathString(), model);
	}

	public DebuggerObjectModel getModel() {
		return model;
	}

	public List<String> getKeyList() {
		return keyList;
	}

	public String name() {
		return PathUtils.getKey(keyList);
	}

	public String index() {
		return PathUtils.getIndex(keyList);
	}

	public boolean isRoot() {
		return keyList.isEmpty();
	}

	public CompletableFuture<TargetObject> fetch() {
		return model.fetchModelObject(getKeyList()).thenApply(obj -> obj);
	}

	public String toPathString() {
		return PathUtils.toString(keyList);
	}

	public TargetObjectPath parent() {
		List<String> pkl = PathUtils.parent(keyList);
		return pkl == null ? null : new TargetObjectPath(model, pkl);
	}

	public TargetObjectPath successor(List<String> subKeyList) {
		return new TargetObjectPath(model, PathUtils.extend(keyList, subKeyList));
	}

	public TargetObjectPath successor(String... subKeyList) {
		return successor(Arrays.asList(subKeyList));
	}
}
