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
package ghidra.dbg.attributes;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetObject;

public interface TargetObjectRefList<T extends TargetObjectRef> extends List<T> {
	public static class EmptyTargetObjectRefList<T extends TargetObjectRef> extends AbstractList<T>
			implements TargetObjectRefList<T> {
		@Override
		public T get(int index) {
			return null;
		}

		@Override
		public int size() {
			return 0;
		}
	}

	public static class DefaultTargetObjectRefList<T extends TargetObjectRef> extends ArrayList<T>
			implements TargetObjectRefList<T> {
		// Nothing to add
	}

	public static final TargetObjectRefList<?> EMPTY = new EmptyTargetObjectRefList<>();

	@SuppressWarnings("unchecked")
	public static <T extends TargetObjectRef> TargetObjectRefList<T> of() {
		return (TargetObjectRefList<T>) EMPTY;
	}

	@SuppressWarnings("unchecked")
	public static <T extends TargetObjectRef> TargetObjectRefList<T> of(T... e) {
		DefaultTargetObjectRefList<T> list = new DefaultTargetObjectRefList<>();
		list.addAll(List.of(e));
		return list;
	}

	public default CompletableFuture<? extends List<? extends TargetObject>> fetchAll() {
		AsyncFence fence = new AsyncFence();
		TargetObject[] result = new TargetObject[size()];
		for (int i = 0; i < result.length; i++) {
			int j = i;
			fence.include(get(i).fetch().thenAccept(obj -> result[j] = obj));
		}
		return fence.ready().thenApply(__ -> Arrays.asList(result));
	}
}
