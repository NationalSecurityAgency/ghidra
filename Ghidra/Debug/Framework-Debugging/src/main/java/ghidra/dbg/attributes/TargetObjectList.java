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

import ghidra.dbg.target.TargetObject;

public interface TargetObjectList<T extends TargetObject> extends List<T> {
	public static class EmptyTargetObjectRefList<T extends TargetObject> extends AbstractList<T>
			implements TargetObjectList<T> {
		@Override
		public T get(int index) {
			return null;
		}

		@Override
		public int size() {
			return 0;
		}
	}

	public static class DefaultTargetObjectList<T extends TargetObject> extends ArrayList<T>
			implements TargetObjectList<T> {
		// Nothing to add
	}

	public static final TargetObjectList<?> EMPTY = new EmptyTargetObjectRefList<>();

	@SuppressWarnings("unchecked")
	public static <T extends TargetObject> TargetObjectList<T> of() {
		return (TargetObjectList<T>) EMPTY;
	}

	@SuppressWarnings("unchecked")
	public static <T extends TargetObject> TargetObjectList<T> of(T... e) {
		DefaultTargetObjectList<T> list = new DefaultTargetObjectList<>();
		list.addAll(List.of(e));
		return list;
	}
}
