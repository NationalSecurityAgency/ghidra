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

import org.apache.commons.collections4.list.AbstractListDecorator;

import ghidra.dbg.util.CollectionUtils.AbstractEmptyList;

public interface TargetStringList extends List<String> {
	public static class EmptyTargetStringList extends AbstractEmptyList<String>
			implements TargetStringList {
	}

	public static class ImmutableTargetStringList extends AbstractListDecorator<String>
			implements TargetStringList {
		public ImmutableTargetStringList(String... strings) {
			super(List.of(strings));
		}

		public ImmutableTargetStringList(Collection<String> col) {
			super(List.copyOf(col));
		}
	}

	public static class MutableTargetStringList extends ArrayList<String>
			implements TargetStringList {
	}

	public static final TargetStringList EMPTY = new EmptyTargetStringList();

	public static TargetStringList of() {
		return EMPTY;
	}

	public static TargetStringList of(String... strings) {
		return new ImmutableTargetStringList(strings);
	}

	public static TargetStringList copyOf(Collection<String> strings) {
		return new ImmutableTargetStringList(strings);
	}
}
