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
package ghidra.app.plugin.core.debug.stack;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.Combinable;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.CustomStackUnwindWarning;

/**
 * A bucket of warnings
 * 
 * <p>
 * This collects stack unwind warnings and then culls, and combines them for display.
 */
public class StackUnwindWarningSet implements Collection<StackUnwindWarning> {
	private final Collection<StackUnwindWarning> warnings = new LinkedHashSet<>();

	public static StackUnwindWarningSet custom(String message) {
		StackUnwindWarningSet set = new StackUnwindWarningSet();
		set.add(new CustomStackUnwindWarning(message));
		return set;
	}

	/**
	 * Create a new empty set
	 */
	public StackUnwindWarningSet() {
	}

	/**
	 * Create a new set with the given initial warnings
	 * 
	 * @param warnings the warnings
	 */
	public StackUnwindWarningSet(StackUnwindWarning... warnings) {
		this.warnings.addAll(Arrays.asList(warnings));
	}

	/**
	 * Copy the given set
	 * 
	 * @param warnings the other set
	 */
	public StackUnwindWarningSet(Collection<StackUnwindWarning> warnings) {
		this.warnings.addAll(warnings);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof StackUnwindWarningSet that)) {
			return false;
		}
		return this.warnings.equals(that.warnings);
	}

	@Override
	public int size() {
		return warnings.size();
	}

	@Override
	public boolean isEmpty() {
		return warnings.isEmpty();
	}

	@Override
	public boolean contains(Object o) {
		return warnings.contains(o);
	}

	@Override
	public Iterator<StackUnwindWarning> iterator() {
		return warnings.iterator();
	}

	@Override
	public Object[] toArray() {
		return warnings.toArray();
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return warnings.toArray(a);
	}

	@Override
	public boolean add(StackUnwindWarning e) {
		return warnings.add(e);
	}

	@Override
	public boolean remove(Object o) {
		return warnings.remove(o);
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return warnings.containsAll(c);
	}

	@Override
	public boolean addAll(Collection<? extends StackUnwindWarning> c) {
		return warnings.addAll(c);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return warnings.removeAll(c);
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return warnings.retainAll(c);
	}

	@Override
	public void clear() {
		warnings.clear();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public List<String> summarize() {
		Set<Class<? extends StackUnwindWarning>> combined = new LinkedHashSet<>();
		List<String> lines = new ArrayList<>();
		for (StackUnwindWarning w : warnings) {
			if (warnings.stream().anyMatch(mw -> mw.moots(w))) {
				// do nothing
			}
			else if (w instanceof Combinable c) {
				Class<? extends StackUnwindWarning> cls = w.getClass();
				if (!combined.add(cls)) {
					continue;
				}
				Collection all =
					warnings.stream().filter(cw -> cls.isInstance(cw)).collect(Collectors.toList());
				if (all.size() == 1) {
					lines.add(w.getMessage());
				}
				else {
					lines.add(c.summarize(all));
				}
			}
			else {
				lines.add(w.getMessage());
			}
		}
		return lines;
	}

	public void reportDetails() {
		for (StackUnwindWarning w : warnings) {
			w.reportDetails();
		}
	}
}
