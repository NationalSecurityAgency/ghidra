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
package ghidra.dbg.testutil;

import java.util.*;

import org.apache.commons.lang3.reflect.TypeUtils;
import org.apache.commons.lang3.reflect.Typed;

import ghidra.async.AsyncReference;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;

public class ElementTrackingListener<T extends TargetObject> implements DebuggerModelListener {
	public final Class<T> valType;
	public final Map<String, T> elements = new TreeMap<>(TargetObjectKeyComparator.ELEMENT);
	public final AsyncReference<Integer, Void> size = new AsyncReference<>();
	public final Map<String, AsyncReference<T, Void>> waitElems = new HashMap<>();

	public ElementTrackingListener(Class<T> valType) {
		this.valType = valType;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public ElementTrackingListener(Typed<T> valType) {
		this((Class) TypeUtils.getRawType(valType.getType(), null));
	}

	public synchronized AsyncReference<T, Void> refElement(String index) {
		T elem = elements.get(index);
		AsyncReference<T, Void> ref = new AsyncReference<>(elem);
		waitElems.put(index, ref);
		return ref;
	}

	@Override
	public synchronized void elementsChanged(TargetObject parent, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		elements.keySet().removeAll(removed);
		putAll(added);
	}

	public synchronized void putAll(Map<String, ? extends TargetObject> update) {
		for (Map.Entry<String, ? extends TargetObject> ent : update.entrySet()) {
			T val = valType.cast(ent.getValue());
			elements.put(ent.getKey(), val);
			AsyncReference<T, Void> ref = waitElems.get(ent.getKey());
			if (ref != null) {
				ref.set(val, null);
			}
		}
		size.set(elements.size(), null);
	}
}
