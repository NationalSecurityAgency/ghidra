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
package ghidra.util.datastruct;

import java.util.Map;
import java.util.concurrent.Executor;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;

/**
 * A weak set of multiplexed listeners and an invocation proxy
 *
 * @param <E> the type of multiplexed listeners
 */
public class ListenerSet<E> {
	public static final Executor CALLING_THREAD = ListenerMap.CALLING_THREAD;
	private final ListenerMap<E, E, E> map;

	/**
	 * A proxy which passes invocations to each member of this set
	 */
	public final E fire;

	/**
	 * Construct a new set whose elements and proxy implement the given interface
	 * 
	 * <p>
	 * Callbacks will be serviced by the invoking thread. This may be risking if the invoking thread
	 * is "precious" to the invoker. There is no guarantee callbacks into client code will complete
	 * in a timely fashion.
	 * 
	 * @param iface the interface to multiplex
	 */
	public ListenerSet(Class<E> iface) {
		this(iface, CALLING_THREAD);
	}

	/**
	 * Construct a new set whose elements and proxy implement the given interface
	 * 
	 * @param iface the interface to multiplex
	 * @param executor an executor for servicing callbacks
	 */
	public ListenerSet(Class<E> iface, Executor executor) {
		map = new ListenerMap<E, E, E>(iface, executor) {
			@Override
			protected Map<E, E> createMap() {
				return ListenerSet.this.createMap();
			};
		};
		fire = map.fire;
	}

	@Override
	public String toString() {
		return map.toString();
	}

	protected Map<E, E> createMap() {
		CacheBuilder<E, E> builder = CacheBuilder.newBuilder()
				.removalListener(this::notifyRemoved)
				.weakKeys()
				.weakValues()
				.concurrencyLevel(1);
		return builder.build().asMap();
	}

	protected void notifyRemoved(RemovalNotification<E, E> rn) {
		map.notifyRemoved(rn);
	}

	public <T extends E> T fire(Class<T> ext) {
		return map.fire(ext);
	}

	public boolean isEmpty() {
		return map.isEmpty();
	}

	public boolean add(E e) {
		return map.put(e, e) != e;
	}

	@SuppressWarnings("unchecked")
	public void addAll(ListenerSet<? extends E> c) {
		map.putAll((ListenerMap<? extends E, E, ? extends E>) c.map);
	}

	public boolean remove(E e) {
		return map.remove(e) == e;
	}

	public void clear() {
		map.clear();
	}

	public void addChained(ListenerSet<? extends E> set) {
		map.addChained(set.map);
	}

	public void removeChained(ListenerSet<?> set) {
		map.removeChained(set.map);
	}

	public void clearChained() {
		map.clearChained();
	}
}
