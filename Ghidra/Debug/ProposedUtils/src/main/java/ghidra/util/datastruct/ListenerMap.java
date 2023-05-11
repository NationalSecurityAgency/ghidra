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

import java.lang.ref.WeakReference;
import java.lang.reflect.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.util.Msg;

/**
 * A map of listeners and a proxy for invoking each
 * 
 * <P>
 * This is effectively a multiplexing primitive for a collection of listeners. The listeners may be
 * indexed by some key other than the listeners themselves. This is often useful if a filter or
 * wrapper is applied. If no wrapper is applied, consider using {@link ListenerSet} instead.
 * Additionally, the map is weak keyed, so that listeners are automatically removed if nothing else
 * maintain a strong reference.
 * 
 * <P>
 * The proxy is accessed via the public {@link #fire} field. This implements the same interfaces as
 * each listener in the collection. Any method invoked on this proxy is invoked upon each listener
 * in the collection. If any invocation results in an unexpected exception, that exception is
 * logged, but otherwise ignored. This protects callbacks from errors introduced by other callbacks.
 * Expected exceptions are those declared in the {@code throws} clause of the invoked method. Such
 * an exception is immediately rethrown, preventing the execution of further callbacks. The default
 * implementation of {@link #createMap()} returns a synchronized map. The return value of any
 * invoked listener is ignored. Every invocation on the proxy returns null. As such, it is advisable
 * to only invoke proxy methods which return {@code void}.
 *
 * @param <K> the type of keys
 * @param <P> the interface of the proxy and multiplexed listeners
 * @param <V> the type of listeners
 */
public class ListenerMap<K, P, V extends P> {
	private static final boolean DEBUG_INCEPTION = false;

	public static class ListenerEntry<V> extends WeakReference<V> {
		final String desc;
		final Throwable inception;

		public ListenerEntry(V referent) {
			super(referent);
			this.desc = referent.toString();
			if (DEBUG_INCEPTION) {
				this.inception = new Throwable();
			}
			else {
				this.inception = null;
			}
		}
	}

	public static final Executor CALLING_THREAD = new Executor() {
		@Override
		public void execute(Runnable command) {
			command.run();
		}
	};

	protected static final AtomicReference<Throwable> firstExc = new AtomicReference<>();

	protected static void reportError(Object listener, Throwable e) {
		if (e instanceof RejectedExecutionException) {
			Msg.trace(listener, "Listener invocation rejected: " + e);
		}
		else {
			Msg.error(listener, "Listener " + listener + " caused unexpected exception", e);
			firstExc.accumulateAndGet(e, (o, n) -> o == null ? n : o);
		}
	}

	/**
	 * Clear the recorded exception.
	 * 
	 * <P>
	 * This method is for testing. If listeners are involved in a test, then this should be called
	 * before that test.
	 * 
	 * @see #checkErr()
	 */
	public static void clearErr() {
		firstExc.set(null);
	}

	/**
	 * Check and clear the recorded exception.
	 * 
	 * <P>
	 * This method is for testing. If listeners are involved in a test, then this should be called
	 * after that test.
	 * 
	 * <P>
	 * Listeners are often invoked in threads off the test thread. Thus, if they generate an
	 * exception, they get logged, but are otherwise ignored. In particular, a JUnit test with a
	 * listener-generated exception will likely still pass (assuming no other assertion fails). This
	 * method allows such exceptions to be detected and properly cause test failure. Note that this
	 * only works for listeners derived from {@link ListenerMap}, including {@link ListenerSet}.
	 * When an exception is logged, it is also recorded (statically) in the {@link ListenerMap}
	 * class. Only the <em>first</em> unhandled exception is recorded. Subsequent exceptions are
	 * logged, but ignored, until that first exception is cleared and/or checked.
	 */
	public static void checkErr() {
		Throwable exc = firstExc.getAndSet(null);
		if (exc != null) {
			throw new AssertionError("Listener caused an exception", exc);
		}
	}

	protected class ListenerHandler<T extends P> implements InvocationHandler {
		protected final Class<T> ext;

		public ListenerHandler(Class<T> ext) {
			this.ext = ext;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			//Msg.debug(this, "Queuing invocation: " + method.getName() + " @" +
			//	System.identityHashCode(executor));
			// Listener adds/removes need to take immediate effect, even with queued events
			executor.execute(() -> {
				Collection<? extends ListenerEntry<? extends V>> listenersVolatile;
				synchronized (lock) {
					listenersVolatile = map.values();
				}
				for (ListenerEntry<? extends V> wl : listenersVolatile) {
					V l = wl.get();
					if (l == null || !ext.isAssignableFrom(l.getClass())) {
						continue;
					}
					//Msg.debug(this,
					//	"Invoking: " + method.getName() + " @" + System.identityHashCode(executor));
					try {
						method.invoke(l, args);
					}
					catch (InvocationTargetException e) {
						Throwable cause = e.getCause();
						reportError(l, cause);
					}
					catch (Throwable e) {
						reportError(l, e);
					}
				}
			});
			return null; // TODO: Assumes void return type
		}
	}

	private final Object lock = new Object();
	private final Class<P> iface;
	private final Executor executor;
	private Map<K, ? extends ListenerEntry<? extends V>> map = createMap();

	/**
	 * A proxy which passes invocations to each value of this map
	 */
	public final P fire;

	/**
	 * A map of cached specialized proxies
	 */
	protected final Map<Class<? extends P>, P> extFires = new HashMap<>();

	/**
	 * Construct a new map whose proxy implements the given interface
	 * 
	 * <P>
	 * The values in the map must implement the same interface.
	 * 
	 * <P>
	 * Callbacks will be serviced by the invoking thread. This may be risking if the invoking thread
	 * is "precious" to the invoker. There is no guarantee callbacks into client code will complete
	 * in a timely fashion.
	 * 
	 * @param iface the interface to multiplex
	 */
	public ListenerMap(Class<P> iface) {
		this(iface, CALLING_THREAD);
	}

	/**
	 * Construct a new map whose proxy implements the given interface
	 * 
	 * <P>
	 * The values in the map must implement the same interface.
	 * 
	 * @param iface the interface to multiplex
	 */
	public ListenerMap(Class<P> iface, Executor executor) {
		this.iface = Objects.requireNonNull(iface);
		this.executor = executor;
		this.fire = iface.cast(Proxy.newProxyInstance(this.getClass().getClassLoader(),
			new Class[] { iface }, new ListenerHandler<>(iface)));
	}

	@Override
	public String toString() {
		return map.toString();
	}

	protected Map<K, ListenerEntry<? extends V>> createMap() {
		return new HashMap<>();
	}

	protected void notifyRemoved(ListenerEntry<? extends V> entry) {
		Msg.warn(this, "Listener garbage collected before removal: " + entry.desc);
	}

	@SuppressWarnings("unchecked")
	public <T extends P> T fire(Class<T> ext) {
		if (ext == iface) {
			return ext.cast(fire);
		}
		if (!iface.isAssignableFrom(ext)) {
			throw new IllegalArgumentException("Cannot fire on less-specific interface");
		}
		return (T) extFires.computeIfAbsent(ext,
			e -> (P) Proxy.newProxyInstance(this.getClass().getClassLoader(),
				new Class<?>[] { iface, ext }, new ListenerHandler<>(ext)));
	}

	public boolean isEmpty() {
		return map.isEmpty();
	}

	protected void doPutAllInto(Map<? super K, ? super ListenerEntry<? extends V>> newMap) {
		for (Entry<K, ? extends ListenerEntry<? extends V>> ent : map.entrySet()) {
			if (ent.getValue().get() == null) {
				notifyRemoved(ent.getValue());
			}
			else {
				newMap.put(ent.getKey(), ent.getValue());
			}
		}
	}

	public V put(K key, V val) {
		synchronized (lock) {
			if (map.get(key) == val) {
				return val;
			}
			Map<K, ListenerEntry<? extends V>> newMap = createMap();
			doPutAllInto(newMap);
			ListenerEntry<? extends V> result = newMap.put(key, new ListenerEntry<>(val));
			map = newMap;
			return result == null ? null : result.get();
		}
	}

	public void putAll(ListenerMap<? extends K, P, ? extends V> that) {
		synchronized (lock) {
			Map<K, ListenerEntry<? extends V>> newMap = createMap();
			doPutAllInto(newMap);
			that.doPutAllInto(newMap);
			map = newMap;
		}
	}

	public V get(K key) {
		ListenerEntry<? extends V> entry = map.get(key);
		return entry == null ? null : entry.get();
	}

	public V remove(K key) {
		synchronized (lock) {
			if (!map.containsKey(key)) {
				return null;
			}
			Map<K, ListenerEntry<? extends V>> newMap = createMap();
			doPutAllInto(newMap);
			ListenerEntry<? extends V> result = newMap.remove(key);
			map = newMap;
			return result == null ? null : result.get();
		}
	}

	public void clear() {
		synchronized (lock) {
			if (map.isEmpty()) {
				return;
			}
			map = createMap();
		}
	}
}
