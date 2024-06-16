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

import java.lang.reflect.*;
import java.util.Objects;

/**
 * A data structure meant to be used to hold listeners.  This class has a few benefits:
 * <ul>
 *  <li>Clients supply the class of the listeners being stored.  Then, clients make use of a Java
 *      {@link Proxy} object to sends events by calling the desired method directly on the proxy.
 *  </li>
 *  <li>This class is thread safe, allowing adding and removing listeners while events are being
 *      fired.
 *  </li>
 *  <li>Weak or strong references may be used seamlessly by passing the correct constructor value.
 *  </li>
 * </ul>
 *
 * <p>
 * Some restrictions:
 * <ul>
 *  <li>Exception handling is currently done by storing the first exception encountered while
 *      processing events.   Any exception encountered while notifying a listener does not stop
 *      follow-on listeners from getting notified.
 *  </li>
 *  <li>Listener classes are restricted to using methods with a void return type, as there is
 *      currently no way to return values back to the client when notifying.
 *  </li>
 *  <li>The insertion order of listeners is not maintained, which means that event notification may
 *      take place in an arbitrary order.
 *  </li>
 * </ul>
 *
 * <p>
 * An example use of this class to fire events could look like this:
 * <pre>
 *     ListenerSet&lt;ActionListener&gt; listeners = new ListenerSet(ActionListener.class);
 *     ActionEvent event = new ActionEvent(this, 1, "Event");
 *     listeners.invoke().actionPerformed(event);
 * </pre>
 *
 * @param <T> the listener type
 */
public class ListenerSet<T> {

	/**
	 * A proxy which passes invocations to each member of this set
	 */
	private final T proxy;
	private final ThreadSafeListenerStorage<T> listeners;

	private ListenerErrorHandler errorHandler =
		DataStructureErrorHandlerFactory.createListenerErrorHandler();

	/**
	 * Constructs a listener set that is backed by weak references.
	 * @param iface the listener class type.
	 * @param isWeak true signals to use weak storage for the listeners.  If using weak storage,
	 *        clients must keep a reference to the listener or it will eventually be removed from
	 *        this data structure when garbage collected.
	 */
	public ListenerSet(Class<T> iface, boolean isWeak) {
		Objects.requireNonNull(iface);
		this.proxy = iface.cast(Proxy.newProxyInstance(this.getClass().getClassLoader(),
			new Class[] { iface }, new ListenerHandler()));
		this.listeners = new ThreadSafeListenerStorage<>(isWeak);
	}

	private class ListenerHandler implements InvocationHandler {
		@Override
		public Object invoke(Object proxyObject, Method method, Object[] args) throws Throwable {

			listeners.forEach(listener -> {
				try {
					method.invoke(listener, args);
				}
				catch (InvocationTargetException e) {
					Throwable cause = e.getCause();
					errorHandler.handleError(listener, cause);
				}
				catch (Throwable e) {
					errorHandler.handleError(listener, e);
				}
			});

			return null; // assumes void return type
		}
	}

	/**
	 * Returns the proxy object.  Using this is the same as calling {@link #getProxy()}. Use this
	 * method to make the client call more readable.
	 *
	 * @return the proxy
	 */
	public T invoke() {
		return proxy;
	}

	/**
	 * Returns the proxy used by this class.  Using {@link #invoke()} is preferred for better
	 * readability.
	 * @return the proxy
	 */
	public T getProxy() {
		return proxy;
	}

	@Override
	public String toString() {
		return listeners.toString();
	}

	public boolean add(T e) {
		return listeners.add(e);
	}

	public boolean remove(T e) {
		return listeners.remove(e);
	}

	public void clear() {
		listeners.clear();
	}

	public int size() {
		return listeners.size();
	}

	public void setErrorHandler(ListenerErrorHandler errorHandler) {
		this.errorHandler = Objects.requireNonNull(errorHandler);
	}
}
