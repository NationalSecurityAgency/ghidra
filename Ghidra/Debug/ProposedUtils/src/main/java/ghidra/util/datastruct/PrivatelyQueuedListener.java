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
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

/**
 * A listener which queues invocations onto a separate executor
 *
 * @param <P> the type of listener
 */
public class PrivatelyQueuedListener<P> {

	protected class ListenerHandler implements InvocationHandler {
		protected final Class<P> iface;

		public ListenerHandler(Class<P> iface) {
			this.iface = iface;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			executor.execute(() -> {
				try {
					method.invoke(out, args);
				}
				catch (InvocationTargetException e) {
					Throwable cause = e.getCause();
					ListenerMap.reportError(out, cause);
				}
				catch (Throwable e) {
					ListenerMap.reportError(out, e);
				}
			});
			return null; // Assumes void return type
		}
	}

	/**
	 * The "input" listener, which should be added as a listener on other things
	 */
	public final P in;

	protected final Executor executor;
	protected final P out;

	/**
	 * Create a new privately-queued listener which will invoke the given "output" listener
	 * 
	 * <p>
	 * Invoking the listener methods of {@link #in} will cause that invocation to be queued and
	 * eventually delivered to the given output listener. Note, as a result, it is assumed all
	 * listener methods return type {@code void}, since returning a value would require waiting on
	 * the invocation to complete, which defeats the purpose of the private queue. The invocations
	 * on {@link #in} will always return {@code null}, which will cause an exception if the return
	 * type is a different primitive.
	 * 
	 * @param iface the interface of the listener
	 * @param executor the executor representing the processing queue
	 * @param out the listener to receive the queued invocations
	 */
	public PrivatelyQueuedListener(Class<P> iface, Executor executor, P out) {
		this.in = iface.cast(Proxy.newProxyInstance(this.getClass().getClassLoader(),
			new Class[] { iface }, new ListenerHandler(iface)));
		this.executor = executor;
		this.out = out;
	}

	/**
	 * Create a new single-threaded privately-queued listener
	 * 
	 * @see {@link #PrivatelyQueuedListener(Class, Executor, Object)}
	 * @param iface the interface of the listener
	 * @param threadNamePattern a pattern for naming the single thread
	 * @param out the listener to receive the queued invocations
	 */
	public PrivatelyQueuedListener(Class<P> iface, String threadNamePattern, P out) {
		this(iface,
			Executors.newSingleThreadExecutor(new BasicThreadFactory.Builder()
					.namingPattern(threadNamePattern)
					.build()),
			out);
	}
}
