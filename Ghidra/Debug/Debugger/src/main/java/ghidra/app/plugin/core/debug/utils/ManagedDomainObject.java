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
package ghidra.app.plugin.core.debug.utils;

import java.io.IOException;
import java.lang.ref.Cleaner;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalFunction;

public class ManagedDomainObject<T extends DomainObject> implements AutoCloseable {
	public static final Cleaner CLEANER = Cleaner.create();

	private static class ObjectState<T extends DomainObject> implements Runnable {
		private T obj;

		@Override
		public synchronized void run() {
			if (obj.getConsumerList().contains(this)) {
				obj.release(this);
			}
		}

		public synchronized T get() {
			if (!obj.getConsumerList().contains(this)) {
				throw new IllegalStateException("Domain object is closed");
			}
			return obj;
		}
	}

	private final ObjectState<T> state = new ObjectState<>();

	public ManagedDomainObject(DomainFile file, Class<T> type, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		state.obj = type.cast(file.getDomainObject(state, false, false, monitor));
		CLEANER.register(this, state);
	}

	public <E extends Exception> ManagedDomainObject(ExceptionalFunction<Object, T, E> supplier)
			throws E {
		state.obj = supplier.apply(state);
		CLEANER.register(this, state);
	}

	@Override
	public void close() {
		state.run();
	}

	public T get() {
		return state.get();
	}
}
