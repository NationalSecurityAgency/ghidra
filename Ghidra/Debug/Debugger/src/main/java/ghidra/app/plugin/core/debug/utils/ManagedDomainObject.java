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

public class ManagedDomainObject implements AutoCloseable {
	public static final Cleaner CLEANER = Cleaner.create();

	private static class ObjectState implements Runnable {
		private DomainObject obj;

		@Override
		public synchronized void run() {
			if (obj.getConsumerList().contains(this)) {
				obj.release(this);
			}
		}

		public synchronized DomainObject get() {
			if (!obj.getConsumerList().contains(this)) {
				throw new IllegalStateException("Domain object is closed");
			}
			return obj;
		}
	}

	private final ObjectState state = new ObjectState();

	public ManagedDomainObject(DomainFile file, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {
		state.obj = file.getDomainObject(state, okToUpgrade, okToRecover, monitor);
		CLEANER.register(this, state);
	}

	@Override
	public void close() throws Exception {
		state.run();
	}

	public DomainObject get() {
		return state.get();
	}
}
