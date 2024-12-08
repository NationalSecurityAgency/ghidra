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
package ghidra.util.task;

import java.util.Iterator;
import java.util.Objects;

/**
 * An {@link Iterator} wrapper that allows clients to use a task monitor to cancel iteration
 *
 * @param <T> the type
 */
public class CancellableIterator<T> implements Iterator<T> {

	private Iterator<T> delegate;
	private TaskMonitor monitor;

	public CancellableIterator(Iterator<T> delegate, TaskMonitor monitor) {
		this.delegate = Objects.requireNonNull(delegate);
		this.monitor = Objects.requireNonNull(monitor);
	}

	@Override
	public boolean hasNext() {
		if (monitor.isCancelled()) {
			return false;
		}
		return delegate.hasNext();
	}

	@Override
	public T next() {
		return delegate.next();
	}
}
