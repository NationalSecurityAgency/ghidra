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
package ghidra.async;

import java.util.List;
import java.util.concurrent.*;

import javax.swing.SwingUtilities;

import ghidra.async.seq.AsyncSequenceActionRuns;
import ghidra.async.seq.AsyncSequenceWithoutTemp;

/**
 * A wrapper for {@link SwingUtilities#invokeLater(Runnable)} that implements
 * {@link ExecutorService}. This makes it a suitable first parameter to
 * {@link AsyncSequenceWithoutTemp#then(ExecutorService, AsyncSequenceActionRuns)} and similar.
 */
public class SwingExecutorService extends AbstractExecutorService {
	public static final SwingExecutorService INSTANCE = new SwingExecutorService();

	private SwingExecutorService() {
	}

	@Override
	public void shutdown() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Runnable> shutdownNow() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isShutdown() {
		return false;
	}

	@Override
	public boolean isTerminated() {
		return false;
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void execute(Runnable command) {
		SwingUtilities.invokeLater(command);
	}
}
