/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.decompiler;

import generic.concurrent.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;

public class DecompilerDisposer {
	private static String THREAD_POOL_NAME = "Decompiler Disposer";
	private static ConcurrentQ<AbstractDisposable, AbstractDisposable> queue;

	static {
		ConcurrentQBuilder<AbstractDisposable, AbstractDisposable> builder =
			new ConcurrentQBuilder<AbstractDisposable, AbstractDisposable>();
		queue = builder.setThreadPoolName(THREAD_POOL_NAME).build(new DisposeCallback());
	}

	private DecompilerDisposer() {
		// utility class
	}

	/**
	 * Disposes the given Process and related streams from a background thread.  This is necessary
	 * due to a low-probability deadlock that occurs in the JVM.
	 * 
	 * @param process The process to destroy.
	 * @param ouputStream The output stream to close
	 * @param inputStream The input stream to close
	 */
	public static void dispose(Process process, OutputStream ouputStream, InputStream inputStream) {
		RuntimeProcessDisposable disposable =
			new RuntimeProcessDisposable(process, ouputStream, inputStream);
		queue.add(disposable);
	}

	/**
	 * Calls dispose in the given decompiler from a background thread.
	 * <p>
	 * Note:<br>
	 * A class to handle the rare case where the {@link DecompInterface}'s
	 * synchronized methods are blocking 
	 * while a decompile operation has died and maintained the lock.  In that scenario, calling
	 * dispose on this class will eventually try to enter a synchronized method that will 
	 * remain blocked forever.
	 * <p>
	 * I examined the uses of dispose() on the {@link DecompInterface} and 
	 * determined that calling dispose() is a
	 * final operation, which means that you don't have to wait.  Further, after calling
	 * dispose() on this class, you should no longer use it.
	 */
	public static void dispose(DecompInterface decompiler) {
		DecompInterfaceDisposable disposable = new DecompInterfaceDisposable(decompiler);
		queue.add(disposable);
	}

	private static class DisposeCallback implements
			QCallback<AbstractDisposable, AbstractDisposable> {
		@Override
		public AbstractDisposable process(AbstractDisposable disposable, TaskMonitor monitor) {
			disposable.dispose();
			return disposable;
		}
	}

	private static abstract class AbstractDisposable {
		abstract void dispose();
	}

	private static class RuntimeProcessDisposable extends AbstractDisposable {
		private Process process;
		private OutputStream ouputStream;
		private InputStream inputStream;

		RuntimeProcessDisposable(Process process, OutputStream ouputStream, InputStream inputStream) {
			this.process = process;
			this.ouputStream = ouputStream;
			this.inputStream = inputStream;
		}

		@Override
		void dispose() {
			try {
				if (process != null) {
					process.destroy();
					process = null;
				}
			}
			catch (Exception e) {
				// we tried
			}

			try {
				if (ouputStream != null) {
					ouputStream.close();
				}
			}
			catch (IOException e) {
				// we tried
			}

			try {
				if (inputStream != null) {
					inputStream.close();
				}
			}
			catch (IOException e) {
				// we tried
			}
		}
	}

	private static class DecompInterfaceDisposable extends AbstractDisposable {

		private DecompInterface decompiler;

		DecompInterfaceDisposable(DecompInterface decompiler) {
			this.decompiler = decompiler;
		}

		@Override
		void dispose() {
			decompiler.disposeCallback();
		}
	}
}
