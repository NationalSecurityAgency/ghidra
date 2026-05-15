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
package generic.concurrent.io;

import java.io.InputStream;
import java.util.concurrent.Future;
import java.util.function.Consumer;

import generic.concurrent.GThreadPool;
import utilities.util.reflection.ReflectionUtilities;
import utility.function.Dummy;

/**
 * A class that allows clients to <b>asynchronously</b> consume the output of a {@link Process}s
 * input and error streams.  The task is asynchronous to avoid deadlocks when both streams need
 * to be read in order for the process to proceed.
 */
public class ProcessConsumer {

	/**
	 * Read the given input stream line-by-line. 
	 * 
	 * <p>To get all output after all reading is done you can call the blocking operation 
	 * {@link Future#get()}.
	 * 
	 * @param is the input stream
	 * @return the future that will be complete when all lines are read
	 */
	public static Future<IOResult> consume(InputStream is) {
		return consume(is, Dummy.consumer());
	}

	/**
	 * Read the given input stream line-by-line.
	 * 
	 * <p>If you wish to get all output after all reading is done you can call the blocking 
	 * operation {@link Future#get()}.
	 * 
	 * @param is the input stream
	 * @param lineConsumer the line consumer; may be null
	 * @return the future that will be complete when all lines are read
	 */
	public static Future<IOResult> consume(InputStream is, Consumer<String> lineConsumer) {

		lineConsumer = Dummy.ifNull(lineConsumer);

		Throwable inception = ReflectionUtilities.filterJavaThrowable(
			ReflectionUtilities.createThrowableWithStackOlderThan(ProcessConsumer.class));

		GThreadPool pool = GThreadPool.getSharedThreadPool(IOResult.THREAD_POOL_NAME);
		IOResult runnable = new IOResult(is, lineConsumer, true, inception);
		Future<IOResult> future = pool.submit(runnable, runnable);
		return future;
	}

	/**
	 * Reads the given input stream line-by-line, calling the given consumer.  When the
	 * InputStream reaches EOF, a final {@code null} will be sent to the line consumer.
	 * <p>
	 * The Inputstream is consumed via a Thread created just for this setup.
	 * 
	 * @param is the input stream
	 * @param lineConsumer the line consumer; may be null
	 * @param processName descriptive name of process being monitored
	 */
	public static void monitorAndSignalEof(InputStream is, Consumer<String> lineConsumer,
			String processName) {

		Throwable inception = ReflectionUtilities.filterJavaThrowable(
			ReflectionUtilities.createThrowableWithStackOlderThan(ProcessConsumer.class));

		IOResult stdoutReader = new IOResult(is, lineConsumer, false, inception);

		Runnable threadRunnable = lineConsumer != null // change mode if null 
				? () -> {
					stdoutReader.run();
					lineConsumer.accept(null); // signal that eof was reached
				}
				: stdoutReader;

		Thread t = new Thread(threadRunnable, "IO Thread for " + processName);
		t.setDaemon(true);
		t.start();
	}
}
