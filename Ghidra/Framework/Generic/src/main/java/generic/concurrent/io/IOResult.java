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

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;
import utility.function.Dummy;

/**
 * Class to pass to a thread pool that will consume all output from an external process.  This is
 * a {@link Runnable} that get submitted to a thread pool.  This class records the data it reads
 */
public class IOResult implements Runnable {

	public static final String THREAD_POOL_NAME = "I/O Thread Pool";

	private List<String> outputLines = new ArrayList<String>();
	private BufferedReader commandOutput;
	private final Throwable inception;
	private Consumer<String> consumer = Dummy.consumer();

	public IOResult(InputStream input) {
		this(ReflectionUtilities.createThrowableWithStackOlderThan(IOResult.class), input);
	}

	public IOResult(Throwable inception, InputStream input) {
		this.inception = inception;
		commandOutput = new BufferedReader(new InputStreamReader(input));
	}

	public void setConsumer(Consumer<String> consumer) {
		this.consumer = consumer;
	}

	public String getOutputAsString() {
		StringBuilder buffy = new StringBuilder();
		for (String line : outputLines) {
			buffy.append(line);
		}
		return buffy.toString();
	}

	public List<String> getOutput() {
		return outputLines;
	}

	@Override
	public void run() {
		String line = null;

		try {
			while ((line = commandOutput.readLine()) != null) {
				consumer.accept(line);
				outputLines.add(line);
			}
		}
		catch (Exception e) {
			String inceptionString = ReflectionUtilities.stackTraceToString(inception);
			Msg.debug(IOResult.class,
				"Exception reading output from process.  Created from:\n" + inceptionString, e);
		}
	}
}
