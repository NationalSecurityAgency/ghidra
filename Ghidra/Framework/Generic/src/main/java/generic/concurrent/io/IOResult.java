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
 * {@link Runnable} that will consume all text output from an {@link InputStream} tied to an 
 * external processes (stdout / stderr).
 * <p>
 * The output can be inspected line-by-line by providing a string {@link Consumer}, or the entire
 * output of the process can be inspected by calling {@link #getOutput()} or 
 * {@link #getOutputAsString()}. 
 */
public class IOResult implements Runnable {

	public static final String THREAD_POOL_NAME = "I/O Thread Pool";

	private final List<String> outputLines;
	private BufferedReader commandOutput;
	private final Throwable inception;
	private final Consumer<String> consumer;

	/**
	 * Creates a {@link IOResult} that consumes the specified {@link InputStream}, saving it
	 * as text lines.
	 * 
	 * @param input {@link InputStream}
	 */
	public IOResult(InputStream input) {
		this(input, null, true,
			ReflectionUtilities.createThrowableWithStackOlderThan(IOResult.class));
	}

	/**
	 * Creates a {@link IOResult} that consumes the specified {@link InputStream}, saving it
	 * as text lines.
	 * 
	 * @param input {@link InputStream}
	 * @param inception information about where this object was created
	 */
	public IOResult(InputStream input, Throwable inception) {
		this(input, null, true, inception);
	}

	/**
	 * Creates a {@link IOResult} that consumes the specified {@link InputStream}, handing each
	 * line to the {@link Consumer}.
	 * <p>
	 * Example: {@code new IOResult(process.getInputStream(), s -> System.out.println(s), null);}
	 * 
	 * @param input {@link InputStream}
	 * @param lineConsumer {@link Consumer string consumer}
	 * @param inception information about where this object was created
	 */
	public IOResult(InputStream input, Consumer<String> lineConsumer, Throwable inception) {
		this(input, lineConsumer, false, inception);
	}

	/**
	 * Creates a {@link IOResult} that consumes the specified {@link InputStream}, handing each
	 * line to the {@link Consumer} and optionally storing each line for later retrieval.
	 * 
	 * @param input {@link InputStream}
	 * @param lineConsumer {@link Consumer string consumer}, optional
	 * @param retainLines boolean flag, if true, the contents read from the InputStream will be
	 * available via {@link #getOutput()} and {@link #getOutputAsString()}
	 * @param inception information about where this object was created
	 */
	public IOResult(InputStream input, Consumer<String> lineConsumer, boolean retainLines,
			Throwable inception) {
		this.outputLines = retainLines ? new ArrayList<>() : List.of();
		if (retainLines) {
			lineConsumer = Dummy.ifNull(lineConsumer).andThen(outputLines::add);
		}
		this.consumer = lineConsumer;
		this.inception = inception;

		commandOutput = new BufferedReader(new InputStreamReader(input));
	}

	public String getOutputAsString() {
		StringBuilder buffy = new StringBuilder();
		for (String line : outputLines) {
			buffy.append(line).append("\n");
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
				consumer.accept(line); // this both adds to outputLines and calls the upstream consumer
			}
		}
		catch (Exception e) {
			String inceptionString = ReflectionUtilities.stackTraceToString(inception);
			Msg.debug(IOResult.class,
				"Exception reading output from process.  Created from:\n" + inceptionString, e);
		}
	}
}
