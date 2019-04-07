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
package ghidra.file.jad;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 *
 * Controller class for the JAD executable.
 *
 */
public class JadProcessController {

	public enum DisposeState {
		NOT_DISPOSED, // Process was/is not disposed
		DISPOSED_ON_TIMEOUT, // A timeout occurred
		DISPOSED_ON_CANCEL, // The process was cancelled
		ENDED_HAPPY;// The process terminated naturally
	}

	private CancelledListener listener = new CancelledListener() {

		@Override
		public void cancelled() {
			dispose();
			disposeState = DisposeState.DISPOSED_ON_CANCEL;
		}
	};

	private MessageLog log = new MessageLog();
	private Runtime runtime = Runtime.getRuntime();
	private String[] environment = new String[] {};
	private Runnable timeoutRunnable;
	private volatile DisposeState disposeState = DisposeState.NOT_DISPOSED;// How this process was (or was not) disposed
	private volatile Process process;
	private volatile InputStream stdin;// stdin from JAD
	private volatile InputStream stderr;// stderr from JAD
	private String desc;

	private JadProcessWrapper wrapper;

	public JadProcessController(JadProcessWrapper wrapper, String desc) {
		this.wrapper = wrapper;
		this.desc = desc;

		timeoutRunnable = new Runnable() {
			@Override
			public void run() {
				if (disposeState == DisposeState.ENDED_HAPPY) {
					return;
				}
				dispose();
				disposeState = DisposeState.DISPOSED_ON_TIMEOUT;
			}
		};
	}

	public void decompile(int timeoutSecs, TaskMonitor monitor) throws IOException {

		monitor.addCancelledListener(listener);

		GTimerMonitor timerMonitor = GTimer.scheduleRunnable(timeoutSecs * 1000, timeoutRunnable);

		try {
			String[] commands = wrapper.getCommands();

			// TODO: JAD will write its output files into its current directory.
			// following line should be changed to wrapper.getOutputDirectory()
			// TODO: JAD will output to file name taken from data inside the .class file.
			// TODO: use -p to force output to stdout.
			process = runtime.exec(commands, environment, wrapper.getWorkingDirectory());

			if (process == null) {
				System.out.println("native process is null");
				return;
			}

			stdin = process.getInputStream();
			stderr = process.getErrorStream();

			readMessagesFromProcess(stdin, "JAD STDOUT " + desc, monitor);
			readMessagesFromProcess(stderr, "JAD STDERR " + desc, monitor);

			waitForProcess();

			disposeState = DisposeState.ENDED_HAPPY;
		}
		finally {
			timerMonitor.cancel();
		}
	}

	private void waitForProcess() {
		try {
			process.waitFor();
		}
		catch (InterruptedException e) {
		}
	}

	/**
	 * Reads the data from stdin and sterr.
	 * It is important to clear the I/O streams of a native process.
	 * If the stream fills, then the process will block.
	 */
	private void readMessagesFromProcess(final InputStream inputStream, String streamName,
			final TaskMonitor monitor) {
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
				StringBuffer buffer = new StringBuffer();
				try {
					byte[] bytes = new byte[0x1000];
					while (!monitor.isCancelled()) {
						int nRead = inputStream.read(bytes);
						if (nRead == -1) {
							break;
						}
						buffer.append(new String(bytes, 0, nRead));
					}
				}
				catch (Exception e) {
					Msg.error(this, "Exception while reading JAD process inputstream", e);
				}
				String string = buffer.toString().trim();
				if (string.length() > 0) {
					string = string.replace("\n", "\n" + streamName + ": ");
					Msg.info(JadProcessController.this, "\n" + streamName + ": " + string);
				}
			}
		};
		Thread thread = new Thread(runnable, "JAD processes stdout/stderr reader");
		thread.start();
	}

	/**
	 * Kicks off a thread to kill the JAD process.
	 */
	public void dispose() {
		if (disposeState != DisposeState.NOT_DISPOSED) {
			return;
		}

		disposeState = DisposeState.DISPOSED_ON_CANCEL;

		// Disposing sometimes hangs and we don't want to hang the swing thread.
		new Thread(new Disposer()).start();
	}

	/**
	 * Returns messages sent from JAD process to stdin and stderr.
	 * @return messages sent from JAD process to stdin and stderr
	 */
	public MessageLog getMessages() {
		return log;
	}

	private class Disposer implements Runnable {
		@Override
		public void run() {

			InputStream stdinCopy = stdin;
			InputStream stderrCopy = stderr;

			stdin = null;
			stderr = null;

			closeProcess();

			close(stdinCopy);
			close(stderrCopy);
		}

		private void closeProcess() {
			try {
				if (process != null) {
					process.destroy();
					process = null;
				}
			}
			catch (Exception e) {
				// we tried
			}
		}

		private void close(InputStream inputStream) {
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
}
