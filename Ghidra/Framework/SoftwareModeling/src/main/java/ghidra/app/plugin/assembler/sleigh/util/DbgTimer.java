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
package ghidra.app.plugin.assembler.sleigh.util;

import java.io.*;
import java.util.Stack;

/**
 * A debugging, timing, and diagnostic tool
 * 
 * TODO: I should probably remove this and rely on the Msg.trace() method, or at the very least,
 * refactor this to use that.
 */
public class DbgTimer extends PrintStream {
	// a stack of start times
	Stack<Long> timeStack = new Stack<>();

	/**
	 * Create a new debugging timer, wrapping the given output stream
	 * @param out the stream
	 */
	public DbgTimer(OutputStream out) {
		super(new TabbingOutputStream(out));
		TabbingOutputStream tos = (TabbingOutputStream) this.out;
		tos.setTimeStack(timeStack);
	}

	/**
	 * Create a new debugging timer, wrapping standard out
	 */
	public DbgTimer() {
		this(System.out);
	}

	/**
	 * A (rather slow) output stream that indents every line of its output
	 */
	public static class TabbingOutputStream extends OutputStream {
		protected static final int STATE_NOLINE = 0;
		protected static final int STATE_LINE = 1;

		protected OutputStream out;
		protected int state = STATE_NOLINE;
		protected Stack<Long> timeStack;

		/**
		 * Create a new stream wrapping another
		 * @param out the stream to wrap
		 */
		private TabbingOutputStream(OutputStream out) {
			this.out = out;
		}

		/**
		 * Start a new (indented) line of output
		 * @throws IOException
		 */
		protected void startln() throws IOException {
			for (@SuppressWarnings("unused")
			Long l : timeStack) {
				out.write(' ');
				out.write(' ');
			}
		}

		/**
		 * Workaround: Set the time stack reference
		 * @param timeStack the stack
		 */
		protected void setTimeStack(Stack<Long> timeStack) {
			this.timeStack = timeStack;
		}

		/**
		 * {@inheritDoc}
		 * 
		 * Parses each line and prepends the indentation as they are printed
		 */
		@Override
		public void write(int b) throws IOException {
			if (b == '\n' || b == '\r') {
				out.write(b);
				state = STATE_NOLINE;
			}
			else if (state == STATE_NOLINE) {
				startln();
				out.write(b);
				state = STATE_LINE;
			}
			else {
				out.write(b);
			}
		}

		@Override
		public void close() throws IOException {
			if (out == System.out || out == System.err) {
				out.flush(); // might as well
				return;
			}
			try (OutputStream s = out) {
				s.flush();
			}
		}

		@Override
		public void flush() throws IOException {
			out.flush();
		}
	}

	/** An instance that prints to standard out */
	public static final DbgTimer ACTIVE = new DbgTimer();
	/** An instance that prints to /dev/null */
	public static final DbgTimer INACTIVE = new DbgTimer(new OutputStream() {
		@Override
		public void write(int b) throws IOException {
			// This prevents inefficient squelching of debug messages. It is much better to squelch
			// at the original print call (many overridden below). If one was missed, please
			// override it too. Also see the TODO in the class documentation above.
			throw new AssertionError("INTERNAL: Should not be here.");
		}
	}) {
		@Override
		public void print(String msg) {
			// Nothing
		}

		@Override
		public void println(String msg) {
			// Nothing
		}

		@Override
		public void println() {
			// Nothing
		}

		@Override
		public void print(Object msg) {
			// Nothing
		}

		@Override
		public void println(Object msg) {
			// Nothing
		}

		@Override
		public DbgCtx start(Object message) {
			return null;
		}

		@Override
		public void stop() {
			// Nothing
		}
	};

	/**
	 * Start a new, possibly long-running, task
	 * @param message the message to print when the task begins
	 * @return a context to close when the task ends
	 * 
	 * This is meant to be used idiomatically, as in a try-with-resources block:
	 * <pre>
	 * {@code
	 * try (DbgCtx dc = dbg.start("Twiddling the frobs:")) {
	 *     // do some classy twiddling
	 * } // this will automatically print done and the time elapsed within the try block
	 * }
	 * </pre>
	 * 
	 * This idiom is preferred because the task will be stopped even if an error occurs, if the
	 * method returns from within the block, etc.
	 */
	public DbgCtx start(Object message) {
		println(message);
		flush();
		timeStack.push(System.currentTimeMillis());
		return new DbgCtx(this);
	}

	/**
	 * Stop the current task
	 * 
	 * This will print done and the elapsed time since the start of the task. The "current task" is
	 * determined from the stack.
	 */
	public void stop() {
		long time = System.currentTimeMillis() - timeStack.pop();
		flush();
		println("Done after " + time + "ms");
	}

	/**
	 * Replace the wrapped output stream (usually temporarily)
	 * @see #resetOutputStream(TabbingOutputStream)
	 * @param s the replacement stream
	 * @return the original stream, wrapped in a tabbing stream
	 */
	public TabbingOutputStream setOutputStream(OutputStream s) {
		flush();
		TabbingOutputStream old = (TabbingOutputStream) this.out;
		TabbingOutputStream tos = new TabbingOutputStream(s);
		tos.setTimeStack(timeStack);
		this.out = tos;
		return old;
	}

	/**
	 * Put the original tabbing stream back
	 * @see #setOutputStream(OutputStream)
	 * @param s the original wrapped stream
	 * @return the replacement stream, wrapped in a tabbing stream
	 */
	public TabbingOutputStream resetOutputStream(TabbingOutputStream s) {
		flush();
		TabbingOutputStream old = (TabbingOutputStream) this.out;
		this.out = s;
		return old;
	}

	/**
	 * A context for idiomatic use of the {@link DbgTimer} in a try-with-resources block
	 */
	public static class DbgCtx implements AutoCloseable {
		private DbgTimer dbg;

		private DbgCtx(DbgTimer dbg) {
			this.dbg = dbg;
		}

		@Override
		public void close() {
			dbg.stop();
		}
	}
}
