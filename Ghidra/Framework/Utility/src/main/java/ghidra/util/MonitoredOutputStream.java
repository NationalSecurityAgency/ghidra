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
package ghidra.util;

import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream which utilizes a TaskMonitor to indicate output progress and
 * allows the operation to be cancelled via the TaskMonitor.
 */
public class MonitoredOutputStream extends OutputStream {

	private final static int PROGRESS_INCREMENT = 32 * 1024;

	protected OutputStream out;
	private TaskMonitor monitor;
	private int smallCount = 0;
	private int count = 0;

	public MonitoredOutputStream(OutputStream out, TaskMonitor monitor) {
		this.out = out;
		this.monitor = monitor;
	}

	/**
	 * Reset the current progress count to the specified value.
	 */
	public void setProgress(int count) {
		this.count = count;
	}

	/**
	 * Writes the specified <code>byte</code> to this output stream. 
	 * <p>
	 * The <code>write</code> method of <code>FilterOutputStream</code> 
	 * calls the <code>write</code> method of its underlying output stream, 
	 * that is, it performs <code>out.write(b)</code>.
	 * <p>
	 * Implements the abstract <code>write</code> method of <code>OutputStream</code>. 
	 *
	 * @param      b   the <code>byte</code>.
	 * @exception  IOException  if an I/O error occurs.
	 */
	@Override
	public void write(int b) throws IOException {
		out.write(b);
		++smallCount;
		if (smallCount >= PROGRESS_INCREMENT) {
			if (monitor.isCancelled())
				throw new IOCancelledException();
			count += smallCount;
			smallCount = 0;
			monitor.setProgress(count);
		}
	}

	/**
	 * Writes <code>b.length</code> bytes to this output stream. 
	 * <p>
	 * The <code>write</code> method of <code>FilterOutputStream</code> 
	 * calls its <code>write</code> method of three arguments with the 
	 * arguments <code>b</code>, <code>0</code>, and 
	 * <code>b.length</code>. 
	 * <p>
	 * Note that this method does not call the one-argument 
	 * <code>write</code> method of its underlying stream with the single 
	 * argument <code>b</code>. 
	 *
	 * @param      b   the data to be written.
	 * @exception  IOException  if an I/O error occurs.
	 * @see        java.io.FilterOutputStream#write(byte[], int, int)
	 */
	@Override
	public void write(byte b[]) throws IOException {
		write(b, 0, b.length);
	}

	/**
	 * Writes <code>len</code> bytes from the specified 
	 * <code>byte</code> array starting at offset <code>off</code> to 
	 * this output stream. 
	 * <p>
	 * The <code>write</code> method of <code>FilterOutputStream</code> 
	 * calls the <code>write</code> method of one argument on each 
	 * <code>byte</code> to output. 
	 * <p>
	 * Note that this method does not call the <code>write</code> method 
	 * of its underlying input stream with the same arguments. Subclasses 
	 * of <code>FilterOutputStream</code> should provide a more efficient 
	 * implementation of this method. 
	 *
	 * @param      b     the data.
	 * @param      off   the start offset in the data.
	 * @param      len   the number of bytes to write.
	 * @exception  IOException  if an I/O error occurs.
	 * @see        java.io.FilterOutputStream#write(int)
	 */
	@Override
	public void write(byte b[], int off, int len) throws IOException {
		out.write(b, off, len);
		smallCount += len;

		if (smallCount >= PROGRESS_INCREMENT) {
			if (monitor.isCancelled())
				throw new IOCancelledException();
			count += smallCount;
			smallCount = 0;
			monitor.setProgress(count);
		}
	}

	/**
	 * Flushes this output stream and forces any buffered output bytes 
	 * to be written out to the stream. 
	 * <p>
	 * The <code>flush</code> method of <code>FilterOutputStream</code> 
	 * calls the <code>flush</code> method of its underlying output stream. 
	 *
	 * @exception  IOException  if an I/O error occurs.
	 */
	@Override
	public void flush() throws IOException {
		out.flush();
	}

	/**
	 * Closes this output stream and releases any system resources 
	 * associated with the stream. 
	 * <p>
	 * The <code>close</code> method of <code>FilterOutputStream</code> 
	 * calls its <code>flush</code> method, and then calls the 
	 * <code>close</code> method of its underlying output stream. 
	 *
	 * @exception  IOException  if an I/O error occurs.
	 * @see        java.io.FilterOutputStream#flush()
	 */
	@Override
	public void close() throws IOException {
		try {
			flush();
		}
		catch (IOException ignored) {
			// don't care
		}
		out.close();
	}
}
