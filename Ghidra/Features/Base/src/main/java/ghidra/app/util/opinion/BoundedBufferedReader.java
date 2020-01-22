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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.Reader;

public class BoundedBufferedReader extends Reader {

	private Reader in;

	private char cb[];
	private int nChars, nextChar;

	private static final int INVALIDATED = -2;
	private static final int UNMARKED = -1;
	private int markedChar = UNMARKED;
	private int readAheadLimit = 0; /* Valid only when markedChar > 0 */

	/** If the next character is a line feed, skip it */
	private boolean skipLF = false;

	/** The skipLF flag when the mark was set */
	private boolean markedSkipLF = false;

	private static int defaultCharBufferSize = 8192;
	private static int defaultExpectedLineLength = 80;

	/**
	 * Creates a buffering character-input stream that uses an input buffer of
	 * the specified size.
	 * 
	 * @param in
	 *            A Reader
	 * @param sz
	 *            Input-buffer size
	 * 
	 * @exception IllegalArgumentException
	 *                If sz is &lt;= 0
	 */
	public BoundedBufferedReader(Reader in, int sz) {
		super(in);
		if (sz <= 0)
			throw new IllegalArgumentException("Buffer size <= 0");
		this.in = in;
		cb = new char[sz];
		nextChar = nChars = 0;
	}

	/**
	 * Creates a buffering character-input stream that uses a default-sized
	 * input buffer.
	 * 
	 * @param in
	 *            A Reader
	 */
	public BoundedBufferedReader(Reader in) {
		this(in, defaultCharBufferSize);
	}

	/** Checks to make sure that the stream has not been closed */
	private void ensureOpen() throws IOException {
		if (in == null)
			throw new IOException("Stream closed");
	}

	/**
	 * Fills the input buffer, taking the mark into account if it is valid.
	 */
	private void fill() throws IOException {
		int dst;
		if (markedChar <= UNMARKED) {
			/* No mark */
			dst = 0;
		} else {
			/* Marked */
			int delta = nextChar - markedChar;
			if (delta >= readAheadLimit) {
				/* Gone past read-ahead limit: Invalidate mark */
				markedChar = INVALIDATED;
				readAheadLimit = 0;
				dst = 0;
			} else {
				if (readAheadLimit <= cb.length) {
					/* Shuffle in the current buffer */
					System.arraycopy(cb, markedChar, cb, 0, delta);
					markedChar = 0;
					dst = delta;
				} else {
					/* Reallocate buffer to accommodate read-ahead limit */
					char ncb[] = new char[readAheadLimit];
					System.arraycopy(cb, markedChar, ncb, 0, delta);
					cb = ncb;
					markedChar = 0;
					dst = delta;
				}
				nextChar = nChars = delta;
			}
		}

		int n;
		do {
			n = in.read(cb, dst, cb.length - dst);
		} while (n == 0);
		if (n > 0) {
			nChars = dst + n;
			nextChar = dst;
		}
	}

	/**
	 * Reads a single character.
	 * 
	 * @return The character read, as an integer in the range 0 to 65535 (
	 *         <code>0x00-0xffff</code>), or -1 if the end of the stream has been
	 *         reached
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public int read() throws IOException {
		synchronized (lock) {
			ensureOpen();
			for (;;) {
				if (nextChar >= nChars) {
					fill();
					if (nextChar >= nChars)
						return -1;
				}
				if (skipLF) {
					skipLF = false;
					if (cb[nextChar] == '\n') {
						nextChar++;
						continue;
					}
				}
				return cb[nextChar++];
			}
		}
	}

	/**
	 * Reads characters into a portion of an array, reading from the underlying
	 * stream if necessary.
	 */
	private int read1(char[] cbuf, int off, int len) throws IOException {
		if (nextChar >= nChars) {
			/*
			 * If the requested length is at least as large as the buffer, and
			 * if there is no mark/reset activity, and if line feeds are not
			 * being skipped, do not bother to copy the characters into the
			 * local buffer. In this way buffered streams will cascade
			 * harmlessly.
			 */
			if (len >= cb.length && markedChar <= UNMARKED && !skipLF) {
				return in.read(cbuf, off, len);
			}
			fill();
		}
		if (nextChar >= nChars)
			return -1;
		if (skipLF) {
			skipLF = false;
			if (cb[nextChar] == '\n') {
				nextChar++;
				if (nextChar >= nChars)
					fill();
				if (nextChar >= nChars)
					return -1;
			}
		}
		int n = Math.min(len, nChars - nextChar);
		System.arraycopy(cb, nextChar, cbuf, off, n);
		nextChar += n;
		return n;
	}

	/**
	 * Reads characters into a portion of an array.
	 * 
	 * <p>
	 * This method implements the general contract of the corresponding
	 * <code>{@link Reader#read(char[], int, int) read}</code> method of the
	 * <code>{@link Reader}</code> class. As an additional convenience, it
	 * attempts to read as many characters as possible by repeatedly invoking
	 * the <code>read</code> method of the underlying stream. This iterated
	 * <code>read</code> continues until one of the following conditions becomes
	 * true:
	 * <ul>
	 * 
	 * <li>The specified number of characters have been read,
	 * 
	 * <li>The <code>read</code> method of the underlying stream returns
	 * <code>-1</code>, indicating end-of-file, or
	 * 
	 * <li>The <code>ready</code> method of the underlying stream returns
	 * <code>false</code>, indicating that further input requests would block.
	 * 
	 * </ul>
	 * If the first <code>read</code> on the underlying stream returns
	 * <code>-1</code> to indicate end-of-file then this method returns
	 * <code>-1</code>. Otherwise this method returns the number of characters
	 * actually read.
	 * 
	 * <p>
	 * Subclasses of this class are encouraged, but not required, to attempt to
	 * read as many characters as possible in the same fashion.
	 * 
	 * <p>
	 * Ordinarily this method takes characters from this stream's character
	 * buffer, filling it from the underlying stream as necessary. If, however,
	 * the buffer is empty, the mark is not valid, and the requested length is
	 * at least as large as the buffer, then this method will read characters
	 * directly from the underlying stream into the given array. Thus redundant
	 * <code>BufferedReader</code>s will not copy data unnecessarily.
	 * 
	 * @param cbuf
	 *            Destination buffer
	 * @param off
	 *            Offset at which to start storing characters
	 * @param len
	 *            Maximum number of characters to read
	 * 
	 * @return The number of characters read, or -1 if the end of the stream has
	 *         been reached
	 * 
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public int read(char cbuf[], int off, int len) throws IOException {
		synchronized (lock) {
			ensureOpen();
			if ((off < 0) || (off > cbuf.length) || (len < 0)
					|| ((off + len) > cbuf.length) || ((off + len) < 0)) {
				throw new IndexOutOfBoundsException();
			} else if (len == 0) {
				return 0;
			}

			int n = read1(cbuf, off, len);
			if (n <= 0)
				return n;
			while ((n < len) && in.ready()) {
				int n1 = read1(cbuf, off + n, len - n);
				if (n1 <= 0)
					break;
				n += n1;
			}
			return n;
		}
	}

	/**
	 * Reads a line of text. A line is considered to be terminated by any one of
	 * a line feed ('\n'), a carriage return ('\r'), or a carriage return
	 * followed immediately by a linefeed.
	 * 
	 * @param ignoreLF
	 *            If true, the next '\n' will be skipped
	 * 
	 * @return A String containing the contents of the line, not including any
	 *         line-termination characters, or null if the end of the stream has
	 *         been reached
	 * 
	 * @see java.io.LineNumberReader#readLine()
	 * 
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	String readLine(boolean ignoreLF) throws IOException {
		StringBuffer s = null;
		int startChar;

		synchronized (lock) {
			ensureOpen();
			boolean omitLF = ignoreLF || skipLF;

			while (true) {

				if (nextChar >= nChars)
					fill();
				if (nextChar >= nChars) { /* EOF */
					if (s != null && s.length() > 0) {
						return s.toString();
					}
					return null;
				}
				boolean eol = false;
				char c = 0;
				int i;

				/* Skip a leftover '\n', if necessary */
				if (omitLF && (cb[nextChar] == '\n'))
					nextChar++;
				skipLF = false;
				omitLF = false;

				charLoop: for (i = nextChar; i < nChars; i++) {
					c = cb[i];
					if ((c == '\n') || (c == '\r')) {
						eol = true;
						break charLoop;
					}
				}

				startChar = nextChar;
				nextChar = i;

				if (eol) {
					String str;
					if (s == null) {
						str = new String(cb, startChar, i - startChar);
					} else {
						s.append(cb, startChar, i - startChar);
						str = s.toString();
					}
					nextChar++;
					if (c == '\r') {
						skipLF = true;
					}
					return str;
				}

				if (s == null)
					s = new StringBuffer(defaultExpectedLineLength);
				s.append(cb, startChar, i - startChar);
				
				if (cb.length > 0x1000) {
					return "";
				}
			}
		}
	}

	/**
	 * Reads a line of text. A line is considered to be terminated by any one of
	 * a line feed ('\n'), a carriage return ('\r'), or a carriage return
	 * followed immediately by a linefeed.
	 * 
	 * @return A String containing the contents of the line, not including any
	 *         line-termination characters, or null if the end of the stream has
	 *         been reached
	 * 
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public String readLine() throws IOException {
		return readLine(false);
	}

	/**
	 * Skips characters.
	 * 
	 * @param n
	 *            The number of characters to skip
	 * 
	 * @return The number of characters actually skipped
	 * 
	 * @exception IllegalArgumentException
	 *                If <code>n</code> is negative.
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public long skip(long n) throws IOException {
		if (n < 0L) {
			throw new IllegalArgumentException("skip value is negative");
		}
		synchronized (lock) {
			ensureOpen();
			long r = n;
			while (r > 0) {
				if (nextChar >= nChars)
					fill();
				if (nextChar >= nChars) /* EOF */
					break;
				if (skipLF) {
					skipLF = false;
					if (cb[nextChar] == '\n') {
						nextChar++;
					}
				}
				long d = nChars - nextChar;
				if (r <= d) {
					nextChar += r;
					r = 0;
					break;
				}
				r -= d;
				nextChar = nChars;
			}
			return n - r;
		}
	}

	/**
	 * Tells whether this stream is ready to be read. A buffered character
	 * stream is ready if the buffer is not empty, or if the underlying
	 * character stream is ready.
	 * 
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public boolean ready() throws IOException {
		synchronized (lock) {
			ensureOpen();

			/*
			 * If newline needs to be skipped and the next char to be read is a
			 * newline character, then just skip it right away.
			 */
			if (skipLF) {
				/*
				 * Note that in.ready() will return true if and only if the next
				 * read on the stream will not block.
				 */
				if (nextChar >= nChars && in.ready()) {
					fill();
				}
				if (nextChar < nChars) {
					if (cb[nextChar] == '\n')
						nextChar++;
					skipLF = false;
				}
			}
			return (nextChar < nChars) || in.ready();
		}
	}

	/**
	 * Tells whether this stream supports the mark() operation, which it does.
	 */
	public boolean markSupported() {
		return true;
	}

	/**
	 * Marks the present position in the stream. Subsequent calls to reset()
	 * will attempt to reposition the stream to this point.
	 * 
	 * @param readAheadLimit
	 *            Limit on the number of characters that may be read while still
	 *            preserving the mark. An attempt to reset the stream after
	 *            reading characters up to this limit or beyond may fail. A
	 *            limit value larger than the size of the input buffer will
	 *            cause a new buffer to be allocated whose size is no smaller
	 *            than limit. Therefore large values should be used with care.
	 * 
	 * @exception IllegalArgumentException
	 *                If readAheadLimit is &lt; 0
	 * @exception IOException
	 *                If an I/O error occurs
	 */
	public void mark(int readAheadLimit) throws IOException {
		if (readAheadLimit < 0) {
			throw new IllegalArgumentException("Read-ahead limit < 0");
		}
		synchronized (lock) {
			ensureOpen();
			this.readAheadLimit = readAheadLimit;
			markedChar = nextChar;
			markedSkipLF = skipLF;
		}
	}

	/**
	 * Resets the stream to the most recent mark.
	 * 
	 * @exception IOException
	 *                If the stream has never been marked, or if the mark has
	 *                been invalidated
	 */
	public void reset() throws IOException {
		synchronized (lock) {
			ensureOpen();
			if (markedChar < 0)
				throw new IOException(
						(markedChar == INVALIDATED) ? "Mark invalid"
								: "Stream not marked");
			nextChar = markedChar;
			skipLF = markedSkipLF;
		}
	}

	public void close() throws IOException {
		synchronized (lock) {
			if (in == null)
				return;
			in.close();
			in = null;
			cb = null;
		}
	}
}
