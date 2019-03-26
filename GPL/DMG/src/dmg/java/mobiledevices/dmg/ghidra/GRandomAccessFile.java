/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

import java.io.*;

/**
 * Instances of this class support both reading and writing to a 
 * random access file. A random access file behaves like a large 
 * array of bytes stored in the file system. There is a kind of cursor, 
 * or index into the implied array, called the <em>file pointer</em>.
 * This implementation relies on java.net.RandomAccessFile,
 * but adds buffering to limit the amount.
 */
public class GRandomAccessFile {
	private static final byte[] EMPTY = new byte[0];
	private static final int BUFFER_SIZE = 0x100000;

	private File file;
	private RandomAccessFile randomAccessFile;
	private byte[] buffer = EMPTY;
	private long bufferOffset = 0;
	private long bufferFileStartIndex = 0;
	private byte[] lastbuffer = EMPTY;
	private long lastbufferOffset = 0;
	private long lastbufferFileStartIndex = 0;
	private boolean open = false;

	private void checkOpen() throws IOException {
		if (!open) {
			throw new IOException("GhidraRandomAccessFile is closed");
		}
	}

	/**
	 * Creates a random access file stream to read from, and optionally to
	 * write to, the file specified by the {@link File} argument.  A new {@link
	 * FileDescriptor} object is created to represent this file connection.
	 *
	 * <p>
	 * This implementation relies on java.net.RandomAccessFile,
	 * but adds buffering to limit the amount.
	 * <p>
	 * 
	 * <a name="mode"><p> The <tt>mode</tt> argument specifies the access mode
	 * in which the file is to be opened.  The permitted values and their
	 * meanings are:
	 *
	 * <blockquote><table summary="Access mode permitted values and meanings">
	 * <tr><th><p align="left">Value</p></th><th><p align="left">Meaning</p></th></tr>
	 * <tr><td valign="top"><tt>"r"</tt></td>
	 *     <td> Open for reading only.  Invoking any of the <tt>write</tt>
	 *     methods of the resulting object will cause an {@link
	 *     java.io.IOException} to be thrown. </td></tr>
	 * <tr><td valign="top"><tt>"rw"</tt></td>
	 *     <td> Open for reading and writing.  If the file does not already
	 *     exist then an attempt will be made to create it. </td></tr>
	 * <tr><td valign="top"><tt>"rws"</tt></td>
	 *     <td> Open for reading and writing, as with <tt>"rw"</tt>, and also
	 *     require that every update to the file's content or metadata be
	 *     written synchronously to the underlying storage device.  </td></tr>
	 * <tr><td valign="top"><tt>"rwd"&nbsp;&nbsp;</tt></td>
	 *     <td> Open for reading and writing, as with <tt>"rw"</tt>, and also
	 *     require that every update to the file's content be written
	 *     synchronously to the underlying storage device. </td></tr>
	 * </table></blockquote>
	 *
	 * @param      file   the file object
	 * @param      mode   the access mode, as described
	 *                    <a href="#mode">above</a>
	 * @exception  IllegalArgumentException  if the mode argument is not equal
	 *               to one of <tt>"r"</tt>, <tt>"rw"</tt>, <tt>"rws"</tt>, or
	 *               <tt>"rwd"</tt>
	 * @exception FileNotFoundException
	 *					that name cannot be created, or if some other error occurs
	 *            while opening or creating the file
	 */
	public GRandomAccessFile(File file, String mode) throws IOException {
		this.file = file;
		randomAccessFile = new RandomAccessFile(file, mode);
		this.open = true;
	}

	@Override
	protected void finalize() {
		if (open) {
			//TODO Msg.warn(this, "FAIL TO CLOSE " + file);
		}
	}

	/**
	 * Closes this random access file stream and releases any system 
	 * resources associated with the stream. A closed random access 
	 * file cannot perform input or output operations and cannot be 
	 * reopened.
	 * <p>
	 * If this file has an associated channel then the channel is closed as well.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public void close() throws IOException {
		checkOpen();
		open = false;
		randomAccessFile.close();
	}

	/**
	 * Returns the length of this file.
	 * @return     the length of this file, measured in bytes.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public long length() throws IOException {
		checkOpen();
		return randomAccessFile.length();
	}

	/**
	 * Sets the file-pointer offset, measured from the beginning of this 
	 * file, at which the next read or write occurs.  The offset may be 
	 * set beyond the end of the file. Setting the offset beyond the end 
	 * of the file does not change the file length.  The file length will 
	 * change only by writing after the offset has been set beyond the end 
	 * of the file. 
	 * @param      pos   the offset position, measured in bytes from the 
	 *                   beginning of the file, at which to set the file 
	 *                   pointer.
	 * @throws IOException 
	 * @exception  IOException  if <code>pos</code> is less than 
	 *                          <code>0</code> or if an I/O error occurs.
	 */
	public void seek(long pos) throws IOException {
		checkOpen();

		if (pos < 0) {
			throw new IOException("pos cannot be less than zero");
		}

		if (pos < bufferFileStartIndex || pos >= bufferFileStartIndex + BUFFER_SIZE) {
			// check if the last buffer contained it, and swap in if necessary
			swapInLast();
			if (pos < bufferFileStartIndex || pos >= bufferFileStartIndex + BUFFER_SIZE) {
				// not in either, gotta get a new one
				buffer = EMPTY;
				bufferOffset = 0;
				bufferFileStartIndex = pos;
			}
		}
		bufferOffset = pos - bufferFileStartIndex;
	}

	/**
	 * This method reads a byte from the file, starting from the current file pointer. 
	 * <p>
	 * This method blocks until the byte is read, the end of the stream 
	 * is detected, or an exception is thrown. 
	 *
	 * @return     the next byte of this file as a signed eight-bit
	 *             <code>byte</code>.
	 * @exception  EOFException  if this file has reached the end.
	 * @exception  IOException   if an I/O error occurs.
	 */
	public byte readByte() throws IOException {
		checkOpen();
		ensure(1);
		return buffer[(int) bufferOffset];
	}

	/**
	 * Reads up to <code>b.length</code> bytes of data from this file 
	 * into an array of bytes. This method blocks until at least one byte 
	 * of input is available. 
	 *
	 * @param      b   the buffer into which the data is read.
	 * @return     the total number of bytes read into the buffer, or
	 *             <code>-1</code> if there is no more data because the end of
	 *             this file has been reached.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public int read(byte[] b) throws IOException {
		checkOpen();
		return read(b, 0, b.length);
	}

	/**
	 * Reads up to <code>len</code> bytes of data from this file into an 
	 * array of bytes. This method blocks until at least one byte of input 
	 * is available.
	 * 
	 * @param      b     the buffer into which the data is read.
	 * @param      off   the start offset of the data.
	 * @param      len   the maximum number of bytes read.
	 * @return     the total number of bytes read into the buffer, or
	 *             <code>-1</code> if there is no more data because the end of
	 *             the file has been reached.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public int read(byte[] b, int offset, int length) throws IOException {
		checkOpen();
		int readLen = length;
		do {
			int blocklength = readLen;
			if (readLen > (BUFFER_SIZE - bufferOffset)) {
				blocklength = (BUFFER_SIZE - (int) bufferOffset);
				if (blocklength <= 0) {
					blocklength = BUFFER_SIZE;
				}
			}
			ensure(blocklength);
			System.arraycopy(buffer, (int) bufferOffset, b, offset, blocklength);
			readLen -= blocklength;
			offset += blocklength;
			if (readLen > 0) {
				seek(this.bufferFileStartIndex + bufferOffset + blocklength);
			}
		}
		while (readLen > 0);
		return length;
	}

	/**
	 * Writes a byte to this file, starting at the current file pointer. 
	 * @param      b   the data.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public void write(byte b) throws IOException {
		checkOpen();
		write(new byte[] { b }, 0, 1);
	}

	/**
	 * Writes <code>b.length</code> bytes from the specified byte array 
	 * to this file, starting at the current file pointer. 
	 * @param      b   the data.
	 * @exception  IOException  if an I/O error occurs.
	 */
	public void write(byte[] b) throws IOException {
		checkOpen();
		write(b, 0, b.length);
	}

	/**
	 * Writes a sub array as a sequence of bytes. 
	 * @param b the data to be written
	 * @param offset the start offset in the data
	 * @param length the number of bytes that are written
	 * @exception IOException If an I/O error has occurred.
	 */
	public void write(byte[] b, int offset, int length) throws IOException {
		checkOpen();
		randomAccessFile.write(b, offset, length);
		buffer = EMPTY;
		bufferOffset = 0;
		lastbuffer = EMPTY;
		lastbufferOffset = 0;
	}

	/**
	 * Ensures that enough bytes are cached to
	 * satisfy the next request to read.
	 */
	private void ensure(int bytesNeeded) throws IOException {
		checkOpen();
		long oldFileStartIndex = bufferFileStartIndex;
		long oldBufferOffset = bufferOffset;
		long oldSeekPos = oldFileStartIndex + oldBufferOffset;

		if (bufferOffset + bytesNeeded > buffer.length) {
			// check if the last buffer contained it, and swap in if necessary
			swapInLast();
			// must ensure that current read pos is in old buffer, and enough bytes
			long newBufferOffset = (oldSeekPos - bufferFileStartIndex);
			if (oldSeekPos < bufferFileStartIndex ||
				oldSeekPos >= bufferFileStartIndex + BUFFER_SIZE ||
				(newBufferOffset + bytesNeeded > buffer.length)) {
				bufferFileStartIndex = oldFileStartIndex + oldBufferOffset;

				buffer = new byte[BUFFER_SIZE];
				randomAccessFile.seek(bufferFileStartIndex);
				randomAccessFile.read(buffer);
				bufferOffset = 0;
			}
			else {
				bufferOffset = newBufferOffset;
			}
		}
	}

	private void swapInLast() throws IOException {
		checkOpen();
		if (buffer == EMPTY) {
			return;
		}
		// swap em and return
		byte[] swapbuffer = buffer;
		long swapbufferOffset = bufferOffset;
		long swapbufferFileStartIndex = bufferFileStartIndex;

		buffer = lastbuffer;
		bufferOffset = lastbufferOffset;
		bufferFileStartIndex = lastbufferFileStartIndex;

		lastbuffer = swapbuffer;
		lastbufferOffset = swapbufferOffset;
		lastbufferFileStartIndex = swapbufferFileStartIndex;
	}
}
