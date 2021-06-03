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
package ghidra.framework.store;

import java.io.IOException;

/**
 * <code>DataFileHandle</code> provides a random-access handle to a file.
 */
public interface DataFileHandle {

	/**
	 * Returns true if this data file handle is open read-only.
	 * @throws IOException if an I/O error occurs.  
	 */
	public boolean isReadOnly() throws IOException;
	
    /**
     * Reads <code>b.length</code> bytes from this file into the byte 
     * array, starting at the current file pointer. This method reads 
     * repeatedly from the file until the requested number of bytes are 
     * read. This method blocks until the requested number of bytes are 
     * read, the end of the stream is detected, or an exception is thrown. 
     *
     * @param      b   the buffer into which the data is read.
     * @exception  java.io.EOFException if this file reaches the end before reading
     *               all the bytes.
     * @exception  IOException   if an I/O error occurs.       
     */
    public void read(byte b[]) throws IOException;

    /**
     * Reads exactly <code>len</code> bytes from this file into the byte 
     * array, starting at the current file pointer. This method reads 
     * repeatedly from the file until the requested number of bytes are 
     * read. This method blocks until the requested number of bytes are 
     * read, the end of the stream is detected, or an exception is thrown. 
     *
     * @param      b     the buffer into which the data is read.
     * @param      off   the start offset of the data.
     * @param      len   the number of bytes to read.
     * @exception  java.io.EOFException  if this file reaches the end before reading
     *               all the bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public void read(byte b[], int off, int len) throws IOException;

    /**
     * Attempts to skip over <code>n</code> bytes of input discarding the 
     * skipped bytes. 
     * <p>
     * 
     * This method may skip over some smaller number of bytes, possibly zero. 
     * This may result from any of a number of conditions; reaching end of 
     * file before <code>n</code> bytes have been skipped is only one 
     * possibility. This method never throws an <code>EOFException</code>. 
     * The actual number of bytes skipped is returned.  If <code>n</code> 
     * is negative, no bytes are skipped.
     *
     * @param      n   the number of bytes to be skipped.
     * @return     the actual number of bytes skipped.
     * @exception  IOException  if an I/O error occurs.
     */
    public int skipBytes(int n) throws IOException;

    /**
     * Writes the specified byte to this file. The write starts at 
     * the current file pointer.
     *
     * @param      b   the <code>byte</code> to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void write(int b) throws IOException;

    /**
     * Writes <code>b.length</code> bytes from the specified byte array 
     * to this file, starting at the current file pointer. 
     *
     * @param      b   the data.
     * @exception  IOException  if an I/O error occurs.
     */
    public void write(byte b[]) throws IOException;

    /**
     * Writes <code>len</code> bytes from the specified byte array 
     * starting at offset <code>off</code> to this file. 
     *
     * @param      b     the data.
     * @param      off   the start offset in the data.
     * @param      len   the number of bytes to write.
     * @exception  IOException  if an I/O error occurs.
     */
    public void write(byte b[], int off, int len) throws IOException;

    /**
     * Sets the file-pointer offset, measured from the beginning of this 
     * file, at which the next read or write occurs.  The offset may be 
     * set beyond the end of the file. Setting the offset beyond the end 
     * of the file does not change the file length.  The file length will 
     * change only by writing after the offset has been set beyond the end 
     * of the file. 
     *
     * @param      pos   the offset position, measured in bytes from the 
     *                   beginning of the file, at which to set the file 
     *                   pointer.
     * @exception  IOException  if <code>pos</code> is less than 
     *                          <code>0</code> or if an I/O error occurs.
     */
    public void seek(long pos) throws IOException;

    /**
     * Returns the length of this file.
     *
     * @return     the length of this file, measured in bytes.
     * @exception  IOException  if an I/O error occurs.
     */
    public long length() throws IOException;

    /**
     * Sets the length of this file.
     *
     * <p> If the present length of the file as returned by the
     * <code>length</code> method is greater than the <code>newLength</code>
     * argument then the file will be truncated.  In this case, if the file
     * offset as returned by the <code>getFilePointer</code> method is greater
     * then <code>newLength</code> then after this method returns the offset
     * will be equal to <code>newLength</code>.
     *
     * <p> If the present length of the file as returned by the
     * <code>length</code> method is smaller than the <code>newLength</code>
     * argument then the file will be extended.  In this case, the contents of
     * the extended portion of the file are not defined.
     *
     * @param      newLength    The desired length of the file
     * @exception  IOException  If an I/O error occurs
     */
    public void setLength(long newLength) throws IOException;

    /**
     * Closes this random access file stream and releases any system 
     * resources associated with the stream. A closed random access 
     * file cannot perform input or output operations and cannot be 
     * reopened.
     *
     * @exception  IOException  if an I/O error occurs.
     */
    public void close() throws IOException;

}
