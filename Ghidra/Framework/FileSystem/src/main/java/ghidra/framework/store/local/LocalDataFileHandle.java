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
package ghidra.framework.store.local;

import ghidra.framework.store.DataFileHandle;

import java.io.*;

/**
 * <code>LocalDataFileHandle</code> provides random access to 
 * a local File.
 */
public class LocalDataFileHandle implements DataFileHandle {

	private RandomAccessFile raf;
	private boolean readOnly;
	
	/**
	 * Construct and open a local DataFileHandle.
	 * @param file file to be opened
	 * @param readOnly if true resulting handle may only be read.
	 * @throws FileNotFoundException if file was not found
	 * @throws IOException if an IO Error occurs
	 */
	public LocalDataFileHandle(File file, boolean readOnly) throws IOException {
		this.readOnly = readOnly;
		raf = new RandomAccessFile(file, readOnly ? "r" : "rw");
	}
	
	/*
	 * @see ghidra.framework.store.DataFileHandle#read(byte[])
	 */
	public void read(byte[] b) throws IOException {
		raf.readFully(b);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#read(byte[], int, int)
	 */
	public void read(byte[] b, int off, int len) throws IOException {
		raf.readFully(b, off, len);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#skipBytes(int)
	 */
	public int skipBytes(int n) throws IOException {
		return raf.skipBytes(n);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#write(int)
	 */
	public void write(int b) throws IOException {
		raf.write(b);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#write(byte[])
	 */
	public void write(byte[] b) throws IOException {
		raf.write(b);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#write(byte[], int, int)
	 */
	public void write(byte[] b, int off, int len) throws IOException {
		raf.write(b, off, len);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#seek(long)
	 */
	public void seek(long pos) throws IOException {
		raf.seek(pos);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#length()
	 */
	public long length() throws IOException {
		return raf.length();
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#setLength(long)
	 */
	public void setLength(long newLength) throws IOException {
		raf.setLength(newLength);
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#close()
	 */
	public void close() throws IOException {
		raf.close();
	}

	/*
	 * @see ghidra.framework.store.DataFileHandle#isReadOnly()
	 */
	public boolean isReadOnly() throws IOException {
		return readOnly;
	}
}
