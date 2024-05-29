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
package ghidra.program.model.pcode;

import java.io.IOException;
import java.io.InputStream;

/**
 * An object that can ingest bytes from a stream in preparation for decoding
 */
public interface ByteIngest {

	/**
	 * Clear any previous cached bytes.
	 */
	public void clear();

	/**
	 * Open the ingester for receiving bytes.  This establishes the description of the source of
	 * the bytes and maximum number of bytes that can be read
	 * @param max is the maximum number of bytes that can be read
	 * @param desc is the description of the byte source
	 */
	public void open(int max, String desc);

	/**
	 * Ingest bytes from the stream up to (and including) the first 0 byte.  This can be called
	 * multiple times to read in bytes in different chunks.
	 * An absolute limit is set on the number of bytes that can be ingested via the max parameter
	 * to a previous call to open(). If this limit is exceeded, an exception is thrown.
	 * @param inStream is the input stream to read from
	 * @throws IOException for errors reading from the stream
	 */
	public void ingestStreamToNextTerminator(InputStream inStream) throws IOException;

	/**
	 * Ingest bytes from the stream until the end of stream is encountered.
	 * An absolute limit is set on the number of bytes that can be ingested via the max parameter
	 * to a previous call to open(). If this limit is exceeded, an exception is thrown.
	 * @param inStream is the input stream to read from
	 * @throws IOException for errors reading from the stream
	 */
	public void ingestStream(InputStream inStream) throws IOException;

	/**
	 * Ingest bytes directly from a byte array.
	 * If these bytes would cause the total number of bytes ingested to exceed
	 * the maximum (as set by the call to open()), an exception is thrown.
	 * This can be called multiple times to read in different chunks.
	 * @param byteArray is the array of bytes
	 * @param off is the index of the first byte to ingest
	 * @param sz is the number of bytes to ingest
	 * @throws IOException if the max number of bytes to ingest is exceeded
	 */
	public void ingestBytes(byte[] byteArray, int off, int sz) throws IOException;

	/**
	 * Formal indicator that ingesting of bytes is complete and processing can begin
	 * @throws IOException for errors processing the underlying stream
	 */
	public void endIngest() throws IOException;

	/**
	 * @return true if no bytes have yet been ingested via ingestStream()
	 */
	public boolean isEmpty();
}
