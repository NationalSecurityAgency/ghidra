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
package generic.hash;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface MessageDigest {
	/**
	 * Returns a string that identifies the algorithm, independent of
	 * implementation details.
	 * @return the name of the algorithm
	 */
	public String getAlgorithm();

	/**
	 * Returns the length of the digest in bytes.
	 * @return the digest length in bytes
	 */
	public int getDigestLength();

	/**
	 * Updates the digest using the specified byte.
	 * @param input the byte with which to update the digest
	 */
	public void update(byte input);

	/**
	 * Updates the digest using the specified short.
	 * @param input the short with which to update the digest (big endian)
	 */
	public void update(short input);

	/**
	 * Updates the digest using the specified int.
	 * @param input the int with which to update the digest (big endian)
	 */
	public void update(int input);

	/**
	 * Updates the digest using the specified long.
	 * @param input the long with which to update the digest (big endian)
	 */
	public void update(long input);

	/**
	 * Updates the digest using the specified array of bytes. Do not use a monitor
	 * @param input the array of bytes
	 */
	public void update(byte[] input);

	/**
	 * Updates the digest using the specified array of bytes, starting at the
	 * specified offset (and for the specified length). Do not use a monitor.
	 * @param input the array of bytes
	 * @param offset the offset to start from in the array of bytes
	 * @param len the number of bytes to use, starting at offset
	 */
	public void update(byte[] input, int offset, int len);

	/**
	 * Updates the digest using the specified array of bytes.
	 * @param input the array of bytes
	 * @param monitor the monitor to check during loops
	 * @throws CancelledException 
	 */
	public void update(byte[] input, TaskMonitor monitor) throws CancelledException;

	/**
	 * Updates the digest using the specified array of bytes, starting at the
	 * specified offset (and for the specified length).
	 * @param input the array of bytes
	 * @param offset the offset to start from in the array of bytes
	 * @param len the number of bytes to use, starting at offset
	 * @param monitor the monitor to check during loops
	 * @throws CancelledException 
	 */
	public void update(byte[] input, int offset, int len, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Completes the hash computation by performing final operations such as
	 * padding.  The digest is reset after this call is made.
	 * @return the array of bytes for the resulting hash value
	 */
	public byte[] digest();

	/**
	 * Completes the hash computation by performing final operations such as
	 * padding, and returns (up to) the first 8 bytes as a big-endian long
	 * value.  The digest is reset after this call is made.
	 * @return the digest value as a long value
	 */
	public long digestLong();

	/**
	 * Completes the hash computation by performing final operations such as
	 * padding.  The digest is reset after this call is made.
	 * @param buf output buffer for the computed digest
	 * @param offset offset into the output buffer to begin storing the digest
	 * @param len number of bytes within buf allocated for the digest
	 * @return the number of bytes placed into buf
	 */
	public int digest(byte[] buf, int offset, int len);

	/**
	 * Resets the digest for further use.
	 */
	public void reset();
}
