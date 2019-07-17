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

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A filtering {@link OutputStream} that calculates the hash of the bytes being
 * written.
 * <p>
 * Call {@link #getDigest()} to retrieve the hash value bytes.
 */
public class HashingOutputStream extends OutputStream {

	private OutputStream out;
	private MessageDigest messageDigest;

	/**
	 * @param out - OutputStream to wrap
	 * @param hashAlgo - see {@link MessageDigest#getInstance(String)}, ie. "MD5".
	 * @throws NoSuchAlgorithmException
	 */
	public HashingOutputStream(OutputStream out, String hashAlgo) throws NoSuchAlgorithmException {
		this.out = out;
		this.messageDigest = MessageDigest.getInstance(hashAlgo);
	}

	public void write(int b) throws IOException {
		messageDigest.update((byte) (b & 0xff));
		out.write(b);
	}

	public void write(byte b[]) throws IOException {
		messageDigest.update(b);
		out.write(b, 0, b.length);
	}

	public void write(byte b[], int off, int len) throws IOException {
		messageDigest.update(b, off, len);
		out.write(b, off, len);
	}

	public void flush() throws IOException {
		out.flush();
	}

	public void close() throws IOException {
		try (OutputStream ostream = out) {
			ostream.flush();
		}
	}

	public byte[] getDigest() {
		return messageDigest.digest();
	}

}
