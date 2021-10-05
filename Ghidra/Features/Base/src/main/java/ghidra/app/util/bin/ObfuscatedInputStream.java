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
package ghidra.app.util.bin;

import java.io.*;


/**
 * An {@link InputStream} wrapper that de-obfuscates the bytes being read from the underlying
 * stream. 
 */
public class ObfuscatedInputStream extends InputStream {

	private InputStream delegate;
	private long currentPosition;

	/**
	 * Creates instance.
	 * 
	 * @param delegate {@link InputStream} to wrap
	 */
	public ObfuscatedInputStream(InputStream delegate) {
		this.delegate = delegate;
	}

	@Override
	public void close() throws IOException {
		delegate.close();
		super.close();
	}

	@Override
	public int read() throws IOException {
		byte[] buffer = new byte[1];
		int bytesRead = read(buffer, 0, 1);
		return bytesRead == 1 ? Byte.toUnsignedInt(buffer[0]) : -1;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int bytesRead = delegate.read(b, off, len);

		for (int i = 0; i < bytesRead; i++, currentPosition++) {
			int xorMaskIndex =
				(int) (currentPosition % ObfuscatedFileByteProvider.XOR_MASK_BYTES.length);
			byte xorMask = ObfuscatedFileByteProvider.XOR_MASK_BYTES[xorMaskIndex];
			b[off + i] ^= xorMask;

		}
		return bytesRead;
	}

	/**
	 * Entry point to enable command line users to retrieve the contents of an obfuscated
	 * file.
	 * 
	 * @param args either ["--help"], or [ "input_filename", "output_filename" ]
	 * @throws IOException if error
	 */
	public static void main(String[] args) throws IOException {
		if (args.length != 2 || (args.length > 1 && args[0].equals("--help"))) {
			System.err.println("De-Obfuscator Usage:");
			System.err.println("\t" + ObfuscatedInputStream.class.getName() +
				" obfuscated_input_filename_path plain_dest_output_filename_path");
			System.err.println("");
			System.err.println("\tExample:");
			System.err.println("\t\t" + ObfuscatedInputStream.class.getName() +
				" /tmp/myuserid-Ghidra/fscache2/aa/bb/aabbccddeeff00112233445566778899 /tmp/aabbccddeeff00112233445566778899.plaintext");
			System.err.println("");
			return;
		}
		File obfuscatedInputFile = new File(args[0]);
		File plainTextOutputFile = new File(args[1]);

		try (InputStream is = new ObfuscatedInputStream(new FileInputStream(obfuscatedInputFile));
				OutputStream os = new FileOutputStream(plainTextOutputFile)) {

			byte buffer[] = new byte[4096];
			int bytesRead;
			while ((bytesRead = is.read(buffer)) > 0) {
				os.write(buffer, 0, bytesRead);
			}
		}
	}

}
