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
package ghidra.file.formats.ios.dmg;

import java.io.*;
import java.util.Arrays;

import ghidra.app.util.bin.*;
import ghidra.file.crypto.*;
import ghidra.file.formats.ios.generic.iOS_AesCrypto;
import ghidra.file.formats.ios.generic.iOS_Sha1Crypto;
import ghidra.util.exception.CryptoException;

/**
 * An {@link InputStream} that decrypts a DMG file on the fly.
 * <p>
 * The crypto keys for the DMG file are found by using the name of the container file
 * this DMG is embedded in (ie. the name of the .ipsw) and the name of this dmg file to
 * query the {@link CryptoKeyFactory}.
 */
public class DmgDecryptorStream extends InputStream {
	public static final int DMG_VERSION_2 = 2;

	private int block;
	private int totalBlocks;
	private long index;
	private int remainder;
	private byte[] aes_key;
	private byte[] sha1_key;
	private iOS_Sha1Crypto sha1;
	private ByteProvider provider;
	private int dmgBlockSize;
	private int dmgVersion;
	private byte[] buffer;
	private int bufferposition;

	/**
	 * See {@link #DmgDecryptorStream(String, String, ByteProvider)}
	 *
	 * @param containerName the name of the ipsw file the DMG is inside
	 * @param dmgName the name of this DMG file
	 * @param srcFile the encrypted DMG {@link File}
	 * @throws IOException if io error or crypto problem.
	 */
	public DmgDecryptorStream(String containerName, String dmgName, File srcFile)
			throws IOException {
		this(containerName, dmgName, new RandomAccessByteProvider(srcFile));
	}

	/**
	 * Creates a DMG decrypting {@link InputStream}, reading from the provided
	 * {@link ByteProvider}.
	 * <p>
	 * The crypto keys for the DMG file are found by using the name of the container file
	 * this DMG is embedded in (ie. the name of the .ipsw) and the name of this dmg file to
	 * query the {@link CryptoKeyFactory}.
	 * <p>
	 * @param containerName Name of the containing .ipsw file
	 * @param dmgName Name of this DMG file
	 * @param provider stream to be wrapped.  Will be closed when this stream is closed.
	 * @throws IOException if io error or crypto problem.
	 */
	public DmgDecryptorStream(String containerName, String dmgName, ByteProvider provider)
			throws IOException {

		try {
			CryptoKey cryptoKey = CryptoKeyFactory.getCryptoKey(containerName, dmgName);
			if (cryptoKey.key.length != 36) {
				throw new CryptoException("Invalid key length.");
			}
			if (cryptoKey.iv.length != 0) {
				throw new CryptoException("Invalid initialization vector (IV) length.");
			}

			aes_key = Arrays.copyOfRange(cryptoKey.key, 0, 16);
			sha1_key = Arrays.copyOfRange(cryptoKey.key, 16, 16 + 20);
		}
		catch (IOException e) {
			// Release the provider before this exception finishes since the #close() method can't
			// be called later to release it.
			try {
				provider.close();
			}
			catch (IOException ioe) {
				// ignore
			}
			throw e;
		}

		this.provider = provider;

		sha1 = new iOS_Sha1Crypto(sha1_key);

		BinaryReader reader = new BinaryReader(provider, false);
		DmgHeaderV2 dmg = new DmgHeaderV2(reader);
		dmgBlockSize = dmg.getBlockSize();
		dmgVersion = dmg.getVersion();

		block = 0;
		totalBlocks = (int) dmg.getDataSize() / dmgBlockSize;
		index = dmg.getDataOffset();
		remainder = (int) (dmg.getDataSize() % dmgBlockSize);
		nextBuffer();
	}

	@Override
	public void close() throws IOException {
		provider.close();
	}

	private void nextBuffer() throws IOException {
		if (block > totalBlocks) {
			buffer = null;
			bufferposition = -1;
			return;
		}
		byte[] iv = computeIV(sha1, block);
		iOS_AesCrypto aes = new iOS_AesCrypto(aes_key, iv);

		byte[] encrypedBytes = provider.readBytes(index, dmgBlockSize);
		byte[] decryptedBytes = aes.decrypt(encrypedBytes);

		if (dmgVersion == DMG_VERSION_2 && block == totalBlocks && remainder > 0) {
			buffer = Arrays.copyOfRange(decryptedBytes, 0, remainder);
		}
		else {
			buffer = decryptedBytes;
		}

		bufferposition = 0;
		index += dmgBlockSize;
		++block;
	}

	@Override
	public int read() throws IOException {
		if (buffer != null && bufferposition >= buffer.length) {
			nextBuffer();
		}
		if (buffer == null) {
			return -1;
		}
		return buffer[bufferposition++];
	}

	@Override
	public int read(byte b[], int off, int len) throws IOException {
		if (buffer != null && bufferposition >= buffer.length) {
			nextBuffer();
		}
		if (buffer == null) {
			return -1;
		}
		int bytesToCopy = Math.min(len, buffer.length - bufferposition);
		System.arraycopy(buffer, bufferposition, b, off, bytesToCopy);
		bufferposition += bytesToCopy;
		return bytesToCopy;
	}

	private static byte[] computeIV(iOS_Sha1Crypto sha1, int block) throws CryptoException {
		sha1.update(CryptoUtil.htonl(block));
		byte[] bytes = sha1.decrypt();
		byte[] iv = Arrays.copyOfRange(bytes, 0, 16);
		return iv;
	}
}
