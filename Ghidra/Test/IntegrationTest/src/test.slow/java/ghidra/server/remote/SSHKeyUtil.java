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
package ghidra.server.remote;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.*;
import java.util.Base64;

import ch.ethz.ssh2.packets.TypesWriter;

public class SSHKeyUtil {

	/**
	 * Generate private/public SSH keys for test purposes using RSA algorithm.
	 * @return kay pair array suitable for writing to SSH private and public 
	 * key files ([0] corresponds to private key, [1] corresponds to public key)
	 * @throws NoSuchAlgorithmException
	 */
	public static String[] generateSSHKeys() throws NoSuchAlgorithmException {

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair keyPair = generator.generateKeyPair();

		String[] keys = new String[2];
		keys[0] = getRSAPrivateKey(keyPair);
		keys[1] = getRSAPublicKey(keyPair);
		return keys;
	}

	private static int getEncodedLength(int value) {
		if (value < 0) {
			throw new IllegalArgumentException("negative value");
		}
		if (value <= 0x7f) {
			return 1;
		}
		int len = 1;
		while (value > 0) {
			value >>>= 8;
			++len;
		}
		return len;
	}

	private static int getEncodedLength(byte[] data) {
		return getEncodedLength(data.length) + data.length;
	}

	private static void writeEncodedValue(int value, ByteArrayOutputStream out) {
		int n = getEncodedLength(value);
		if (n == 1) {
			out.write(value & 0xff);
			return;
		}
		if (n < 1 || n > 0x7f) {
			throw new IllegalArgumentException("bad value: " + n);
		}
		out.write(0x80 | --n);
		int shift = 8 * (n - 1);
		for (int i = 0; i < n; i++) {
			out.write((value >> shift) & 0xff);
			shift -= 8;
		}
	}

	private static void writeEncoded(byte[] data, ByteArrayOutputStream out) {
		out.write(0x02);
		writeEncodedValue(data.length, out);
		out.writeBytes(data);
	}

	private static String getRSAPublicKey(KeyPair rsaKeyPair) {
		String keyAlgorithm = "ssh-rsa";
		RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
		TypesWriter w = new TypesWriter();
		w.writeString(keyAlgorithm);
		w.writeMPInt(rsaPublicKey.getPublicExponent());
		w.writeMPInt(rsaPublicKey.getModulus());

		byte[] bytesOut = w.getBytes();
		String publicKeyEncoded = new String(Base64.getEncoder().encodeToString(bytesOut));
		return keyAlgorithm + " " + publicKeyEncoded + " test\n";
	}

	private static String getRSAPrivateKey(KeyPair rsaKeyPair) {
		RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
		RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) privateKey;
		RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		byte[] nArray = privateKey.getModulus().toByteArray();
		byte[] eArray = publicKey.getPublicExponent().toByteArray();
		byte[] dArray = privateKey.getPrivateExponent().toByteArray();
		byte[] pArray = privateCrtKey.getPrimeP().toByteArray();
		byte[] qArray = privateCrtKey.getPrimeQ().toByteArray();
		byte[] epArray = privateCrtKey.getPrimeExponentP().toByteArray();
		byte[] eqArray = privateCrtKey.getPrimeExponentQ().toByteArray();
		byte[] cArray = privateCrtKey.getCrtCoefficient().toByteArray();

		int contentLength = 11 + getEncodedLength(nArray) + getEncodedLength(eArray) +
			getEncodedLength(dArray) + getEncodedLength(pArray) + getEncodedLength(qArray) +
			getEncodedLength(epArray) + getEncodedLength(eqArray) + getEncodedLength(cArray);

		ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
		bytesOut.write(0x30);
		writeEncodedValue(contentLength, bytesOut);
		writeEncoded(new byte[1], bytesOut); // zero
		writeEncoded(nArray, bytesOut);
		writeEncoded(eArray, bytesOut);
		writeEncoded(dArray, bytesOut);
		writeEncoded(pArray, bytesOut);
		writeEncoded(qArray, bytesOut);
		writeEncoded(epArray, bytesOut);
		writeEncoded(eqArray, bytesOut);
		writeEncoded(cArray, bytesOut);
		byte[] privateKeyBytes = bytesOut.toByteArray();

		byte[] base64data = Base64.getEncoder().encodeToString(privateKeyBytes).getBytes();

		StringBuilder rsaKeyOut = new StringBuilder();

		rsaKeyOut.append("-----BEGIN RSA PRIVATE KEY-----\n");
		int cnt = 0;
		while (cnt < base64data.length) {
			int len = Math.min(64, base64data.length - cnt);
			rsaKeyOut.append(new String(base64data, cnt, len));
			rsaKeyOut.append('\n');
			cnt += len;
		}
		rsaKeyOut.append("-----END RSA PRIVATE KEY-----\n");

		return rsaKeyOut.toString();
	}
}
