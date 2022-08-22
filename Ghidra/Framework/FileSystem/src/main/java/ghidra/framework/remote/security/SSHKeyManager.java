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
package ghidra.framework.remote.security;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import ghidra.security.KeyStorePasswordProvider;
import ghidra.util.Msg;

public class SSHKeyManager {

	static {
		// For JcaPEMKeyConverter().setProvider("BC")
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private static KeyStorePasswordProvider passwordProvider;

	private SSHKeyManager() {
		// static class--can't create
	}

	/**
	 * Set PKI protected keystore password provider
	 * @param provider key store password provider
	 */
	public static synchronized void setProtectedKeyStorePasswordProvider(
			KeyStorePasswordProvider provider) {
		passwordProvider = provider;
	}

	/**
	 * Return the SSH private key corresponding to the specified key file.
	 * If the specified key file is encrypted the currently installed password
	 * provider will be used to obtain the decrypt password.
	 * @param sshPrivateKeyFile private ssh key file
	 * @return private key cipher parameters ({@link RSAKeyParameters} or {@link DSAKeyParameters})
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 * @throws InvalidKeyException if key is not an SSH private key (i.e., PEM format)
	 */
	public static CipherParameters getSSHPrivateKey(File sshPrivateKeyFile)
			throws InvalidKeyException, IOException {

		if (!sshPrivateKeyFile.isFile()) {
			throw new FileNotFoundException("SSH private key file not found: " + sshPrivateKeyFile);
		}

		try (InputStream keyIn = new FileInputStream(sshPrivateKeyFile)) {
			return getSSHPrivateKey(keyIn, sshPrivateKeyFile.getAbsolutePath());
		}
	}

	/**
	 * Return the SSH private key corresponding to the specified key input stream.
	 * If the specified key is encrypted the currently installed password
	 * provider will be used to obtain the decrypt password.
	 * @param sshPrivateKeyIn private ssh key resource input stream
	 * @return private key cipher parameters ({@link RSAKeyParameters} or {@link DSAKeyParameters})
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 * @throws InvalidKeyException if key is not an SSH private key (i.e., PEM format)
	 */
	public static CipherParameters getSSHPrivateKey(InputStream sshPrivateKeyIn)
			throws InvalidKeyException, IOException {
		return getSSHPrivateKey(sshPrivateKeyIn, "Protected SSH Key");
	}

	private static CipherParameters getSSHPrivateKey(InputStream sshPrivateKeyIn, String srcName)
			throws InvalidKeyException, IOException {

		StringBuffer keyBuf = new StringBuffer();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(sshPrivateKeyIn))) {
			boolean checkKeyFormat = true;
			String line;
			while ((line = r.readLine()) != null) {
				if (checkKeyFormat) {
					if (!line.startsWith("-----BEGIN ") || line.indexOf(" KEY-----") < 0) {
						throw new InvalidKeyException("Invalid SSH Private Key");
					}
					if (!line.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
						!line.startsWith("-----BEGIN DSA PRIVATE KEY-----")) {
						Msg.error(SSHKeyManager.class,
							"Unsupported SSH Key Format (see svrREADME.html)");
						throw new IOException("Unsupported SSH Private Key");
					}
					checkKeyFormat = false;
				}
				if (keyBuf.length() != 0) {
					keyBuf.append('\n');
				}
				keyBuf.append(line);
			}
		}

		char[] password = null;
		try (Reader r = new StringReader(keyBuf.toString())) {

			PEMParser pemParser = new PEMParser(r);
			Object object = pemParser.readObject();

			PrivateKeyInfo privateKeyInfo;
			if (object instanceof PEMEncryptedKeyPair) {

				password = passwordProvider.getKeyStorePassword(srcName, false);
				if (password == null) {
					throw new IOException("Password required to open SSH private keystore");
				}

				// Encrypted key - we will use provided password
				PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
				PEMDecryptorProvider decProv =
					new JcePEMDecryptorProviderBuilder().build(password);
				privateKeyInfo = ckp.decryptKeyPair(decProv).getPrivateKeyInfo();
			}
			else {
				// Unencrypted key - no password needed
				PEMKeyPair ukp = (PEMKeyPair) object;
				privateKeyInfo = ukp.getPrivateKeyInfo();
			}
			return PrivateKeyFactory.createKey(privateKeyInfo);
		}
		finally {
			if (password != null) {
				Arrays.fill(password, (char) 0);
			}
		}
	}

	/**
	 * Attempt to instantiate an SSH public key from the specified file
	 * which contains a single public key.
	 * @param sshPublicKeyFile public ssh key file
	 * @return public key cipher parameters {@link RSAKeyParameters} or {@link DSAKeyParameters}
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 */
	public static CipherParameters getSSHPublicKey(File sshPublicKeyFile) throws IOException {

		String keyLine = null;
		try (BufferedReader r = new BufferedReader(new FileReader(sshPublicKeyFile))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (!line.startsWith("ssh-")) {
					continue;
				}
				keyLine = line;
				break;
			}
		}

		if (keyLine != null) {
			String[] part = keyLine.split("\\s+");
			if (part.length >= 2 && part[0].startsWith("ssh-")) {
				byte[] pubkeyBytes = Base64.decode(part[1]);
				return OpenSSHPublicKeyUtil.parsePublicKey(pubkeyBytes);
			}
		}

		throw new IOException(
			"Invalid SSH public key file, supported SSH public key not found: " +
				sshPublicKeyFile);
	}

}
