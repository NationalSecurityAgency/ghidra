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
package ghidra.framework.remote.security;

import ghidra.security.KeyStorePasswordProvider;

import java.io.*;

import ch.ethz.ssh2.crypto.Base64;
import ch.ethz.ssh2.crypto.PEMDecoder;
import ch.ethz.ssh2.signature.*;

public class SSHKeyManager {

//	private static final String DEFAULT_KEYSTORE_PATH =
//		System.getProperty("user.home") + File.separator + ".ssh/id_rsa";
//
//	/**
//	 * Preference name for the SSH key file paths
//	 */
//	private static final String SSH_KEYSTORE_PROPERTY = "ghidra.sshKeyFile";

	// The public key file is derived by adding this extension to the key store filename
	//private static final String SSH_PUBLIC_KEY_EXT1 = ".pub";

	private static KeyStorePasswordProvider passwordProvider;

	private SSHKeyManager() {
		// static class--can't create
	}

	/**
	 * Set PKI protected keystore password provider
	 * @param provider
	 */
	public static synchronized void setProtectedKeyStorePasswordProvider(
			KeyStorePasswordProvider provider) {
		passwordProvider = provider;
	}

//	/**
//	 * Return the SSH private key for the current user.  The default ~/.ssh/id_rsa file
//	 * will be used unless the System property <i>ghidra.sshKeyFile</i> has been set.
//	 * If the corresponding key file is encrypted the currently installed password
//	 * provider will be used to obtain the decrypt password.
//	 * @return RSAPrivateKey or DSAPrivateKey
//	 * @throws FileNotFoundException key file not found
//	 * @throws IOException if key file not found or key parse failed
//	 * @see RSAPrivateKey
//	 * @see DSAPrivateKey
//	 */
//	public static Object getUsersSSHPrivateKey() throws IOException {
//
//		String privateKeyStorePath = System.getProperty(SSH_KEYSTORE_PROPERTY);
//		if (privateKeyStorePath == null) {
//			privateKeyStorePath = DEFAULT_KEYSTORE_PATH;
//		}
//
//		return getSSHPrivateKey(new File(privateKeyStorePath));
//	}

	/**
	 * Return the SSH private key corresponding to the specified key file.
	 * If the specified key file is encrypted the currently installed password
	 * provider will be used to obtain the decrypt password.
	 * @param sshPrivateKeyFile
	 * @return RSAPrivateKey or DSAPrivateKey
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 * @see RSAPrivateKey
	 * @see DSAPrivateKey
	 */
	public static Object getSSHPrivateKey(File sshPrivateKeyFile) throws IOException {

		if (!sshPrivateKeyFile.isFile()) {
			throw new FileNotFoundException("SSH private key file not found: " + sshPrivateKeyFile);
		}

		InputStream keyIn = new FileInputStream(sshPrivateKeyFile);
		try {
			return getSSHPrivateKey(keyIn, sshPrivateKeyFile.getAbsolutePath());
		}
		finally {
			try {
				keyIn.close();
			}
			catch (IOException e) {
			}
		}
	}

	/**
	 * Return the SSH private key corresponding to the specified key input stream.
	 * If the specified key is encrypted the currently installed password
	 * provider will be used to obtain the decrypt password.
	 * @param sshPrivateKeyIn
	 * @return RSAPrivateKey or DSAPrivateKey
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 * @see RSAPrivateKey
	 * @see DSAPrivateKey
	 */
	public static Object getSSHPrivateKey(InputStream sshPrivateKeyIn) throws IOException {
		return getSSHPrivateKey(sshPrivateKeyIn, "Protected SSH Key");
	}

	private static Object getSSHPrivateKey(InputStream sshPrivateKeyIn, String srcName)
			throws IOException {

		boolean isEncrypted = false;
		StringBuffer keyBuf = new StringBuffer();
		BufferedReader r = new BufferedReader(new InputStreamReader(sshPrivateKeyIn));
		String line;
		while ((line = r.readLine()) != null) {
			if (line.startsWith("Proc-Type:")) {
				isEncrypted = (line.indexOf("ENCRYPTED") > 0);
			}
			keyBuf.append(line);
			keyBuf.append('\n');
		}
		r.close();

		String password = null;
		if (isEncrypted) {
			char[] pwd = passwordProvider.getKeyStorePassword(srcName, false);
			if (pwd == null) {
				throw new IOException("Password required to open SSH private keystore");
			}
			// Don't like using String for password - but API doesn't give us a choice
			password = new String(pwd);
		}

		return PEMDecoder.decode(keyBuf.toString().toCharArray(), password);

	}

	/**
	 * Attempt to instantiate an SSH public key from the specified file
	 * which contains a single public key.
	 * @param sshPublicKeyFile
	 * @return RSAPublicKey or DSAPublicKey
	 * @throws FileNotFoundException key file not found
	 * @throws IOException if key file not found or key parse failed
	 * @see RSAPublicKey
	 * @see DSAPublicKey
	 */
	public static Object getSSHPublicKey(File sshPublicKeyFile) throws IOException {

		BufferedReader r = new BufferedReader(new FileReader(sshPublicKeyFile));
		String keyLine = null;
		String line;
		while ((line = r.readLine()) != null) {
			if (!line.startsWith("ssh-")) {
				continue;
			}
			keyLine = line;
			break;
		}
		r.close();

		if (keyLine != null) {
			String[] pieces = keyLine.split(" ");
			if (pieces.length >= 2) {
				byte[] pubkeyBytes = Base64.decode(pieces[1].toCharArray());
				if ("ssh-rsa".equals(pieces[0])) {
					return RSASHA1Verify.decodeSSHRSAPublicKey(pubkeyBytes);
				}
				else if ("ssh-dsa".equals(pieces[0])) {
					return DSASHA1Verify.decodeSSHDSAPublicKey(pubkeyBytes);
				}
			}
		}

		throw new IOException(
			"Invalid SSH public key file, valid ssh-rsa or ssh-dsa entry not found: " +
				sshPublicKeyFile);
	}

}
