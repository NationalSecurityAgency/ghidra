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
package ghidra.framework.remote;

import java.io.Serializable;
import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.x500.X500Principal;

/**
 * <code>SignatureCallback</code> provides a Callback implementation used
 * to perform PKI authentication.  This callback is instantiated
 * by the server with a random token which must be signed using the 
 * user's certificate which contains one of the recognizedAuthorities
 * within it certificate chain.
 * <p>
 * It is the responsibility of the callback handler to invoke the 
 * sign(X509Certificate[], byte[]) and return this object in response
 * to the callback.
 */
public class SignatureCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private X500Principal[] recognizedAuthorities;
	private final byte[] token;
	private final byte[] serverSignature;

	private byte[] signature;
	private X509Certificate[] certChain;

	/**
	 * Construct callback with a random token to be signed by the client. 
	 * @param recognizedAuthorities list of CA's from which one must occur
	 * within the certificate chain of the signing certificate.
	 * @param token random bytes to be signed
	 */
	public SignatureCallback(X500Principal[] recognizedAuthorities, byte[] token,
			byte[] serverSignature) {
		this.token = token;
		this.serverSignature = serverSignature;
		this.recognizedAuthorities = recognizedAuthorities;
	}

	/**
	 * Returns list of approved certificate authorities.
	 */
	public Principal[] getRecognizedAuthorities() {
		return (recognizedAuthorities == null ? null : (Principal[]) recognizedAuthorities.clone());
	}

	/**
	 * Returns token to be signed using user certificate.
	 */
	public byte[] getToken() {
		return (token == null ? null : (byte[]) token.clone());
	}

	/**
	 * Returns signed token bytes set by callback handler.
	 */
	public byte[] getSignature() {
		return (signature == null ? null : (byte[]) signature.clone());
	}

	/**
	 * Returns the server's signature of the token bytes.
	 */
	public byte[] getServerSignature() {
		return serverSignature;
	}

	/**
	 * Returns certificate chain used to sign token.
	 */
	public X509Certificate[] getCertificateChain() {
		return certChain;
	}

	/**
	 * Set token signature data.  Method must be invoked by 
	 * callback handler.
	 * @param sigCertChain certificate chain used to sign token.
	 * @param certSignature token signature
	 */
	public void sign(X509Certificate[] sigCertChain, byte[] certSignature) {
		this.certChain = sigCertChain;
		this.signature = (certSignature == null ? null : certSignature.clone());
	}

	public String getSigAlg() {
		// TODO Auto-generated method stub
		return null;
	}

//	private void writeObject(java.io.ObjectOutputStream out) throws IOException {
//		
//		out.defaultWriteObject();
//		
//		try {
//			out.writeInt(certChain == null ? -1 : certChain.length);
//			if (certChain != null) {
//				for (int i = 0; i < certChain.length; i++) {
//					out.writeObject(certChain[i].getEncoded());
//				}
//			}
//		} catch (CertificateEncodingException e) {
//			throw new IOException("Can not serialize certificate chain");
//		}
//	}
//	
// 	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
// 		
// 		in.defaultReadObject();
// 		
// 		try {
// 			int cnt = in.readInt();
// 			if (cnt >= 0) {
// 				CertificateFactory cf = CertificateFactory.getInstance("X509");
// 				certChain = new X509Certificate[cnt];
// 				for (int i = 0; i < cnt; i++) {
// 					byte[] bytes = (byte[]) in.readObject();
// 					certChain[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
// 				}
// 			}
// 		} catch (CertificateException e) {
// 			throw new IOException("Can not de-serialize certificate chain");
// 		}
// 	}

}
