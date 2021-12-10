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
package ghidra.formats.gfilesystem.crypto;

import java.util.Iterator;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A stub implementation of CryptoSession that relies on a parent instance.
 */
public class CryptoProviderSessionChildImpl implements CryptoSession {

	private CryptoSession parentSession;

	public CryptoProviderSessionChildImpl(CryptoSession parentSession) {
		this.parentSession = parentSession;
	}

	@Override
	public void close() {
		// don't close parent
	}

	@Override
	public boolean isClosed() {
		return parentSession.isClosed();
	}

	@Override
	public Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt) {
		return parentSession.getPasswordsFor(fsrl, prompt);
	}

	@Override
	public void addSuccessfulPassword(FSRL fsrl, PasswordValue password) {
		parentSession.addSuccessfulPassword(fsrl, password);
	}

}
