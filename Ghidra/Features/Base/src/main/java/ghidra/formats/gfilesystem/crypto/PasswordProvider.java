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
 * Instances of this interface provide passwords to decrypt files.
 * <p>
 * Instances are typically not called directly, instead are used 
 * by a {@link CryptoSession} along with other provider instances to provide
 * a balanced breakfast. 
 * <p>
 * Multiple passwords can be returned for each request with the
 * assumption that the consumer of the values can test and validate each one
 * to find the correct value.  Conversely, it would not be appropriate to use this to get
 * a password for a login service that may lock the requester out after a small number
 * of failed attempts.
 * <p>
 * TODO: add negative password result that can be persisted / cached so
 * user isn't spammed with requests for an unknown password during batch / recursive
 * operations.
 */
public interface PasswordProvider extends CryptoProvider {
	/**
	 * Returns a sequence of passwords (ordered by quality) that may apply to
	 * the specified file.
	 * 
	 * @param fsrl {@link FSRL} path to the password protected file
	 * @param prompt optional prompt that may be displayed to a user
	 * @param session a place to hold state values that persist across
	 * related queries
	 * @return {@link Iterator} of possible passwords
	 */
	Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt, Session session);
}
