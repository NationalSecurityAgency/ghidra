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

import java.io.Closeable;
import java.util.Iterator;

import ghidra.formats.gfilesystem.FSRL;

/**
 * Provides the caller with the ability to perform crypto querying operations
 * for a group of related files.
 * <p>
 * Typically used to query passwords and to add known good passwords
 * to caches for later re-retrieval.
 * <p>
 * Closing a CryptoSession instance does not invalidate the instance, instead is is a suggestion
 * that the instance should not be used for any further nested sessions.
 * <p>
 * See {@link CryptoProviders#newSession()}.
 */
public interface CryptoSession extends Closeable {

	/**
	 * Returns a sequence of passwords (sorted by quality) that may apply to
	 * the specified file.
	 * 
	 * @param fsrl {@link FSRL} path to the password protected file
	 * @param prompt optional prompt that may be displayed to a user
	 * @return {@link Iterator} of possible passwords
	 */
	Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt);

	/**
	 * Pushes a known good password into a cache for later re-retrieval.
	 * 
	 * @param fsrl {@link FSRL} path to the file that was unlocked by the password
	 * @param password the good password
	 */
	void addSuccessfulPassword(FSRL fsrl, PasswordValue password);

	/**
	 * Returns true if this session has been closed.
	 * 
	 * @return boolean true if closed
	 */
	boolean isClosed();

	/**
	 * Closes this session.
	 */
	@Override
	void close();

}
