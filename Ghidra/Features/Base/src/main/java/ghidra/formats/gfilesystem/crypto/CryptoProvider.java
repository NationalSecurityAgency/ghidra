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

import java.util.function.Supplier;

/**
 * Common interface for provider interfaces that provide crypto information.
 * <p>
 * TODO: add CryptoKeyProvider.
 */
public interface CryptoProvider {

	interface Session {
		/**
		 * Saves a state object into the session using the cryptoprovider's identity as the key
		 * 
		 * @param cryptoProvider the instance storing the value
		 * @param value the value to store
		 */
		void setStateValue(CryptoProvider cryptoProvider, Object value);

		/**
		 * Retrieves a state object from the session
		 * 
		 * @param <T> the type of the state object
		 * @param cryptoProvider the CryptoProvider instance
		 * @param stateFactory supplier that will create a new instance of the requested
		 * state object if not present in the session
		 * @return state object (either previously saved or newly created by the factory supplier)
		 */
		<T> T getStateValue(CryptoProvider cryptoProvider, Supplier<T> stateFactory);

		/**
		 * Returns the {@link CryptoProviders} instance that created this session.
		 * 
		 * @return the {@link CryptoProviders} instance that created this session
		 */
		CryptoProviders getCryptoProviders();
	}

}
