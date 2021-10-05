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

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import ghidra.formats.gfilesystem.FSRL;

/**
 * Registry of {@link CryptoProvider crypto providers} and {@link #newSession() session creator}.
 */
public class CryptoProviders {
	private static final CryptoProviders singletonInstance = new CryptoProviders();

	/**
	 * Fetch the global {@link CryptoProviders} singleton instance.
	 * 
	 * @return shared {@link CryptoProviders} singleton instance 
	 */
	public static CryptoProviders getInstance() {
		return singletonInstance;
	}

	private CachedPasswordProvider cachedCryptoProvider;
	private List<CryptoProvider> cryptoProviders = new CopyOnWriteArrayList<>();

	CryptoProviders() {
		initPasswordCryptoProviders();
	}

	private void initPasswordCryptoProviders() {
		cachedCryptoProvider = new CachedPasswordProvider();
		CmdLinePasswordProvider runtimePasswords = new CmdLinePasswordProvider();

		registerCryptoProvider(runtimePasswords);
		registerCryptoProvider(cachedCryptoProvider);
	}

	/**
	 * Adds a {@link CryptoProvider} to this registry.
	 * <p>
	 * TODO: do we need provider priority ordering?
	 * 
	 * @param provider {@link CryptoProvider}
	 */
	public void registerCryptoProvider(CryptoProvider provider) {
		cryptoProviders.add(provider);
	}

	/**
	 * Removes a {@link CryptoProvider} from this registry.
	 * 
	 * @param provider {@link CryptoProvider} to remove
	 */
	public void unregisterCryptoProvider(CryptoProvider provider) {
		cryptoProviders.remove(provider);
	}

	/**
	 * Returns the {@link CachedPasswordProvider}.
	 * <p>
	 * (Used by GUI actions to manage the cache)
	 * 
	 * @return cached crypto provider instance
	 */
	public CachedPasswordProvider getCachedCryptoProvider() {
		return cachedCryptoProvider;
	}

	/**
	 * Returns the previously registered matching {@link CryptoProvider} instance.
	 * 
	 * @param <T> CryptoProvider type
	 * @param providerClass {@link CryptoProvider} class
	 * @return previously registered CryptoProvider instance, or null if not found
	 */
	public <T extends CryptoProvider> T getCryptoProviderInstance(Class<T> providerClass) {
		return cryptoProviders.stream()
				.filter(providerClass::isInstance)
				.map(providerClass::cast)
				.findFirst()
				.orElse(null);
	}

	/**
	 * Creates a new {@link CryptoSession}.
	 * <p>
	 * TODO: to truly be effective when multiple files
	 * are being opened (ie. batch import), nested sessions
	 * need to be implemented.
	 * 
	 * @return new {@link CryptoSession} instance
	 */
	public CryptoSession newSession() {
		return new CryptoProviderSessionImpl(cryptoProviders);
	}

	private class CryptoProviderSessionImpl
			implements CryptoProvider.Session, CryptoSession {
		private List<CryptoProvider> providers;
		private Map<CryptoProvider, Object> sessionStateValues = new IdentityHashMap<>();
		private boolean closed;

		public CryptoProviderSessionImpl(List<CryptoProvider> providers) {
			this.providers = new ArrayList<>(providers);
		}

		@Override
		public void addSuccessfulPassword(FSRL fsrl, PasswordValue password) {
			cachedCryptoProvider.addPassword(fsrl, password);
		}

		@Override
		public void close() {
			closed = true;
		}

		@Override
		public boolean isClosed() {
			return closed;
		}

		@Override
		public void setStateValue(CryptoProvider cryptoProvider, Object value) {
			sessionStateValues.put(cryptoProvider, value);
		}

		@Override
		public <T> T getStateValue(CryptoProvider cryptoProvider,
				Supplier<T> stateFactory) {
			Object val = sessionStateValues.get(cryptoProvider);
			if (val == null) {
				T newVal = stateFactory.get();
				sessionStateValues.put(cryptoProvider, newVal);
				return newVal;
			}
			return (T) val;
		}

		@Override
		public CryptoProviders getCryptoProviders() {
			return CryptoProviders.this;
		}

		@Override
		public Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt) {
			return new PasswordIterator(providers, fsrl, prompt);
		}

		/**
		 * Union iterator of all password providers
		 */
		class PasswordIterator implements Iterator<PasswordValue> {
			private List<PasswordProvider> providers;
			private Iterator<PasswordValue> currentIt;
			private String prompt;
			private FSRL fsrl;

			PasswordIterator(List<CryptoProvider> providers, FSRL fsrl, String prompt) {
				this.providers = providers.stream()
						.filter(PasswordProvider.class::isInstance)
						.map(PasswordProvider.class::cast)
						.collect(Collectors.toList());
				this.fsrl = fsrl;
				this.prompt = prompt;
			}

			@Override
			public boolean hasNext() {
				while (currentIt == null || !currentIt.hasNext()) {
					if (providers.isEmpty()) {
						return false;
					}
					PasswordProvider provider = providers.remove(0);
					currentIt = provider.getPasswordsFor(fsrl, prompt, CryptoProviderSessionImpl.this);
				}
				return true;
			}

			@Override
			public PasswordValue next() {
				return currentIt.next();
			}

		}

	}

}
