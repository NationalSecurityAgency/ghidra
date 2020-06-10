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
package ghidra.feature.fid.service;

import generic.cache.Factory;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.LRUMap;

/**
 * The caching factory for FID function hashes.  Greatly speeds up processing by memoizing hash
 * valuses for functions which are used repeatedly in different contexts.
 * 
 * NOTE: The function is passed to the factory to create and cache the hash, however the
 * function hashes are keyed by the entry point of the function.
 */
public class FIDFixedSizeMRUCachingFactory implements Factory<Function, FidHashQuad> {

	private LRUMap<Address, FidHashQuad> cache;
	private Factory<Function, FidHashQuad> delegate;

	public FIDFixedSizeMRUCachingFactory(Factory<Function, FidHashQuad> factory, int size) {
		this.delegate = factory;
		this.cache = new LRUMap<Address, FidHashQuad>(size);
	}

	@Override
	public FidHashQuad get(Function func) {
		// Use the entry point of the function as the key, instead of the function
		Address entryPoint = func.getEntryPoint();

		FidHashQuad value = cache.get(entryPoint);
		if (value != null) {
			return value;
		}

		value = delegate.get(func);
		if (value == null) {
			return null;
		}
		cache.put(entryPoint, value);
		return value;
	}
}
