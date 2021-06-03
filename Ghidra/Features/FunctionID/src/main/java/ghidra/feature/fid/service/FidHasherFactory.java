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
import ghidra.feature.fid.hash.FidHasher;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * A factory for caching FID function hashes.  Greatly speeds up processing by memoizing hash
 * values for functions which are used repeatedly in different contexts.
 */
class FidHasherFactory implements Factory<Function, FidHashQuad> {
	private final FidHasher hasher;

	public FidHasherFactory(FidHasher hasher) {
		this.hasher = hasher;
	}

	@Override
	public FidHashQuad get(Function function) {
		try {
			return hasher.hash(function);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}
}
