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
package ghidra.features.base.memsearch.bytesource;

import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Implementation for an empty {@link AddressableByteSource}
 */
public enum EmptyByteSource implements AddressableByteSource {
	INSTANCE;

	@Override
	public int getBytes(Address address, byte[] bytes, int length) {
		return 0;
	}

	@Override
	public List<SearchRegion> getSearchableRegions() {
		return List.of();
	}

	@Override
	public void invalidate() {
		// nothing to do
	}
}
