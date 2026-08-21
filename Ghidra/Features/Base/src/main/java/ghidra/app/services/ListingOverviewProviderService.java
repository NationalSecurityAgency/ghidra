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
package ghidra.app.services;

import ghidra.app.util.viewer.listingpanel.ListingOverviewProvider;

public interface ListingOverviewProviderService {

	/**
	 * Creates a new overview provider.
	 * @return the provider
	 */
	public ListingOverviewProvider createOverviewProvider();

	/**
	 * True if this service is the owner of the given provider.
	 * @param provider the provider to check
	 * @return true if the owner
	 */
	public boolean isOwner(ListingOverviewProvider provider);
}
