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
package sarif.handlers.result
;

import java.util.List;

import ghidra.program.model.address.Address;
import sarif.handlers.SarifResultHandler;

public class SarifAddressResultHandler extends SarifResultHandler  {
	
	// If we can parse a listing Address we can make the table navigate there when
	// selected
	
	public String getKey() {
		return "Address";
	}

	public Address parse() {
		List<Address> listingAddresses = controller.getListingAddresses(result);
		return listingAddresses.isEmpty() ? null : listingAddresses.get(0);
	}
	
}
