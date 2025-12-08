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
package ghidra.app.util.viewer.proxy;

import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Variable Proxy for when the function variables aren't being shown. It doesn't include
 * a variable object which prevents the various variable field factories from triggering.
 */
public class ClosedVariableProxy extends VariableProxy {

	public ClosedVariableProxy(ListingModel model, Program program, Address locationAddr,
			Function fun) {
		super(model, program, locationAddr, fun, null, true);
	}

}
