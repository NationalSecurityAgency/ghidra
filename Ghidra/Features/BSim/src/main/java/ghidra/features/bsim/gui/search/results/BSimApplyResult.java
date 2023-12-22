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
package ghidra.features.bsim.gui.search.results;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Contains information regarding the result of a BSim 'apply function name' operation. It 
 * indicates the function name being changed, the new name to use, the address, and any 
 * pertinent error/informational text.
 *
 */
public class BSimApplyResult {

	private String target;
	private String source;
	private BSimResultStatus status;
	private Address address;
	private String message;

	public BSimApplyResult(BSimMatchResult result, BSimResultStatus status, String message) {
		this(result.getOriginalFunctionName(), result.getSimilarFunctionName(), status,
			result.getAddress(), message);
	}

	public BSimApplyResult(Function target, Function source, BSimResultStatus status,
		String message) {
		this(target.getName(true), source.getName(true), status, target.getEntryPoint(), message);
	}

	public BSimApplyResult(String target, String source, BSimResultStatus status, Address address,
		String message) {
		this.target = target;
		this.source = source;
		this.status = status;
		this.address = address;
		this.message = message;
	}

	/**
	 * @return the target function name
	 */
	public String getTargetFunctionName() {
		return target;
	}

	/**
	 * @return the similar function name
	 */
	public String getSourceFunctionName() {
		return source;
	}

	/**
	 * @return the status
	 */
	public BSimResultStatus getStatus() {
		return status;
	}

	/**
	 * @return the address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	public boolean isError() {
		return status == BSimResultStatus.ERROR;
	}

	public boolean isIgnored() {
		return status == BSimResultStatus.IGNORED;
	}

}
