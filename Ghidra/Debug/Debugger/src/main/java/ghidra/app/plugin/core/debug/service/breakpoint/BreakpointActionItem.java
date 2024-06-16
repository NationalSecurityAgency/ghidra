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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.program.model.address.*;

/**
 * An invocation is planning an action on a breakpoint
 * 
 * @see BreakpointActionSet
 */
public interface BreakpointActionItem {
	/**
	 * Compute a range from an address and length
	 * 
	 * @param address the min address
	 * @param length the length
	 * @return the range
	 */
	static AddressRange range(Address address, long length) {
		try {
			return new AddressRangeImpl(address, length);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Perform the action
	 * 
	 * @return the future for the action. Synchronous invocations can just return
	 *         {@link AsyncUtils#NIL}.
	 */
	public CompletableFuture<Void> execute();
}
