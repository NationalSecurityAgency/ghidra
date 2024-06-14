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
package ghidra.features.base.codecompare.model;

import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Duo.Side;

/**
 * Allows subscribers to register for {@link FunctionComparisonModel function
 * comparison model} changes
 */
public interface FunctionComparisonModelListener {

	/**
	 * Notification that the selected function changed on one side or the other.
	 * @param side the side whose selected function changed
	 * @param function the new selected function for the given side
	 */
	public void activeFunctionChanged(Side side, Function function);

	/**
	 * Notification that the set of functions on at least one side changed. The selected functions
	 * on either side may have also changed.
	 */
	public void modelDataChanged();
}
