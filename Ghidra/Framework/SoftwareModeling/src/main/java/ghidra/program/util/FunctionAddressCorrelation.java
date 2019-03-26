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
package ghidra.program.util;

import ghidra.program.model.listing.Function;

/**
 * This is the interface for a correlator that associates instructions from one function to
 * instructions from another function. Given an address from one function it determines the matching
 * address in the other function if possible.
 */
public interface FunctionAddressCorrelation extends ListingAddressCorrelation {

	/**
	 * Gets the first function for this address correlator.
	 * @return the first function.
	 */
	public Function getFirstFunction();

	/**
	 * Gets the second function for this address correlator.
	 * @return the second function.
	 */
	public Function getSecondFunction();

}
