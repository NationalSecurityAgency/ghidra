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

import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;

/**
 * Interface for address correlation algorithms that can generate an address mapping from one
 * set of program addresses to another.
 * <p>
 * This interface supplies a {@link #getPriority() priority} of {@link #DEFAULT_PRIORITY}.  
 * {@link DiscoverableAddressCorrelator discoverable} correlators can change this priority to be a
 * lower value to be run before the supplied system correlators.   Generally, the more specific or
 * restrictive a correlator, the earlier (higher priority) it should be.
 */
public interface AddressCorrelator {

	/**
	 * The default priority.  This applies to client-supplied {@link DiscoverableAddressCorrelator}s
	 */
	public static final int DEFAULT_PRIORITY = 500;

	/**
	 * A high priority (low number value) for correlators that should used before other correlators
	 */
	public static final int EARLY_PRIORITY = 100;

	/**
	 * A low priority (high number value) for correlators that should used after other correlators
	 */
	public static final int LATE_CHANCE_PRIORITY = 1000;

	/**
	 * A value used to raise or lower priorities.
	 */
	public static final int PRIORITY_OFFSET = 10;

	/**
	 * Returns an address mapping from one function to another.
	 * @param sourceFunction the source function.
	 * @param destinationFunction the destination function.
	 * @return an AddressCorrelation that represents a mapping of the addresses from the
	 * source function to the destination function.
	 */
	public AddressCorrelation correlate(Function sourceFunction, Function destinationFunction);

	/**
	 * Returns an address mapping from one piece of data to another.
	 * @param sourceData the source data.
	 * @param destinationData the destination data.
	 * @return an AddressCorrelation that represents a mapping of the addresses from the
	 * source data to the destination data.
	 */
	public AddressCorrelation correlate(Data sourceData, Data destinationData);

	/**
	 * Returns the current Option settings for this correlator.
	 * @return the current Option settings for this correlator.
	 */
	public ToolOptions getOptions();

	/**
	 * Sets the options to use for this correlator.
	 * @param options the options to use for this correlator.
	 */
	public void setOptions(ToolOptions options);

	/**
	 * Returns the options with the default settings for this correlator.
	 * @return  the options with the default settings for this correlator.
	 */
	public Options getDefaultOptions();

	/**
	 * Returns a number based on an arbitrary number scheme that dictates the order that correlators 
	 * should be used.   If a correlator returns a null value from one of the {@code correlate()}
	 * methods, then the next highest priority correlator will be called, and so on until a non-null
	 * correlation is found or all correlators have been called.
	 * <p>
	 * A lower number value is a higher priority.  See {@link #DEFAULT_PRIORITY}.
	 * 
	 * @return the priority
	 */
	public default int getPriority() {
		return DEFAULT_PRIORITY;
	}
}
