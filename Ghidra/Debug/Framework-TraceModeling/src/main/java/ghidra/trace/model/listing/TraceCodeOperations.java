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
package ghidra.trace.model.listing;

public interface TraceCodeOperations {
	/**
	 * Get a view of all the code units in the listing
	 * 
	 * @return the code-units view
	 */
	TraceCodeUnitsView codeUnits();

	/**
	 * Get a view of only the instructions in the listing
	 * 
	 * This view supports the creation of new instruction units. This view also supports clearing.
	 * 
	 * @return the instruction-units view
	 */
	TraceInstructionsView instructions();

	/**
	 * Get a view of only the data units (defined and undefined) in the listing
	 * 
	 * @return the data-units view
	 */
	TraceDataView data();

	/**
	 * Get a view of only the defined data units in the listing
	 * 
	 * This view supports the creation of new data units. This view also supports clearing.
	 * 
	 * @return the defined-data-units view
	 */
	TraceDefinedDataView definedData();

	/**
	 * Get a view of only the undefined data units in the listing
	 * 
	 * @return return the undefined-data-units view
	 */
	TraceUndefinedDataView undefinedData();

	/**
	 * Get a view of only the defined units (data and instructions) in the listing
	 * 
	 * This view support clearing.
	 * 
	 * @return the defined-units-view
	 */
	TraceDefinedUnitsView definedUnits();
}
