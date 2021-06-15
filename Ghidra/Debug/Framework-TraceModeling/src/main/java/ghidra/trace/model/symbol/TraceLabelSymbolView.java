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
package ghidra.trace.model.symbol;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.InvalidInputException;

public interface TraceLabelSymbolView extends TraceSymbolWithLocationView<TraceLabelSymbol> {

	TraceLabelSymbol add(Range<Long> lifespan, TraceThread thread, Address address, String name,
			TraceNamespaceSymbol parent, SourceType source) throws InvalidInputException;

	default TraceLabelSymbol create(long snap, TraceThread thread, Address address, String name,
			TraceNamespaceSymbol parent, SourceType source) throws InvalidInputException {
		return add(DBTraceUtils.toRange(snap), thread, address, name, parent, source);
	}
}
