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

import java.util.List;

import com.google.common.collect.Range;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.util.exception.InvalidInputException;

public interface TraceFunctionSymbolView extends TraceSymbolWithLocationView<TraceFunctionSymbol> {

	TraceFunctionSymbol add(Range<Long> lifespan, Address entryPoint, AddressSetView body,
			String name, TraceFunctionSymbol thunked, TraceNamespaceSymbol parent,
			SourceType source) throws InvalidInputException, OverlappingFunctionException;

	default TraceFunctionSymbol create(long snap, Address entryPoint, AddressSetView body,
			String name, TraceFunctionSymbol thunked, TraceNamespaceSymbol parent,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return add(DBTraceUtils.toRange(snap), entryPoint, body, name, thunked, parent, source);
	}

	PrototypeModel[] getCallingConventions();

	List<String> getCallingConventionNames();

	PrototypeModel getDefaultCallingConvention();

	PrototypeModel getCallingConvention(String name);
}
