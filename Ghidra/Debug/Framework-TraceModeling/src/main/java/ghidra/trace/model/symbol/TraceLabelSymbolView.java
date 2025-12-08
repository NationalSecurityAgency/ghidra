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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.exception.InvalidInputException;

/**
 * The label symbol view.
 */
public interface TraceLabelSymbolView extends TraceSymbolWithLocationView<TraceLabelSymbol> {

	/**
	 * Add a new label symbol.
	 * 
	 * @param lifespan the lifespan of the symbol
	 * @param address the address of the label
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	TraceLabelSymbol add(Lifespan lifespan, Address address, String name,
			TraceNamespaceSymbol parent, SourceType source) throws InvalidInputException;

	/**
	 * A shorthand for {@link #add(Lifespan, Address, String, TraceNamespaceSymbol, SourceType)}
	 * where lifespan is from the given snap on.
	 * 
	 * @param snap the starting snapshot key of the symbol
	 * @param address the address of the label
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	default TraceLabelSymbol create(long snap, Address address, String name,
			TraceNamespaceSymbol parent, SourceType source) throws InvalidInputException {
		return add(Lifespan.nowOn(snap), address, name, parent, source);
	}

	/**
	 * Add a new label symbol on a register for the given thread
	 * 
	 * @param platform the platform defining the register
	 * @param lifespan the lifespan of the symbol
	 * @param thread the thread
	 * @param register the register
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	default TraceLabelSymbol add(TracePlatform platform, Lifespan lifespan, TraceThread thread,
			Register register, String name, TraceNamespaceSymbol parent, SourceType source)
			throws InvalidInputException {
		TraceRegisterUtils.requireByteBound(register);
		AddressSpace space = TraceRegisterUtils.getRegisterAddressSpace(thread, 0, true);
		AddressRange range = platform.getConventionalRegisterRange(space, register);
		return add(lifespan, range.getMinAddress(), name, parent, source);
	}

	/**
	 * Add new new label symbol on a register for the given thread
	 * 
	 * @param lifespan the lifespan of the symbol
	 * @param thread the thread
	 * @param register the register
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	default TraceLabelSymbol add(Lifespan lifespan, TraceThread thread, Register register,
			String name, TraceNamespaceSymbol parent, SourceType source)
			throws InvalidInputException {
		return add(getTrace().getPlatformManager().getHostPlatform(), lifespan, thread, register,
			name, parent, source);
	}

	/**
	 * A shorthand for
	 * {@link #add(Lifespan, TraceThread, Register, String, TraceNamespaceSymbol, SourceType)} where
	 * lifespan is from the given snap on.
	 * 
	 * @param snap the starting snapshot key of the symbol
	 * @param thread the thread
	 * @param register the register
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	default TraceLabelSymbol create(long snap, TraceThread thread, Register register, String name,
			TraceNamespaceSymbol parent, SourceType source) throws InvalidInputException {
		return add(getTrace().getPlatformManager().getHostPlatform(), Lifespan.nowOn(snap), thread,
			register, name, parent, source);
	}

	/**
	 * A shorthand for
	 * {@link #add(TracePlatform, Lifespan, TraceThread, Register, String, TraceNamespaceSymbol, SourceType)}
	 * where lifespan is from the given snap on.
	 * 
	 * @param platform the platform defining the register
	 * @param snap the starting snapshot key of the symbol
	 * @param thread the thread
	 * @param register the register
	 * @param name the name of the label
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new label symbol
	 * @throws InvalidInputException if the name is not valid
	 */
	default TraceLabelSymbol create(TracePlatform platform, long snap, TraceThread thread,
			Register register, String name, TraceNamespaceSymbol parent, SourceType source)
			throws InvalidInputException {
		return add(platform, Lifespan.nowOn(snap), thread, register, name, parent, source);
	}
}
