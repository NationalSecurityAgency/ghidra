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
package ghidra.dbg.target;

import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.CollectionUtils.AbstractEmptySet;
import ghidra.dbg.util.CollectionUtils.AbstractNSet;
import ghidra.program.model.address.*;

/**
 * A container for breakpoint specifications and/or locations
 * 
 * <p>
 * This interface provides for the placement (creation) of breakpoints and as a listening point for
 * breakpoint events. Typically, it is implemented by an object whose elements are breakpoints.
 * 
 * <p>
 * TODO: Rename this to {@code TargetBreakpointOperations}. Conventionally, it is a container of
 * breakpoints, but it doesn't technically have to be. A client searching for the breakpoint
 * (location) container should use {@link TargetObjectSchema#searchForCanonicalContainer(Class)},
 * passing {@link TargetBreakpointLocation}. A client seeking to place breakpoints should use
 * {@link TargetObjectSchema#searchForSuitable(Class, java.util.List)}, passing
 * {@link TargetBreakpointSpecContainer}.
 */
@DebuggerTargetObjectIface("BreakpointSpecContainer")
public interface TargetBreakpointSpecContainer extends TargetObject {

	String SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "supported_breakpoint_kinds";

	public interface TargetBreakpointKindSet extends Set<TargetBreakpointKind> {
		public static class EmptyTargetBreakpointKindSet
				extends AbstractEmptySet<TargetBreakpointKind> implements TargetBreakpointKindSet {
			// Nothing
		}

		public static class ImmutableTargetBreakpointKindSet
				extends AbstractNSet<TargetBreakpointKind>
				implements TargetBreakpointKindSet {

			public ImmutableTargetBreakpointKindSet(TargetBreakpointKind... kinds) {
				super(kinds);
			}

			public ImmutableTargetBreakpointKindSet(Set<TargetBreakpointKind> set) {
				super(set);
			}
		}

		TargetBreakpointKindSet EMPTY = new EmptyTargetBreakpointKindSet();

		public static TargetBreakpointKindSet of() {
			return EMPTY;
		}

		public static TargetBreakpointKindSet of(TargetBreakpointKind... kinds) {
			return new ImmutableTargetBreakpointKindSet(kinds);
		}

		public static TargetBreakpointKindSet copyOf(Set<TargetBreakpointKind> set) {
			return new ImmutableTargetBreakpointKindSet(set);
		}
	}

	/**
	 * Get the kinds of supported breakpoints
	 * 
	 * <p>
	 * Different debuggers have differing vocabularies of breakpoints, and may only support a subset
	 * of those recognized by Ghidra. This attribute describes those supported.
	 * 
	 * @return the set of supported kinds
	 */
	@TargetAttributeType(
		name = SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME,
		required = true,
		hidden = true)
	public default TargetBreakpointKindSet getSupportedBreakpointKinds() {
		return getTypedAttributeNowByName(SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME,
			TargetBreakpointKindSet.class, TargetBreakpointKindSet.of());
	}

	/**
	 * Specify a breakpoint having the given expression and kinds
	 * 
	 * <p>
	 * Certain combinations of kinds and expression may not be reasonable. In those cases, the
	 * debugger may choose to reject, split, and/or adjust the request.
	 * 
	 * @param expression the expression, in the native debugger's syntax
	 * @param kinds the desired set of kinds
	 * @return a future which completes when the request is processed
	 */
	public CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds);

	/**
	 * Specify a breakpoint having the given range and kinds
	 * 
	 * <p>
	 * Certain combinations of kinds and range may not be reasonable. In those cases, the debugger
	 * may choose to reject, split, and/or adjust the request.
	 * 
	 * @param range the range of addresses for the breakpoint
	 * @param kinds the desired set of kinds
	 * @return a future which completes when the request is processed
	 */
	public CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds);

	/**
	 * Specify a breakpoint having the given address and kinds
	 * 
	 * <p>
	 * Certain combinations of kinds may not be reasonable. In those cases, the debugger may choose
	 * to reject, split, and/or adjust the request.
	 * 
	 * @param expression the expression, in the native debugger's syntax
	 * @param kinds the desired set of kinds
	 * @return a future which completes when the request is processed
	 */
	public default CompletableFuture<Void> placeBreakpoint(Address address,
			Set<TargetBreakpointKind> kinds) {
		return placeBreakpoint(new AddressRangeImpl(address, address), kinds);
	}
}
