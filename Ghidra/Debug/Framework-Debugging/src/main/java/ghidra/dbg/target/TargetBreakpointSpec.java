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

import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * The specification of a breakpoint applied to a target object
 * 
 * <p>
 * Note that a single specification could result in several locations, or no locations at all. For
 * example, a breakpoint placed on a function within a module which has not been loaded ("pending"
 * in GDB's nomenclature), will not have any location. On the other hand, a breakpoint expressed by
 * line number in a C++ template or a C macro could resolve to many addresses. The children of this
 * object include the resolved {@link TargetBreakpointLocation}s. If the debugger does not share
 * this same concept, then its breakpoints should implement both the specification and the location;
 * the specification need not have any children.
 * 
 * <p>
 * This object extends {@link TargetTogglable} for a transitional period only. Implementations whose
 * breakpoint specifications can be toggled should declare this interface explicitly. When the
 * specification is user togglable, toggling it should effectively toggle all locations -- whether
 * or not the locations are user togglable.
 */
@DebuggerTargetObjectIface("BreakpointSpec")
public interface TargetBreakpointSpec extends TargetObject, /*@Transitional*/ TargetTogglable {

	public enum TargetBreakpointKind {
		/**
		 * A read breakpoint, likely implemented in hardware
		 */
		READ,
		/**
		 * A write breakpoint, likely implemented in hardware
		 */
		WRITE,
		/**
		 * An execution breakpoint implemented in hardware, i.e., without modifying the target's
		 * program memory
		 */
		HW_EXECUTE,
		/**
		 * An execution breakpoint implemented in software, i.e., by modifying the target's program
		 * memory
		 */
		SW_EXECUTE;
	}

	String CONTAINER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "container";
	String EXPRESSION_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "expression";
	String KINDS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "kinds";

	/**
	 * Get the container of this breakpoint.
	 * 
	 * <p>
	 * While it is most common for a breakpoint specification to be an immediate child of its
	 * container, that is not necessarily the case. This method is a reliable and type-safe means of
	 * obtaining that container.
	 * 
	 * @return a reference to the container
	 */
	@TargetAttributeType(name = CONTAINER_ATTRIBUTE_NAME, required = true, hidden = true)
	public default TargetBreakpointSpecContainer getContainer() {
		return getTypedAttributeNowByName(CONTAINER_ATTRIBUTE_NAME,
			TargetBreakpointSpecContainer.class,
			null);
	}

	/**
	 * Get the user-specified expression describing the breakpoint
	 * 
	 * <p>
	 * Depending on the underlying debugger, this could be a variety of forms, e.g., source file and
	 * line number, module and symbol, address.
	 * 
	 * @return the expression
	 */
	@TargetAttributeType(name = EXPRESSION_ATTRIBUTE_NAME, required = true, hidden = true)
	public default String getExpression() {
		return getTypedAttributeNowByName(EXPRESSION_ATTRIBUTE_NAME, String.class, "");
	}

	/**
	 * Get the kinds of breakpoint
	 * 
	 * @return the kinds
	 */
	@TargetAttributeType(name = KINDS_ATTRIBUTE_NAME, required = true, hidden = true)
	public default TargetBreakpointKindSet getKinds() {
		return getTypedAttributeNowByName(KINDS_ATTRIBUTE_NAME, TargetBreakpointKindSet.class,
			TargetBreakpointKindSet.EMPTY);
	}

	/**
	 * Add an action to execute locally when this breakpoint traps execution
	 * 
	 * <p>
	 * Note that unlike other parts of this API, the breakpoint specification implementation must
	 * keep a strong reference to its actions. Adding the same action a second time may cause
	 * undefined behavior. Ideally, the implementation would at least detect this condition and log
	 * a warning.
	 * 
	 * @param action the action to execute
	 */
	public void addAction(TargetBreakpointAction action);

	/**
	 * Remove an action from this breakpoint
	 * 
	 * @param action the action to remove
	 */
	public void removeAction(TargetBreakpointAction action);

	public interface TargetBreakpointAction {
		/**
		 * An effective breakpoint from this specification trapped execution
		 * 
		 * @param spec the breakpoint specification
		 * @param trapped the object whose execution was trapped
		 * @param frame the innermost stack frame, if available, of the trapped object
		 * @param breakpoint the effective breakpoint that actually trapped execution
		 */
		void breakpointHit(TargetBreakpointSpec spec, TargetObject trapped, TargetStackFrame frame,
				TargetBreakpointLocation breakpoint);
	}

	/**
	 * Get the locations created by this specification.
	 * 
	 * <p>
	 * While it is most common for locations to be immediate children of the specification, that is
	 * not necessarily the case.
	 * 
	 * @implNote By default, this method collects all successor locations ordered by path.
	 *           Overriding that behavior is not yet supported.
	 * @return the effective breakpoints
	 */
	public default CompletableFuture< //
			? extends Collection<? extends TargetBreakpointLocation>> getLocations() {
		if (this instanceof TargetBreakpointLocation) {
			return CompletableFuture.completedFuture(List.of((TargetBreakpointLocation) this));
		}
		return DebugModelConventions.collectSuccessors(this, TargetBreakpointLocation.class);
	}

	// TODO: Make hit count part of the common interface?
}
