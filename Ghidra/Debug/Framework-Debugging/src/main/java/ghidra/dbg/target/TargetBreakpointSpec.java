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
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
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
 */
@DebuggerTargetObjectIface("BreakpointSpec")
public interface TargetBreakpointSpec extends TargetObject {

	public enum TargetBreakpointKind {
		READ, WRITE, EXECUTE, SOFTWARE;
	}

	String CONTAINER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "container";
	String EXPRESSION_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "expression";
	String KINDS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "kinds";
	String ENABLED_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "enabled";

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
	public default TargetBreakpointContainer getContainer() {
		return getTypedAttributeNowByName(CONTAINER_ATTRIBUTE_NAME, TargetBreakpointContainer.class,
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
	 * Check if the breakpoint is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	@TargetAttributeType(name = ENABLED_ATTRIBUTE_NAME, required = true, hidden = true)
	public default boolean isEnabled() {
		return getTypedAttributeNowByName(ENABLED_ATTRIBUTE_NAME, Boolean.class, false);
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
	 * Disable all breakpoints resulting from this specification
	 */
	public CompletableFuture<Void> disable();

	/**
	 * Enable all breakpoints resulting from this specification
	 */
	public CompletableFuture<Void> enable();

	/**
	 * Enable or disable all breakpoints resulting from this specification
	 * 
	 * @param enabled true to enable, false to disable
	 */
	public default CompletableFuture<Void> toggle(boolean enabled) {
		return enabled ? enable() : disable();
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

	public interface TargetBreakpointSpecListener extends TargetObjectListener {
		default void breakpointToggled(TargetBreakpointSpec spec, boolean enabled) {
		}
	}
}
