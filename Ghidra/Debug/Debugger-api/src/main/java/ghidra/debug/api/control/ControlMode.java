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
package ghidra.debug.api.control;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.model.time.schedule.TraceSchedule.ScheduleForm;

/**
 * The control / state editing modes
 */
public abstract class ControlMode {

	// LATER: these should be instance fields of the plugin
	private static final List<ControlMode> ALL_INTERNAL = new ArrayList<>();
	public static final List<ControlMode> ALL = Collections.unmodifiableList(ALL_INTERNAL);

	public static final TargetControlMode TARGET = new TargetControlMode();
	public static final TraceControlMode TRACE = new TraceControlMode();
	public static final EmulatorControlMode EMULATOR = new EmulatorControlMode();

	public static final ControlMode DEFAULT = TARGET;

	public final String name;
	public Icon icon;
	public Icon iconEditable;
	public Icon iconUneditable;
	protected boolean isEditEnabled = false;

	protected ControlMode(String name, Icon iconEditable, Icon iconUneditable) {
		this.name = name;
		this.icon = iconUneditable;
		this.iconEditable = iconEditable;
		this.iconUneditable = iconUneditable;
		ALL_INTERNAL.add(this);
	}

	/**
	 * Check if the UI should keep its active snapshot in sync with the recorder's latest.
	 * 
	 * @return true to follow, false if not
	 */
	public abstract boolean followsPresent();

	/**
	 * Validate and/or adjust the given coordinates pre-activation
	 * 
	 * <p>
	 * This is called by the trace manager whenever there is a request to activate new coordinates.
	 * The control mode may adjust or reject the request before the trace manager actually performs
	 * and notifies the activation.
	 * 
	 * @param tool the tool for displaying status messages
	 * @param coordinates the requested coordinates
	 * @param cause the cause of the activation
	 * @return the effective coordinates or null to reject
	 */
	public DebuggerCoordinates validateCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates, ActivationCause cause) {
		if (!followsPresent() || cause != ActivationCause.USER) {
			return coordinates;
		}
		Target target = coordinates.getTarget();
		if (target == null) {
			return coordinates;
		}

		ScheduleForm form = coordinates.getObject() == null ? null
				: target.getSupportedTimeForm(coordinates.getObject(), coordinates.getSnap());
		if (form == null) {
			if (coordinates.getTime().isSnapOnly() &&
				coordinates.getSnap() == target.getSnap()) {
				return coordinates;
			}
			tool.setStatusInfo("""
					Cannot navigate time in %s mode. Switch to Trace or Emulate mode first."""
					.formatted(name),
				true);
			return null;
		}
		TraceSchedule norm = form.validate(coordinates.getTrace(), coordinates.getTime());
		if (norm != null) {
			return coordinates.time(norm);
		}

		String errMsg = switch (form) {
			case SNAP_ONLY -> """
					Target can only navigate to snapshots. Switch to Emulate mode first.""";
			case SNAP_EVT_STEPS -> """
					Target can only replay steps on the event thread. Switch to Emulate mode \
					first.""";
			case SNAP_ANY_STEPS -> """
					Target cannot perform p-code steps. Switch to Emulate mode first.""";
			case SNAP_ANY_STEPS_OPS -> throw new AssertionError();
		};

		tool.setStatusInfo(errMsg, true);
		return null;
	}

	protected TracePlatform platformFor(DebuggerCoordinates coordinates, Address address) {
		if (address.isRegisterAddress()) {
			return coordinates.getPlatform();
		}
		// This seems odd, but the memory UI components are displaying *host* addresses.
		return coordinates.getTrace().getPlatformManager().getHostPlatform();
	}

	/**
	 * Check if (broadly speaking) the mode supports editing the given coordinates
	 * 
	 * @param coordinates the coordinates to check
	 * @return true if editable, false if not
	 */
	public abstract boolean canEdit(DebuggerCoordinates coordinates);

	/**
	 * Check if the given variable can be edited under this mode
	 * 
	 * @param coordinates the coordinates to check
	 * @param address the address of the variable
	 * @param length the length of the variable, in bytes
	 * @return true if editable, false if not
	 */
	public abstract boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
			int length);

	/**
	 * Set the value of a variable
	 * 
	 * <p>
	 * Because the edit may be directed to a live target, the return value is a
	 * {@link CompletableFuture}. Additionally, when directed to the emulator, this allows the
	 * emulated state to be computed in the background.
	 * 
	 * @param tool the tool requesting the edit
	 * @param coordinates the coordinates of the edit
	 * @param address the address of the variable
	 * @param data the desired value of the variable
	 * @return a future which completes when the edit is finished
	 */
	public abstract CompletableFuture<Void> setVariable(PluginTool tool,
			DebuggerCoordinates coordinates, Address address, byte[] data);

	/**
	 * Check if this mode operates on target breakpoints or emulator breakpoints
	 * 
	 * @return false for target, true for emulator
	 */
	public abstract boolean useEmulatedBreakpoints();

	/**
	 * Check if this mode can be selected for the given coordinates
	 * 
	 * @param coordinates the current coordinates
	 * @return true to enable selection, false to disable
	 */
	public boolean isSelectable(DebuggerCoordinates coordinates) {
		return true;
	}

	/**
	 * If the mode can no longer be selected for new coordinates, get the new mode
	 * 
	 * <p>
	 * For example, if a target terminates while the mode is {@link #TARGET}, this specifies the
	 * new mode.
	 * 
	 * @param coordinates the new coordinates
	 * @return the new mode
	 */
	public ControlMode getAlternative(DebuggerCoordinates coordinates) {
		throw new AssertionError("INTERNAL: Non-selectable mode must provide alternative");
	}

	/**
	 * Find the new mode (or same) mode when activating the given coordinates
	 * 
	 * <p>
	 * The default is implemented using {@link #isSelectable(DebuggerCoordinates)} followed by
	 * {@link #getAlternative(DebuggerCoordinates)}.
	 * 
	 * @param coordinates the new coordinates
	 * @return the mode
	 */
	public ControlMode modeOnChange(DebuggerCoordinates coordinates) {
		if (isSelectable(coordinates)) {
			return this;
		}
		return getAlternative(coordinates);
	}

	/**
	 * Indicates whether this mode controls the target
	 * 
	 * @return true if it controls the target
	 */
	public abstract boolean isTarget();

	/**
	 * Toggles canEdit and associated icon
	 */
	public void toggleEditable() {
		isEditEnabled = !isEditEnabled;
		icon = isEditEnabled ? iconEditable : iconUneditable;
	}

	/**
	 * Does the mode support editing 
	 * 
	 * @return true if editable, false if not
	 */
	public boolean isEditable() {
		return isEditEnabled;
	}

	/**
	 * Set the mode as editable
	 * 
	 * @param editable is editable
	 */
	public void setEditable(boolean editable) {
		this.isEditEnabled = editable;
		icon = isEditEnabled ? iconEditable : iconUneditable;
	}

}
