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
package agent.lldb.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.lldb.lldb.DebugClient;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetDeletable;
import ghidra.util.datastruct.ListenerSet;

public interface LldbModelTargetBreakpointSpec extends //
		LldbModelTargetObject, //
		TargetBreakpointSpec, //
		TargetDeletable {

	String BPT_ACCESS_ATTRIBUTE_NAME = "Access";
	String BPT_DISP_ATTRIBUTE_NAME = "Enabled";
	String BPT_VALID_ATTRIBUTE_NAME = "Valid";
	String BPT_TIMES_ATTRIBUTE_NAME = "Count";
	String BPT_TYPE_ATTRIBUTE_NAME = "Type";
	String BPT_INDEX_ATTRIBUTE_NAME = "Id";

	@Override
	public default CompletableFuture<Void> delete() {
		return getModel().gateFuture(getManager().deleteBreakpoints(getId()));
	}

	@Override
	public default CompletableFuture<Void> disable() {
		setEnabled(false, "Disabled");
		return getModel().gateFuture(getManager().disableBreakpoints(getId()));
	}

	@Override
	public default CompletableFuture<Void> enable() {
		setEnabled(true, "Enabled");
		return getModel().gateFuture(getManager().enableBreakpoints(getId()));
	}

	public default String getId() {
		return DebugClient.getId(getModelObject());
	}

	@Override
	public TargetBreakpointKindSet getKinds();

	public void updateInfo(Object info, String reason);

	/**
	 * Update the enabled field
	 * 
	 * This does not actually toggle the breakpoint. It just updates the field and calls the proper
	 * listeners. To actually toggle the breakpoint, use {@link #toggle(boolean)} instead, which if
	 * effective, should eventually cause this method to be called.
	 * 
	 * @param enabled true if enabled, false if disabled
	 * @param reason a description of the cause (not really used, yet)
	 */
	public void setEnabled(boolean enabled, String reason);

	public ListenerSet<TargetBreakpointAction> getActions();

	@Override
	public default void addAction(TargetBreakpointAction action) {
		getActions().add(action);
	}

	@Override
	public default void removeAction(TargetBreakpointAction action) {
		getActions().remove(action);
	}

	public default void breakpointHit() {
		LldbModelTargetThread targetThread =
			getParentProcess().getThreads().getTargetThread(getManager().getEventThread());
		getActions().fire.breakpointHit((LldbModelTargetBreakpointSpec) getProxy(), targetThread,
			null, findLocation(targetThread));
	}

	public LldbModelTargetBreakpointLocation findLocation(Object object);

}
