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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.*;

import ghidra.dbg.jdi.manager.JdiCause;
import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.jdi.model.iface1.JdiModelSelectableObject;
import ghidra.dbg.jdi.model.iface1.JdiModelTargetFocusScope;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(name = "StackFrame", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Object.class) })
public class JdiModelTargetStackFrame extends JdiModelTargetObjectImpl implements TargetStackFrame, //
		//TargetRegisterBank, //
		JdiEventsListenerAdapter, //
		JdiModelSelectableObject {

	public static String getUniqueId(int level) {
		return Integer.toString(level);
	}

	public static final String FUNC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "function";
	public static final String FROM_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "from"; // TODO

	protected final JdiModelTargetThread thread;
	protected JdiModelTargetLocalVariableContainer variables;
	protected JdiModelTargetValueMap values;
	protected JdiModelTargetObjectReference thisObject;
	protected JdiModelTargetLocation location;
	protected JdiModelTargetValueContainer arguments;

	protected StackFrame frame;
	protected Address pc;
	protected long level;

	public JdiModelTargetStackFrame(JdiModelTargetStack stack, JdiModelTargetThread thread,
			int level, StackFrame frame, boolean isElement) {
		super(stack, getUniqueId(level), frame, isElement);
		this.thread = thread;
		this.level = level;
		this.frame = frame;

		this.location = new JdiModelTargetLocation(this, frame.location(), false);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), // 
			LOCATION_ATTRIBUTE_NAME, location, //
			THREAD_ATTRIBUTE_NAME, thread.getName(), //
			PC_ATTRIBUTE_NAME, location.getAddress() //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		//this.arguments = new JdiModelTargetValueContainer(this, "Arguments", frame.getArgumentValues());

		ObjectReference obj = frame.thisObject();
		if (obj != null) {
			this.thisObject = (JdiModelTargetObjectReference) getInstance(obj);
			changeAttributes(List.of(), List.of(), Map.of( //
				THIS_OBJECT_ATTRIBUTE_NAME, thisObject //
			), "Initialized");
		}
		try {
			this.variables = new JdiModelTargetLocalVariableContainer(this, "Visible Variables",
				frame.visibleVariables());
			Map<LocalVariable, Value> map = frame.getValues(frame.visibleVariables());
			this.values = new JdiModelTargetValueMap(this, map);
			changeAttributes(List.of(), List.of( //
				variables, //
				values //
			), Map.of(), "Initialized");
		}
		catch (AbsentInformationException e) {
			// Ignore
		}

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public String getDisplay() {
		if (frame == null) {
			return super.getDisplay();
		}
		Location loc = null;
		try {
			loc = frame.location();
		}
		catch (InvalidStackFrameException e) {
			Msg.error(this, "Invalid stack frame");
		}
		return String.format("#%d %s", level, loc);
	}

	@Override
	public void threadSelected(ThreadReference eventThread, StackFrame eventFrame, JdiCause cause) {
		if (eventThread.equals(thread.thread) && eventFrame.equals(frame)) {
			((JdiModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		///return frame.select();
		return CompletableFuture.completedFuture(null);
	}

	public long getFrameLevel() {
		return level;
	}

	public void setFrameLevel(long level) {
		this.level = level;
	}

	public void setFrame(int level, StackFrame frame) {
		this.frame = frame;
		targetVM.setTargetObject(getUniqueId(level), frame, this);
		setModified(true);
	}

}
