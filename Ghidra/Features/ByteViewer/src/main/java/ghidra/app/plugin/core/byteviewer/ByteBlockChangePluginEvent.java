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
package ghidra.app.plugin.core.byteviewer;

import java.lang.ref.WeakReference;

import ghidra.app.plugin.core.format.ByteEditInfo;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.ToolEventName;
import ghidra.program.model.listing.Program;

/**
 * Plugin event for notification of byte block changes that the Byte Viewer
 * produces.
 */
@ToolEventName(ByteBlockChangePluginEvent.NAME) // this allows the event to be considered for tool connection
public final class ByteBlockChangePluginEvent extends PluginEvent {
	/**
	 * Name of this event.
	 */
	static final String NAME = "ByteBlockChange";

	private WeakReference<Program> programRef;
	private ByteEditInfo edit;

	/**
	 * Construct a new plugin event.
	 * @param src the name of the plugin that generated this event.
	 * @param edit byte block edit
	 * @param program the domain object for which the change affects
	 */
	public ByteBlockChangePluginEvent(String src, ByteEditInfo edit, Program program) {
		super(src, NAME);
		this.edit = edit;
		this.programRef = new WeakReference<>(program);
	}

	/**
	 * Returns the domain object that the change refers to.
	 */
	public Program getProgram() {
		return programRef.get();
	}

	/**
	 * Get the block for the change.
	 */
	public ByteEditInfo getByteEditInfo() {
		return edit;
	}

	@Override
	protected String getDetails() {
		return ("Address of Block Change==> " + edit.getBlockAddress() + ", offset ==> " +
			edit.getOffset());
	}

}
