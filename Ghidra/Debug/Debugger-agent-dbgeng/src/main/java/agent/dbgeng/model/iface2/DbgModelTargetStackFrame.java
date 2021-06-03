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
package agent.dbgeng.model.iface2;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgEventsListenerAdapter;
import agent.dbgeng.manager.DbgStackFrame;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public interface DbgModelTargetStackFrame extends //
		//DbgModelTargetObject,
		TargetStackFrame, //
		DbgEventsListenerAdapter, //
		DbgModelSelectableObject {

	public static final String FUNC_ATTRIBUTE_NAME = "function";
	public static final String FUNC_TABLE_ENTRY_ATTRIBUTE_NAME = "Table Entry";
	public static final String FRAME_OFFSET_ATTRIBUTE_NAME = "Frame Offset";
	public static final String INST_OFFSET_ATTRIBUTE_NAME = "Inst. Offset";
	public static final String RETURN_OFFSET_ATTRIBUTE_NAME = "Return Offset";
	public static final String STACK_OFFSET_ATTRIBUTE_NAME = "Stack Offset";
	public static final String VIRTUAL_ATTRIBUTE_NAME = "Virtual";
	public static final String PARAM0_ATTRIBUTE_NAME = "Param[0]";
	public static final String PARAM1_ATTRIBUTE_NAME = "Param[1]";
	public static final String PARAM2_ATTRIBUTE_NAME = "Param[2]";
	public static final String PARAM3_ATTRIBUTE_NAME = "Param[3]";
	public static final String FROM_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "from"; // TODO

	@Override
	public default CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		DbgThreadImpl thread = manager.getCurrentThread();
		String name = this.getName();
		String stripped = name.substring(1, name.length() - 1);
		int index = Integer.decode(stripped);
		return manager.setActiveFrame(thread, index);
	}

	@Override
	public default CompletableFuture<Void> init(Map<String, Object> map) {
		AddressSpace space = getModel().getAddressSpace("ram");
		return requestNativeAttributes().thenCompose(attrs -> {
			if (attrs == null) {
				return AsyncUtils.NIL;
			}
			map.putAll(attrs);
			DbgModelTargetObject attributes = (DbgModelTargetObject) attrs.get("Attributes");
			if (attributes == null) {
				return AsyncUtils.NIL;
			}
			return attributes.requestAugmentedAttributes().thenCompose(ax -> {
				if (!isValid()) {
					return AsyncUtils.NIL;
				}
				Map<String, ?> subattrs = attributes.getCachedAttributes();
				DbgModelTargetObject frameNumber =
					(DbgModelTargetObject) subattrs.get("FrameNumber");
				if (frameNumber == null) {
					return AsyncUtils.NIL;
				}
				return frameNumber.requestAugmentedAttributes().thenCompose(bx -> {
					if (!isValid()) {
						return AsyncUtils.NIL;
					}
					Object noval = frameNumber.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
					String nostr = noval.toString();
					DbgModelTargetObject instructionOffset =
						(DbgModelTargetObject) subattrs.get("InstructionOffset");
					if (instructionOffset == null) {
						return AsyncUtils.NIL;
					}
					return instructionOffset.requestAugmentedAttributes().thenAccept(cx -> {
						if (!isValid()) {
							return;
						}
						String oldval = (String) getCachedAttribute(DISPLAY_ATTRIBUTE_NAME);
						Object pcval = instructionOffset.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
						String pcstr = pcval.toString();
						long pc = Long.parseUnsignedLong(pcstr, 16);
						map.put(PC_ATTRIBUTE_NAME, space.getAddress(pc));
						String display = String.format("#%s 0x%s", nostr, pcstr);
						map.put(DISPLAY_ATTRIBUTE_NAME, display);
						setModified(map, !display.equals(oldval));
					});
				});
			});
		});
	}

	public void setFrame(DbgStackFrame frame);

	public TargetObject getThread();

	public Address getPC();

	public DbgModelTargetProcess getProcess();

}
