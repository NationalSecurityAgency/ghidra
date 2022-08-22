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
package agent.frida.model.impl;

import java.lang.invoke.MethodHandles;
import java.util.*;

import agent.frida.frida.FridaThreadInfo;
import agent.frida.manager.FridaProcess;
import agent.frida.manager.FridaThread;
import agent.frida.manager.evt.FridaStateChangedEvent;
import agent.frida.manager.evt.FridaThreadSelectedEvent;
import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.app.plugin.core.debug.service.workflow.DebuggerWorkflowServicePlugin;
import ghidra.app.services.DebuggerBot;
import ghidra.app.services.DebuggerBotInfo;
import ghidra.dbg.*;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.util.DebuggerCallbackReorderer;
import ghidra.framework.options.annotation.HelpInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.datastruct.PrivatelyQueuedListener;

@DebuggerBotInfo( //
	description = "Link debugger to Frida", //
	details = "Listens for debuggers to add state to Frida.", //
	help = @HelpInfo(anchor = "link_frida"), //
	enabledByDefault = true //
)
public class FridaDebuggerBot implements DebuggerBot {
	private DebuggerWorkflowServicePlugin plugin;

	private FridaObjectListener listener = new FridaObjectListener();
	private List<DebuggerObjectModel> models = new ArrayList<>();
	private FridaModelImpl primary;
	private FridaManagerImpl manager;

	@Override
	public void enable(DebuggerWorkflowServicePlugin wp) {
		this.plugin = wp;
	}

	@Override
	public boolean isEnabled() {
		return plugin != null;
	}

	@Override
	public void disable() {
		plugin = null;
	}

	@Override
	public void modelAdded(DebuggerObjectModel model) {
		models.add(model);
		if (model instanceof FridaModelImpl) {
			primary = (FridaModelImpl) model;
			manager = primary.getManager();
		} else {
			model.addModelListener(getListener(), true);			
		}
	}

	@Override
	public void modelRemoved(DebuggerObjectModel model) {
		models.remove(model);
		if (model instanceof FridaModelImpl) {
			primary = null;
			manager = null;
		} else {
			model.removeModelListener(getListener());			
		}
	}
	
	public DebuggerModelListener getListener() {
		return listener.queue.in;
	}
	
	private Object findMatchingObject(TargetObject object) {
		if (object instanceof TargetProcess) {
			String id = Long.toHexString(((TargetProcess) object).getPid());
			return manager.getProcess(manager.getCurrentSession(), id);
		}
		if (object instanceof TargetThread) {
			TargetProcess tp = DebugModelConventions.ancestor(TargetProcess.class, object);
			Object found = findMatchingObject(tp);
			if (found != null) {
				FridaProcess process = (FridaProcess) found;
				String id = Long.toHexString(((TargetThread) object).getTid());
				return manager.getThread(process, id);
			}
		}
		return null;
	}
	
	class FridaObjectListener extends AnnotatedDebuggerAttributeListener {
		protected final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
		protected final PrivatelyQueuedListener<DebuggerModelListener> queue =
			new PrivatelyQueuedListener<>(DebuggerModelListener.class, "ObjectsProvider-EventQueue",
				reorderer);

		public FridaObjectListener() {
			super(MethodHandles.lookup());
		}

		@AttributeCallback(TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME)
		public void accessibilityChanged(TargetObject object, boolean accessible) {
			//System.err.println("accessibilityChanged: "+object+":"+accessible);
		}

		@Override
		public void consoleOutput(TargetObject console, Channel channel, String out) {
			//System.err.println("consoleOutput: "+out);
		}

		@AttributeCallback(TargetObject.DISPLAY_ATTRIBUTE_NAME)
		public void displayChanged(TargetObject object, String display) {
			//System.err.println("displayChanged: "+display);
		}

		@AttributeCallback(TargetObject.MODIFIED_ATTRIBUTE_NAME)
		public void modifiedChanged(TargetObject object, boolean modified) {
			//System.err.println("modifiedChanged: "+object);
		}

		@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
		public void executionStateChanged(TargetObject object, TargetExecutionState state) {
			if (primary != null) {
				Object localObject = findMatchingObject(object);
				if (localObject != null) {
					manager.processEvent(new FridaStateChangedEvent(localObject, state));
				}
			}
		}

		@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
		public void focusChanged(TargetObject object, TargetObject focused) {
			if (primary != null) {
				if (focused instanceof TargetThread) {
					Object localObject = findMatchingObject(focused);
					if (localObject != null) {
						FridaThreadInfo info = new FridaThreadInfo((FridaThread) localObject);
						manager.processEvent(new FridaThreadSelectedEvent(info));
					}				
				}
			}
		}

		@Override
		public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
			//System.err.println("memoryUpdated: "+address);
		}

		@Override
		public void memoryReadError(TargetObject memory, AddressRange range,
				DebuggerMemoryAccessException e) {
			//System.err.println("memoryReadError: "+range);
		}

		@AttributeCallback(TargetInterpreter.PROMPT_ATTRIBUTE_NAME)
		public void promptChanged(TargetObject interpreter, String prompt) {
			//System.err.println("promptChanged: "+prompt);
		}

		@Override
		public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
			//System.err.println("registersUpdated: "+bank);
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			//System.err.println("elementsChanged: "+parent);
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			super.attributesChanged(parent, removed, added);
			//System.err.println("attributesChanged: "+parent);
		}
	}

}
