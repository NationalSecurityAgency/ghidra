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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugClient.DebugOutputFlags;
import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.dbgeng.DebugSessionRecord;
import agent.dbgeng.manager.DbgEventsListenerAdapter;
import agent.dbgeng.manager.DbgSession;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface1.DbgModelTargetAccessConditioned;
import agent.dbgeng.model.iface1.DbgModelTargetExecutionStateful;
import agent.dbgeng.model.iface1.DbgModelTargetInterpreter;
import agent.dbgeng.model.iface1.DbgModelTargetInterruptible;
import agent.dbgeng.model.iface1.DbgModelTargetResumable;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetConsole;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.util.PathUtils;

public interface DbgModelTargetSession extends //
		DbgModelTargetAccessConditioned, //
		//DbgModelTargetFocusScope, //
		DbgModelTargetExecutionStateful, //
		DbgModelTargetInterpreter, //
		DbgModelTargetInterruptible, //
		DbgModelTargetResumable, //
		DbgEventsListenerAdapter, //
		DbgModelSelectableObject, //
		TargetAggregate {

	DbgModelTargetProcessContainer getProcesses();

	public default DbgSession getSession() {
		return getSession(true);
	}

	public default DbgSession getSession(boolean fire) {
		DbgManagerImpl manager = getManager();
		try {
			String index = PathUtils.parseIndex(getName());
			Integer sid = Integer.decode(index);
			DebugSessionId id = new DebugSessionRecord(sid);
			return manager.getSessionComputeIfAbsent(id, fire);
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentSession();
		}
	}

	@Override
	public default void consoleOutput(String output, int mask) {

		if (!isValid()) {
			return;
		}
		Channel chan = TargetConsole.Channel.STDOUT;
		if (((mask & DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) //
				== DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) || //
			((mask & DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue()) // 
					== DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue())) {
			chan = TargetConsole.Channel.STDERR;
		}
		if (output.contains("loaded *kernel* extension dll for usermode")) {
			return;
		}
		if (!isValid()) {
			return;
		}
		broadcast().consoleOutput(getProxy(), chan, output);
	}

	@Override
	public default void promptChanged(String prompt) {
		changeAttributes(List.of(), Map.of( //
			PROMPT_ATTRIBUTE_NAME, prompt //
		), "Refreshed");
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		DbgSession session = getSession();
		if (session == null) {
			session = manager.getEventSession();
		}
		return manager.setActiveSession(session);
	}
}
