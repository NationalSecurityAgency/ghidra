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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.*;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(name = "RegisterContainer", attributes = {
	@TargetAttributeType(type = Void.class) }, canonicalContainer = true)
public class GdbModelTargetRegisterContainer
		extends DefaultTargetObject<GdbModelTargetRegister, GdbModelTargetInferior>
		implements TargetRegisterContainer {
	public static final String NAME = "Registers";

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;

	protected final Map<Integer, GdbModelTargetRegister> registersByNumber =
		new WeakValueHashMap<>();

	public GdbModelTargetRegisterContainer(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "RegisterContainer");
		this.impl = inferior.impl;
		this.inferior = inferior.inferior;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (!refresh) {
			return completeUsingThreads(inferior.getKnownThreads());
		}
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		return inferior.listThreads().thenCompose(this::completeUsingThreads);
	}

	protected CompletableFuture<Void> completeUsingThreads(Map<Integer, GdbThread> byId) {
		if (byId.isEmpty()) {
			setElements(List.of(), "Refreshed (with no thread)");
			return AsyncUtils.NIL;
		}
		GdbThread thread = byId.values().iterator().next();
		return thread.listRegisters().thenAccept(regs -> {
			List<GdbModelTargetRegister> registers;
			synchronized (this) { // calls getTargetRegister
				// No stale garbage. New architecture may re-use numbers, so clear cache out!
				registersByNumber.clear();
				registers = regs.stream().map(this::getTargetRegister).collect(Collectors.toList());
			}
			// TODO: Equality only considers paths, i.e., name. If a name is re-used, the old
			// stuff has to go. Not sure how to accomplish that, yet.
			setElements(registers, "Refreshed");
		});
	}

	protected synchronized GdbModelTargetRegister getTargetRegister(GdbRegister register) {
		return registersByNumber.computeIfAbsent(register.getNumber(),
			n -> new GdbModelTargetRegister(this, register));
	}

	public CompletableFuture<Void> refreshInternal() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return doRefresh().exceptionally(ex -> {
			Msg.error(this, "Problem refreshing inferior's register descriptions", ex);
			return null;
		});
	}

	public void stateChanged(GdbStateChangeRecord sco) {
		requestElements(false).thenAccept(__ -> {
			for (GdbModelTargetRegister modelRegister : registersByNumber.values()) {
				modelRegister.stateChanged(sco);
			}
		});
	}

}
