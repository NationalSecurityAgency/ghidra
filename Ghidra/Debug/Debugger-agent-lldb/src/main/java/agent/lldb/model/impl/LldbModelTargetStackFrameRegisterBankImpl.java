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
package agent.lldb.model.impl;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.*;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface2.LldbModelTargetRegister;
import agent.lldb.model.iface2.LldbModelTargetStackFrameRegisterBank;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(
	name = "RegisterValueBank",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = LldbModelTargetStackFrameRegisterImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class LldbModelTargetStackFrameRegisterBankImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegisterBank {
	public static final String NAME = "Registers";

	protected static String keyValue(SBValue value) {
		return PathUtils.makeKey(value.GetName());
	}

	protected final LldbModelTargetStackFrameRegisterContainerImpl container;

	public LldbModelTargetStackFrameRegisterBankImpl(
			LldbModelTargetStackFrameRegisterContainerImpl container, SBValue val) {
		super(container.getModel(), container, val.GetName(), val, "StackFrameRegisterBank");
		this.container = container;

		changeAttributes(List.of(), List.of(), Map.of(
			DISPLAY_ATTRIBUTE_NAME, getName(),
			DESCRIPTIONS_ATTRIBUTE_NAME, container), "Initialized");

		requestElements(false);
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBValue val = (SBValue) getModelObject();
		val.GetDescription(stream);
		return stream.GetData();
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		SBValue bank = (SBValue) getModelObject();
		return getManager().listStackFrameRegisters(bank).thenAccept(regs -> {
			List<TargetObject> registers;
			synchronized (this) {
				registers = regs.values()
						.stream()
						.map(this::getTargetRegister)
						.collect(Collectors.toList());
			}
			setElements(registers, Map.of(), "Refreshed");
			if (!getCachedElements().isEmpty()) {
				readRegistersNamed(getCachedElements().keySet());
			}
		});
	}

	@Override
	public LldbModelTargetRegister getTargetRegister(SBValue register) {
		TargetObject targetObject = getMapObject(register);
		if (targetObject != null) {
			LldbModelTargetRegister targetRegister = (LldbModelTargetRegister) targetObject;
			targetRegister.setModelObject(register);
			return targetRegister;
		}
		return new LldbModelTargetStackFrameRegisterImpl(this, register);
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		if (state.equals(StateType.eStateStopped)) {
			requestElements(false).thenAccept(__ -> {
				readRegistersNamed(getCachedElements().keySet());
			});
		}
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		Map<String, byte[]> result = new HashMap<>();
		Map<String, TargetObject> elements = getCachedElements();
		for (String regname : names) {
			if (!elements.containsKey(regname)) {
				throw new DebuggerRegisterAccessException("No such register: " + regname);
			}
			LldbModelTargetStackFrameRegisterImpl register =
				(LldbModelTargetStackFrameRegisterImpl) elements.get(regname);
			byte[] bytes = register.getBytes();
			result.put(regname, bytes);
		}
		ListenerSet<DebuggerModelListener> listeners = getListeners();
		if (listeners != null) {
			//if (getName().contains("General")) {
			listeners.fire.registersUpdated(this, result);
			//}
		}
		return CompletableFuture.completedFuture(result);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		Map<String, TargetObject> elements = getCachedElements();
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			String regname = ent.getKey();
			LldbModelTargetStackFrameRegisterImpl reg =
				(LldbModelTargetStackFrameRegisterImpl) elements.get(regname);
			if (reg == null) {
				throw new DebuggerRegisterAccessException("No such register: " + regname);
			}
			BigInteger val = new BigInteger(1, ent.getValue());
			reg.getRegister().SetValueFromCString(val.toString());
		}
		getListeners().fire.registersUpdated(getProxy(), values);
		return AsyncUtils.NIL;
	}

	public Object getContainer() {
		return container;
	}

}
