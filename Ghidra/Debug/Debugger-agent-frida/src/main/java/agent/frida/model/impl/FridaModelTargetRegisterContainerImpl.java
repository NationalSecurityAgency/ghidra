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

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.manager.*;
import agent.frida.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "RegisterContainer",
	attributeResync = ResyncMode.ALWAYS,
	elements = { //
		@TargetElementType(type = FridaModelTargetRegisterImpl.class) //
	},
	attributes = {
		@TargetAttributeType(
			name = TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME,
			type = FridaModelTargetRegisterContainerImpl.class),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetRegisterContainerImpl
		extends FridaModelTargetObjectImpl
		implements FridaModelTargetRegisterContainerAndBank {
	public static final String NAME = "Registers";

	protected final FridaModelTargetThreadImpl thread;

	public FridaModelTargetRegisterContainerImpl(FridaModelTargetThreadImpl thread) {
		super(thread.getModel(), thread, NAME, "RegisterContainer");
		this.thread = thread;

		changeAttributes(List.of(), List.of(), Map.of(
			DISPLAY_ATTRIBUTE_NAME, getName(),
			DESCRIPTIONS_ATTRIBUTE_NAME, this), "Initialized");

		requestElements(RefreshBehavior.REFRESH_NEVER);
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		if (refresh.equals(RefreshBehavior.REFRESH_ALWAYS)) {
			broadcast().invalidateCacheRequested(this);
		}
		return getManager().listRegisters(thread.getThread()).thenAccept(registers -> {
			List<TargetObject> targetRegisters;
			synchronized (this) {
				targetRegisters = registers.entrySet()
						.stream()
						.map(this::getTargetRegister)
						.collect(Collectors.toList());
			}
			setElements(targetRegisters, Map.of(), "Refreshed");
			if (!getCachedElements().isEmpty()) {
				readRegistersNamed(getCachedElements().keySet());
			}
			//changeAttributes(List.of(), targetRegisters, Map.of(), "Refreshed");
		});
	}

	@SuppressWarnings("rawtypes")
	@Override
	public FridaModelTargetRegister getTargetRegister(Entry entry) {
		FridaValue val = new FridaValue((String) entry.getKey(), (String) entry.getValue());
		TargetObject targetObject = getMapObject(val);
		if (targetObject != null) {
			FridaModelTargetRegister targetRegister = (FridaModelTargetRegister) targetObject;
			targetRegister.setModelObject(val);
			return targetRegister;
		}
		return new FridaModelTargetRegisterImpl(this, val);
	}

	public void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		if (state.equals(FridaState.FRIDA_THREAD_STOPPED)) {
			requestAttributes(RefreshBehavior.REFRESH_NEVER).thenAccept(__ -> {
				for (Object attribute : getCachedAttributes().values()) {
					if (attribute instanceof FridaModelTargetRegisterBank) {
						FridaModelTargetRegisterBank bank =
							(FridaModelTargetRegisterBank) attribute;
						bank.threadStateChangedSpecific(state, reason);
					}
				}
			});
		}
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		Map<String, byte[]> result = new HashMap<>();
		Map<String, TargetObject> els = getCachedElements();
		for (String regname : names) {
			if (!elements.containsKey(regname)) {
				throw new DebuggerRegisterAccessException("No such register: " + regname);
			}
			FridaModelTargetRegisterImpl register =
				(FridaModelTargetRegisterImpl) els.get(regname);
			byte[] bytes = register.getBytes();
			result.put(regname, bytes);
		}
		//if (getName().contains("General")) {
		broadcast().registersUpdated(this, result);
		//}
		return CompletableFuture.completedFuture(result);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		Map<String, TargetObject> els = getCachedElements();
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			String regname = ent.getKey();
			FridaModelTargetRegisterImpl reg =
				(FridaModelTargetRegisterImpl) els.get(regname);
			if (reg == null) {
				throw new DebuggerRegisterAccessException("No such register: " + regname);
			}
			BigInteger val = new BigInteger(1, ent.getValue());
			reg.getRegister().setValue(val.toString());
		}
		broadcast().registersUpdated(getProxy(), values);
		return AsyncUtils.NIL;
	}

}
