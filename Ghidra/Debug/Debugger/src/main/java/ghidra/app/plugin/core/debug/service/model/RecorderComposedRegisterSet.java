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
package ghidra.app.plugin.core.debug.service.model;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncLazyMap;
import ghidra.async.AsyncLazyMap.KeyedFuture;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.util.Msg;
import ghidra.util.TriConsumer;

public class RecorderComposedRegisterSet {

	private DefaultTraceRecorder recorder;

	protected final TriConsumer<Boolean, Boolean, Void> listenerRegAccChanged =
		this::registerAccessibilityChanged;

	protected void registerAccessibilityChanged(boolean old, boolean acc,
			Void __) {
		recorder.getListeners().fire.registerAccessibilityChanged(recorder);
	}

	protected final AsyncLazyMap<TargetRegisterBank, AllRequiredAccess> accessibilityByRegBank =
		new AsyncLazyMap<>(new HashMap<>(), this::fetchRegAccessibility) {
			public AllRequiredAccess remove(TargetRegisterBank key) {
				AllRequiredAccess acc = super.remove(key);
				if (acc != null) {
					acc.removeChangeListener(listenerRegAccChanged);
				}
				return acc;
			}
		};

	protected CompletableFuture<AllRequiredAccess> fetchRegAccessibility(
			TargetRegisterBank bank) {
		return DebugModelConventions.trackAccessibility(bank).thenApply(acc -> {
			acc.addChangeListener(listenerRegAccChanged);
			return acc;
		});
	}

	public RecorderComposedRegisterSet(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
	}

	public void updateRegisters(TargetRegisterBank newRegs, TargetRegisterBank oldRegs) {
		synchronized (accessibilityByRegBank) {
			if (oldRegs != null) {
				accessibilityByRegBank.remove(oldRegs);
			}
			accessibilityByRegBank.get(newRegs).exceptionally(e -> {
				e = AsyncUtils.unwrapThrowable(e);
				Msg.error(this, "Could not track register accessibility: " + e.getMessage());
				return null;
			});
		}
	}

	public boolean checkRegistersRemoved(Map<Integer, TargetRegisterBank> regs,
			TargetObject invalid) {
		synchronized (accessibilityByRegBank) {
			if (regs.values().remove(invalid)) {
				accessibilityByRegBank.remove((TargetRegisterBank) invalid);
				return true;
			}
			return false;
		}
	}

	public boolean isRegisterBankAccessible(TargetRegisterBank bank) {
		if (bank == null) {
			return false;
		}
		synchronized (accessibilityByRegBank) {
			KeyedFuture<?, AllRequiredAccess> future = accessibilityByRegBank.get(bank);
			if (future == null) {
				return false;
			}
			AllRequiredAccess acc = future.getNow(null);
			if (acc == null) {
				return false;
			}
			return acc.get();
		}
	}
}
