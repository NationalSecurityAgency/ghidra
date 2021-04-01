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
package ghidra.dbg.gadp.client;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetRegisterBank;

public interface GadpClientTargetRegisterBank extends GadpClientTargetObject, TargetRegisterBank {

	@Override
	default CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		getDelegate().assertValid();
		Map<String, byte[]> result = new LinkedHashMap<>();
		Map<String, byte[]> cache = getDelegate().getRegisterCache();
		Set<String> needed = new HashSet<>();
		for (String name : names) {
			byte[] value = cache.get(name);
			if (value == null) {
				needed.add(name);
			}
			// Allow null to reserve the position
			result.put(name, value);
		}
		if (needed.isEmpty()) {
			return CompletableFuture.completedFuture(result);
		}
		return getModel().sendChecked(Gadp.RegisterReadRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.addAllName(needed),
			Gadp.RegisterReadReply.getDefaultInstance()).thenApply(rep -> {
				for (Gadp.RegisterValue rv : rep.getValueList()) {
					result.put(rv.getName(), rv.getContent().toByteArray());
				}
				return result;
			});
	}

	@Override
	default CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		getDelegate().assertValid();
		// User may change values before completion (how rude)
		Map<String, byte[]> copy = Map.copyOf(values);
		Map<String, byte[]> cache = getDelegate().getRegisterCache();
		return getModel().sendChecked(Gadp.RegisterWriteRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.addAllValue(GadpValueUtils.makeRegisterValues(copy)),
			Gadp.RegisterWriteReply.getDefaultInstance()).thenAccept(rep -> {
				cache.putAll(copy);
			});
	}

	@Override
	default Map<String, byte[]> getCachedRegisters() {
		getDelegate().assertValid();
		Map<String, byte[]> cache = getDelegate().getRegisterCache();
		synchronized (cache) {
			return Map.copyOf(cache);
		}
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.REGISTER_UPDATE_EVENT)
	default void handleRegisterUpdateEvent(Gadp.EventNotification notification) {
		Gadp.RegisterUpdateEvent evt = notification.getRegisterUpdateEvent();
		Map<String, byte[]> updates = GadpValueUtils.getRegisterValueMap(evt.getValueList());
		DelegateGadpClientTargetObject delegate = getDelegate();
		delegate.getRegisterCache().putAll(updates);
		delegate.getListeners().fire.registersUpdated(this, updates);
	}
}
