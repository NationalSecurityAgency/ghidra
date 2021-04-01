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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.Location;

import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "TargetRegisterContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetRegister.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetRegisterContainer extends JdiModelTargetObjectImpl
		implements TargetRegisterBank, TargetRegisterContainer {

	private final Map<String, JdiModelTargetRegister> registersByName = new HashMap<>();

	private JdiModelTargetThread thread;
	private JdiModelTargetRegister pc;
	private JdiModelTargetRegister sp;
	private JdiModelTargetRegister retAddr;

	public JdiModelTargetRegisterContainer(JdiModelTargetThread thread) {
		super(thread, "Registers");
		this.thread = thread;
		this.pc = new JdiModelTargetRegister(this, "PC", true);
		this.sp = new JdiModelTargetRegister(this, "SP", true);
		this.retAddr = new JdiModelTargetRegister(this, "return_address", true);
		registersByName.put(pc.getName(), pc);
		registersByName.put(sp.getName(), sp);
		registersByName.put(retAddr.getName(), retAddr);
		changeElements(List.of(), List.of( //
			pc, //
			sp, //
			retAddr //
		), "Initialized");
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getName(), //
			DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
	}

	/*
	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
	
		changeAttributes(List.of(), List.of( //
			pc, //
			sp, //
			retAddr //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getName(), //
			DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
	
		return CompletableFuture.completedFuture(null);
	}
	*/

	protected synchronized JdiModelTargetRegister getTargetRegister(String rname) {
		return registersByName.computeIfAbsent(rname,
			n -> new JdiModelTargetRegister(this, rname, true));
	}

	public synchronized JdiModelTargetRegister getTargetMethodIfPresent(String rname) {
		return registersByName.get(rname);
	}

	@Override

	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		Map<String, byte[]> map = new HashMap<>();
		Location pcLoc = thread.getLocation();
		Location spLoc = null;
		Location raLoc = null;

		JdiModelTargetStackFrame targetFrame = thread.stack.getTargetFrame(1);
		if (targetFrame != null) {
			JdiModelTargetLocation loc = targetFrame.location;
			if (loc != null) {
				raLoc = loc.location;
			}
		}

		if (pcLoc != null) {
			byte[] bytes = pc.readRegister(pcLoc);
			map.put(pc.getIndex(), bytes);
		}
		//if (spLoc != null) {
		//	byte[] bytes = sp.readRegister(spLoc);
		//	map.put(sp.getIndex(), bytes);
		//}
		if (raLoc != null) {
			byte[] bytes = retAddr.readRegister(raLoc);
			map.put(retAddr.getIndex(), bytes);
		}
		if (!map.isEmpty()) {
			listeners.fire.registersUpdated(this, map);
		}
		return CompletableFuture.completedFuture(map);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		// TODO Auto-generated method stub
		return null;
	}

	public void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}

	protected CompletableFuture<?> update() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return fetchElements(true).exceptionally(e -> {
			Msg.error(this, "Could not update registers " + this + " on STOPPED");
			return null;
		});
	}
}
