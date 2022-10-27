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
package ghidra.trace.database.listing;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.*;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The implementation of {@link TraceCodeManager#definedData()}
 */
public class DBTraceInstructionsMemoryView
		extends AbstractBaseDBTraceCodeUnitsMemoryView<DBTraceInstruction, DBTraceInstructionsView>
		implements TraceInstructionsView, InternalTraceBaseDefinedUnitsView<TraceInstruction> {

	/**
	 * Construct the view
	 * 
	 * @param manager the manager
	 */
	public DBTraceInstructionsMemoryView(DBTraceCodeManager manager) {
		super(manager);
	}

	@Override
	protected DBTraceInstructionsView getView(DBTraceCodeSpace space) {
		return space.instructions;
	}

	@Override
	public void clear(Lifespan span, AddressRange range, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		delegateDeleteV(range.getAddressSpace(), m -> m.clear(span, range, clearContext, monitor));
	}

	@Override
	public DBTraceInstruction create(Lifespan lifespan, Address address,
			TracePlatform platform, InstructionPrototype prototype,
			ProcessorContextView context) throws CodeUnitInsertionException {
		return delegateWrite(address.getAddressSpace(),
			m -> m.create(lifespan, address, platform, prototype, context));
	}

	@Override
	public AddressSetView addInstructionSet(Lifespan lifespan, TracePlatform platform,
			InstructionSet instructionSet, boolean overwrite) {
		InstructionSet mappedSet = platform.mapGuestInstructionAddressesToHost(instructionSet);

		Map<AddressSpace, InstructionSet> breakDown = new HashMap<>();
		// TODO: I'm not sure the consequences of breaking an instruction set down.
		for (InstructionBlock block : mappedSet) {
			InstructionSet setPerSpace =
				breakDown.computeIfAbsent(block.getStartAddress().getAddressSpace(),
					s -> new InstructionSet(manager.getBaseLanguage().getAddressFactory()));
			setPerSpace.addBlock(block);
		}
		AddressSet result = new AddressSet();
		try (LockHold hold = LockHold.lock(manager.writeLock())) {
			for (Entry<AddressSpace, InstructionSet> entry : breakDown.entrySet()) {
				DBTraceInstructionsView instructionsView = getForSpace(entry.getKey(), true);
				result.add(instructionsView.addInstructionSet(lifespan, platform, entry.getValue(),
					overwrite));
			}
			return result;
		}
	}
}
