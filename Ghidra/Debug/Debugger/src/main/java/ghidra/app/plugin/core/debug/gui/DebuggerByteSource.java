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
package ghidra.app.plugin.core.debug.gui;

import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Stream;

import db.Transaction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.debug.gui.action.DebuggerReadsMemoryTrait;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;

/**
 * A byte source for searching the memory of a possibly-live target in the debugger.
 * 
 * <p>
 * Because we'd like the search to preserve its state over the lifetime of the target, and the
 * target "changes" by navigating snapshots, we need to allow the view to move without requiring a
 * new byte source to be constructed. We <em>cannot</em>, however, just blindly follow the
 * {@link Navigatable} wherever it goes. This is roughly the equivalent of a {@link Program}, but
 * with knowledge of the target to cause a refresh of actual target memory when necessary.
 */
public class DebuggerByteSource implements AddressableByteSource {

	private final PluginTool tool;
	private final TraceProgramView view;
	private final Target target;
	private final DebuggerReadsMemoryTrait readsMem;

	public DebuggerByteSource(PluginTool tool, TraceProgramView view, Target target,
			DebuggerReadsMemoryTrait readsMem) {
		this.tool = tool;
		this.view = view;
		this.target = target;
		this.readsMem = readsMem;
	}

	@Override
	public int getBytes(Address address, byte[] bytes, int length) {
		AddressSet set = new AddressSet(address, address.add(length - 1));
		try {
			readsMem.getAutoSpec()
					.readMemory(tool, DebuggerCoordinates.NOWHERE.view(view).target(target), set)
					.get(Target.TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
			return view.getMemory().getBytes(address, bytes, 0, length);
		}
		catch (AddressOutOfBoundsException | MemoryAccessException | InterruptedException
				| ExecutionException | TimeoutException e) {
			return 0;
		}
	}

	@Override
	public List<SearchRegion> getSearchableRegions() {
		AddressFactory factory = view.getTrace().getBaseAddressFactory();
		List<AddressSpace> spaces = Stream.of(factory.getPhysicalSpaces())
				.filter(s -> s.getType() != AddressSpace.TYPE_OTHER)
				.toList();
		if (spaces.size() == 1) {
			return DebuggerSearchRegionFactory.ALL.stream()
					.map(f -> f.createRegion(null))
					.toList();
		}

		Stream<AddressSpace> concat =
			Stream.concat(Stream.of((AddressSpace) null), spaces.stream());
		return concat
				.flatMap(s -> DebuggerSearchRegionFactory.ALL.stream().map(f -> f.createRegion(s)))
				.toList();
	}

	@Override
	public void invalidate() {
		try (Transaction tx = view.getTrace().openTransaction("Invalidate memory")) {
			TraceMemoryManager mm = view.getTrace().getMemoryManager();
			for (AddressSpace space : view.getTrace().getBaseAddressFactory().getAddressSpaces()) {
				if (!space.isMemorySpace()) {
					continue;
				}
				TraceMemorySpace ms = mm.getMemorySpace(space, false);
				if (ms == null) {
					continue;
				}
				ms.setState(view.getSnap(), space.getMinAddress(), space.getMaxAddress(),
					TraceMemoryState.UNKNOWN);
			}
		}
	}
}
