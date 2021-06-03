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
package ghidra.trace.database.program;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.ComparatorMath;
import ghidra.util.LockHold;
import ghidra.util.exception.*;

public class DBTraceProgramViewRootModule implements ProgramModule {
	public static final ProgramModule[] EMPTY_MODULE_ARRAY = new ProgramModule[] {};

	protected final DBTraceProgramView program;
	protected final AbstractDBTraceProgramViewListing listing;

	public DBTraceProgramViewRootModule(AbstractDBTraceProgramViewListing listing) {
		this.program = listing.program;
		this.listing = listing;
	}

	@Override
	public String getComment() {
		return "root";
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return AbstractDBTraceProgramViewListing.TREE_NAME;
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(CodeUnit codeUnit) {
		return true;
	}

	@Override
	public int getNumParents() {
		return 0;
	}

	@Override
	public ProgramModule[] getParents() {
		return EMPTY_MODULE_ARRAY;
	}

	@Override
	public String[] getParentNames() {
		return AbstractDBTraceProgramViewListing.EMPTY_STRING_ARRAY;
	}

	@Override
	public String getTreeName() {
		return AbstractDBTraceProgramViewListing.TREE_NAME;
	}

	@Override
	public boolean contains(ProgramFragment fragment) {
		return true;
	}

	@Override
	public boolean contains(ProgramModule module) {
		return true;
	}

	@Override
	public int getNumChildren() {
		return program.trace.getMemoryManager().getRegionsAtSnap(program.snap).size();
	}

	@Override
	public Group[] getChildren() {
		// TODO: Should I cache these? IDK. This whole thing is a hack anyway
		// NOTE: Would flush on snap change
		try (LockHold hold = LockHold.lock(program.trace.getReadWriteLock().readLock())) {
			List<DBTraceProgramViewFragment> frags = new ArrayList<>();
			program.memory.forVisibleRegions(region -> {
				frags.add(listing.fragmentsByRegion.computeIfAbsent(region,
					r -> new DBTraceProgramViewFragment(listing, r)));
			});
			return frags.toArray(new DBTraceProgramViewFragment[frags.size()]);
		}
	}

	@Override
	public int getIndex(String name) {
		// TODO: This isn't pretty at all. Really should database these.
		List<String> names = new ArrayList<>();
		try (LockHold hold = LockHold.lock(program.trace.getReadWriteLock().readLock())) {
			program.memory.forVisibleRegions(region -> names.add(region.getName()));
		}
		return names.indexOf(names);
	}

	@Override
	public void add(ProgramModule module)
			throws CircularDependencyException, DuplicateGroupException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void add(ProgramFragment fragment) throws DuplicateGroupException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule createModule(String moduleName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramFragment createFragment(String fragmentName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void reparent(String name, ProgramModule oldParent) throws NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void moveChild(String name, int index) throws NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeChild(String name) throws NotEmptyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDescendant(ProgramModule module) {
		return false;
	}

	@Override
	public boolean isDescendant(ProgramFragment fragment) {
		return true;
	}

	protected <T> T reduceRegions(java.util.function.Function<TraceMemoryRegion, T> func,
			BiFunction<T, T, T> reducer) {
		var action = new Consumer<TraceMemoryRegion>() {
			public T cur;

			@Override
			public void accept(TraceMemoryRegion region) {
				if (cur == null) {
					cur = func.apply(region);
				}
				else {
					cur = reducer.apply(cur, func.apply(region));
				}
			}
		};
		return action.cur;
	}

	@Override
	public Address getMinAddress() {
		if (!program.viewport.isForked()) {
			return program.trace.getMemoryManager()
					.getRegionsAddressSet(program.snap)
					.getMinAddress();
		}
		// TODO: There has got to be a better way
		return reduceRegions(TraceMemoryRegion::getMinAddress, ComparatorMath::cmin);
	}

	@Override
	public Address getMaxAddress() {
		if (!program.viewport.isForked()) {
			return program.trace.getMemoryManager()
					.getRegionsAddressSet(program.snap)
					.getMaxAddress();
		}
		// TODO: There has got to be a better way
		return reduceRegions(TraceMemoryRegion::getMaxAddress, ComparatorMath::cmax);
	}

	@Override
	public Address getFirstAddress() {
		return getMinAddress();
	}

	@Override
	public Address getLastAddress() {
		return getMaxAddress();
	}

	@Override
	public AddressSetView getAddressSet() {
		return program.viewport
				.unionedAddresses(s -> program.trace.getMemoryManager().getRegionsAddressSet(s));
	}

	@Override
	public Object getVersionTag() {
		return program.versionTag;
	}

	@Override
	public long getModificationNumber() {
		return program.versionTag;
	}

	@Override
	public long getTreeID() {
		return 0;
	}
}
