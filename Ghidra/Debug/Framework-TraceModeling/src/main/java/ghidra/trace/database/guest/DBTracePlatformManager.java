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
package ghidra.trace.database.guest;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.*;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/*
 * TODO: Store mapping as from (host) address, to (guest) address, length. "to" must include
 * spaceId. It is not a problem if things overlap, as these are just informational in case an
 * instruction or reference comes along that needs mapping. This also determines what is visible
 * in program views of the mapped language. There should not be any overlaps in the same guest
 * language, however.
 */
public class DBTracePlatformManager implements DBTraceManager, TracePlatformManager {
	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final CompilerSpec baseCompilerSpec;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceGuestLanguage> languageStore;
	protected final DBCachedObjectStore<DBTraceGuestPlatform> platformStore;
	protected final Collection<TraceGuestPlatform> platformView;
	protected final Map<Language, DBTraceGuestLanguage> languagesByLanguage = new HashMap<>();
	protected final Map<CompilerSpec, DBTraceGuestPlatform> platformsByCompiler = new HashMap<>();

	protected final DBCachedObjectStore<DBTraceGuestPlatformMappedRange> rangeMappingStore;

	protected final InternalTracePlatform hostPlatform = new InternalTracePlatform() {
		@Override
		public Trace getTrace() {
			return trace;
		}

		@Override
		public DBTraceGuestLanguage getLanguageEntry() {
			return null;
		}

		@Override
		public int getIntKey() {
			return -1;
		}

		@Override
		public boolean isGuest() {
			return false;
		}

		@Override
		public Language getLanguage() {
			return trace.getBaseLanguage();
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			return trace.getBaseCompilerSpec();
		}

		@Override
		public AddressSetView getHostAddressSet() {
			return trace.getBaseAddressFactory().getAddressSet();
		}

		@Override
		public AddressSetView getGuestAddressSet() {
			return trace.getBaseAddressFactory().getAddressSet();
		}

		@Override
		public Address mapHostToGuest(Address hostAddress) {
			return hostAddress;
		}

		@Override
		public Address mapGuestToHost(Address guestAddress) {
			return guestAddress;
		}

		@Override
		public MemBuffer getMappedMemBuffer(long snap, Address guestAddress) {
			return trace.getMemoryManager().getBufferAt(snap, guestAddress);
		}

		@Override
		public InstructionSet mapGuestInstructionAddressesToHost(InstructionSet set) {
			return set;
		}
	};

	public DBTracePlatformManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, CompilerSpec baseCompilerSpec, DBTrace trace)
			throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.baseLanguage = baseCompilerSpec.getLanguage();
		this.baseCompilerSpec = baseCompilerSpec;
		this.trace = trace;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();
		languageStore = factory.getOrCreateCachedStore(DBTraceGuestLanguage.TABLE_NAME,
			DBTraceGuestLanguage.class, DBTraceGuestLanguage::new, true);
		platformStore = factory.getOrCreateCachedStore(DBTraceGuestPlatform.TABLE_NAME,
			DBTraceGuestPlatform.class, (s, r) -> new DBTraceGuestPlatform(this, s, r), true);
		platformView = Collections.unmodifiableCollection(platformStore.asMap().values());

		rangeMappingStore = factory.getOrCreateCachedStore(
			DBTraceGuestPlatformMappedRange.TABLE_NAME, DBTraceGuestPlatformMappedRange.class,
			(s, r) -> new DBTraceGuestPlatformMappedRange(this, s, r), true);

		loadLanguages();
		loadPlatforms();
		loadPlatformMappings();
	}

	protected void loadLanguages() {
		for (DBTraceGuestLanguage languageEntry : languageStore.asMap().values()) {
			languagesByLanguage.put(languageEntry.getLanguage(), languageEntry);
		}
	}

	protected void loadPlatforms()
			throws LanguageNotFoundException, CompilerSpecNotFoundException, VersionException {
		for (DBTraceGuestPlatform platformEntry : platformStore.asMap().values()) {
			platformsByCompiler.put(platformEntry.getCompilerSpec(), platformEntry);
		}
	}

	protected void loadPlatformMappings() {
		for (DBTraceGuestPlatformMappedRange langMapping : rangeMappingStore.asMap().values()) {
			DBTraceGuestPlatform mappedLanguage =
				platformStore.getObjectAt(langMapping.guestPlatformKey);
			mappedLanguage.rangesByHostAddress.put(langMapping.getHostRange().getMinAddress(),
				langMapping);
			mappedLanguage.rangesByGuestAddress.put(langMapping.getGuestRange().getMinAddress(),
				langMapping);
		}
	}

	@Internal
	protected DBTraceGuestLanguage getOrCreateLanguage(Language language) {
		if (language == baseLanguage) {
			return null;
		}
		DBTraceGuestLanguage languageEntry = languagesByLanguage.get(language);
		if (languageEntry == null) {
			languageEntry = languageStore.create();
			languageEntry.set(language);
			languagesByLanguage.put(language, languageEntry);
		}
		return languageEntry;
	}

	@Internal
	public DBTraceGuestLanguage getLanguageByKey(int key) {
		if (key == -1) {
			return null;
		}
		return languageStore.getObjectAt(key);
	}

	@Internal
	public InternalTracePlatform getPlatformByKey(int key) {
		if (key == -1) {
			return hostPlatform;
		}
		return platformStore.getObjectAt(key);
	}

	protected int getPlatformKeyForCompiler(CompilerSpec compiler) {
		if (Objects.equals(compiler, baseCompilerSpec)) {
			return -1;
		}
		return (int) platformsByCompiler.get(compiler).getKey();
	}

	@Internal
	public DBTraceGuestLanguage getLanguageByLanguage(Language language) {
		if (Objects.equals(language, baseLanguage)) {
			return null;
		}
		return Objects.requireNonNull(languagesByLanguage.get(language));
	}

	protected CompilerSpec getCompilerByKey(int compilerKey) {
		if (compilerKey == -1) {
			return baseCompilerSpec;
		}
		return platformStore.getObjectAt(compilerKey).getCompilerSpec();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		languageStore.invalidateCache();
		platformStore.invalidateCache();
		rangeMappingStore.invalidateCache();
		languagesByLanguage.clear();
		platformsByCompiler.clear();
		try {
			loadLanguages();
			loadPlatforms();
			loadPlatformMappings();
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException | VersionException e) {
			throw new AssertionError(e);
		}
	}

	protected void deleteGuestPlatform(DBTraceGuestPlatform platform, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			int platformKey = (int) platform.getKey();
			trace.getCodeManager().deletePlatform(platform, monitor);
			monitor.setMessage("Clearing guest platform range mappings");
			monitor.setMaximum(rangeMappingStore.getRecordCount());
			for (Iterator<DBTraceGuestPlatformMappedRange> it =
				rangeMappingStore.asMap().values().iterator(); it.hasNext();) {
				DBTraceGuestPlatformMappedRange range = it.next();
				if (platformKey != range.guestPlatformKey) {
					continue;
				}
				it.remove();
			}
			platformsByCompiler.remove(platform.getCompilerSpec());
			platformStore.delete(platform);
		}
	}

	@Override
	public InternalTracePlatform getHostPlatform() {
		return hostPlatform;
	}

	protected DBTraceGuestPlatform doAddGuestPlatform(CompilerSpec compilerSpec) {
		DBTraceGuestPlatform platformEntry = platformStore.create();
		platformEntry.set(compilerSpec);
		platformsByCompiler.put(compilerSpec, platformEntry);
		return platformEntry;
	}

	@Override
	public DBTraceGuestPlatform addGuestPlatform(CompilerSpec compilerSpec) {
		if (trace.getBaseCompilerSpec() == compilerSpec) {
			throw new IllegalArgumentException(
				"Base compiler spec cannot be a guest compiler spec");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return doAddGuestPlatform(compilerSpec);
		}
	}

	@Override
	public InternalTracePlatform getPlatform(CompilerSpec compilerSpec) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (trace.getBaseCompilerSpec() == compilerSpec) {
				return hostPlatform;
			}
			return platformsByCompiler.get(compilerSpec);
		}
	}

	@Override
	public DBTraceGuestPlatform getOrAddGuestPlatform(CompilerSpec compilerSpec) {
		if (compilerSpec.getCompilerSpecID()
				.equals(trace.getBaseCompilerSpec().getCompilerSpecID())) {
			throw new IllegalArgumentException("Base language cannot be a guest language");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceGuestPlatform exists = platformsByCompiler.get(compilerSpec);
			if (exists != null) {
				return exists;
			}
			return doAddGuestPlatform(compilerSpec);
		}
	}

	@Override
	public Collection<TraceGuestPlatform> getGuestPlatforms() {
		return platformView;
	}

	@Internal
	public InternalTracePlatform assertMine(TracePlatform platform) {
		if (platform == hostPlatform) {
			return hostPlatform;
		}
		if (!(platform instanceof DBTraceGuestPlatform)) {
			throw new IllegalArgumentException("Given platform does not belong to this trace");
		}
		DBTraceGuestPlatform dbPlatform = (DBTraceGuestPlatform) platform;
		if (dbPlatform.manager != this) {
			throw new IllegalArgumentException("Given platform does not belong to this trace");
		}
		if (dbPlatform.isDeleted()) {
			throw new IllegalArgumentException("Given platform has been deleted");
		}
		return dbPlatform;
	}
}
