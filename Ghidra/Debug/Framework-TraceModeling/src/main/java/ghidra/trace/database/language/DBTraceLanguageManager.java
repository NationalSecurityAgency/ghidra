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
package ghidra.trace.database.language;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.model.language.TraceGuestLanguage;
import ghidra.trace.model.language.TraceLanguageManager;
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
public class DBTraceLanguageManager implements DBTraceManager, TraceLanguageManager {
	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceGuestLanguage> languageStore;
	protected final Collection<TraceGuestLanguage> languageView;
	protected final Map<Language, DBTraceGuestLanguage> entriesByLanguage = new HashMap<>();

	protected final DBCachedObjectStore<DBTraceGuestLanguageMappedRange> rangeMappingStore;

	public DBTraceLanguageManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace)
			throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.baseLanguage = baseLanguage;
		this.trace = trace;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();
		languageStore = factory.getOrCreateCachedStore(DBTraceGuestLanguage.TABLE_NAME,
			DBTraceGuestLanguage.class, (s, r) -> new DBTraceGuestLanguage(this, s, r), true);
		languageView = Collections.unmodifiableCollection(languageStore.asMap().values());

		rangeMappingStore = factory.getOrCreateCachedStore(
			DBTraceGuestLanguageMappedRange.TABLE_NAME, DBTraceGuestLanguageMappedRange.class,
			(s, r) -> new DBTraceGuestLanguageMappedRange(this, s, r), true);

		loadLanguages();
		loadLanguageMappings();
	}

	protected void loadLanguages() throws LanguageNotFoundException, VersionException {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		for (DBTraceGuestLanguage langEnt : languageStore.asMap().values()) {
			langEnt.doGetLanguage(langServ);
			entriesByLanguage.put(langEnt.getLanguage(), langEnt);
		}
	}

	protected void loadLanguageMappings() {
		for (DBTraceGuestLanguageMappedRange langMapping : rangeMappingStore.asMap().values()) {
			DBTraceGuestLanguage mappedLanguage =
				languageStore.getObjectAt(langMapping.guestLangKey);
			mappedLanguage.rangesByHostAddress.put(langMapping.getHostRange().getMinAddress(),
				langMapping);
			mappedLanguage.rangesByGuestAddress.put(langMapping.getGuestRange().getMinAddress(),
				langMapping);
		}
	}

	// Internal
	public int getKeyForLanguage(Language language) {
		if (Objects.equals(language, baseLanguage)) {
			return -1;
		}
		return (int) entriesByLanguage.get(language).getKey();
	}

	// Internal
	public Language getLanguageByKey(int langKey) {
		if (langKey == -1) {
			return baseLanguage;
		}
		return languageStore.getObjectAt(langKey).getLanguage();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		languageStore.invalidateCache();
		rangeMappingStore.invalidateCache();
		entriesByLanguage.clear();
		try {
			loadLanguages();
			loadLanguageMappings();
		}
		catch (LanguageNotFoundException | VersionException e) {
			throw new AssertionError(e);
		}
	}

	protected void deleteGuestLanguage(DBTraceGuestLanguage langEnt, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			int langKey = (int) langEnt.getKey();
			trace.getCodeManager().deleteLanguage(langKey, monitor);
			monitor.setMessage("Clearing guest language range mappings");
			monitor.setMaximum(rangeMappingStore.getRecordCount());
			for (Iterator<DBTraceGuestLanguageMappedRange> it =
				rangeMappingStore.asMap().values().iterator(); it.hasNext();) {
				DBTraceGuestLanguageMappedRange range = it.next();
				if (langKey != range.guestLangKey) {
					continue;
				}
				it.remove();
			}
			entriesByLanguage.remove(langEnt.getLanguage());
			languageStore.delete(langEnt);
		}
	}

	@Override
	public Language getBaseLanguage() {
		return trace.getBaseLanguage();
	}

	@Override
	public DBTraceGuestLanguage addGuestLanguage(Language language) {
		if (language.getLanguageID().equals(trace.getBaseLanguage().getLanguageID())) {
			throw new IllegalArgumentException("Base language cannot be a guest language");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceGuestLanguage langEnt = languageStore.create();
			langEnt.setLanguage(language);
			entriesByLanguage.put(language, langEnt);
			return langEnt;
		}
	}

	public DBTraceGuestLanguage getGuestLanguage(Language language) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return entriesByLanguage.get(language);
		}
	}

	@Override
	public Collection<TraceGuestLanguage> getGuestLanguages() {
		return languageView;
	}

	protected Language getLanguageOf(InstructionSet instructionSet) {
		for (InstructionBlock block : instructionSet) {
			for (Instruction instruction : block) {
				return instruction.getPrototype().getLanguage();
			}
		}
		// No instructions, default to base language
		return trace.getBaseLanguage();
	}

	@Override
	public InstructionSet mapGuestInstructionAddressesToHost(InstructionSet instructionSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			Language language = getLanguageOf(instructionSet);
			if (language == trace.getBaseLanguage()) {
				return instructionSet; // Nothing to map
			}
			DBTraceGuestLanguage guest = trace.getLanguageManager().getGuestLanguage(language);
			if (guest == null) {
				throw new IllegalArgumentException(
					"Instructions are in neither the base nor a guest language");
			}
			return guest.mapGuestInstructionAddressesToHost(instructionSet);
		}
	}
}
