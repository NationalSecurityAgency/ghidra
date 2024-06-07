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
package ghidra.app.plugin.core.debug.service.modules;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.modules.TraceModule;

// TODO: Consider making this a front-end plugin?
public class ProgramModuleIndexer implements DomainFolderChangeListener {
	public static final String MODULE_PATHS_PROPERTY = "Module Paths";
	private static final Gson JSON = new Gson();

	public static void setModulePaths(Program program, Collection<String> moduleNames) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		LinkedHashSet<String> distinct = moduleNames instanceof LinkedHashSet<String> yes ? yes
				: new LinkedHashSet<>(moduleNames);
		options.setString(MODULE_PATHS_PROPERTY, JSON.toJson(distinct));
	}

	public static Collection<String> getModulePaths(DomainFile df) {
		return getModulePaths(df.getMetadata());
	}

	public static Collection<String> getModulePaths(Map<String, String> metadata) {
		String json = metadata.get(MODULE_PATHS_PROPERTY);
		if (json == null) {
			return List.of();
		}
		return JSON.fromJson(json, new TypeToken<List<String>>() {}.getType());
	}

	public static void addModulePaths(Program program, Collection<String> moduleNames) {
		LinkedHashSet<String> union = new LinkedHashSet<>(getModulePaths(program.getMetadata()));
		union.addAll(moduleNames);
		setModulePaths(program, union);
	}

	protected enum NameSource {
		MODULE_PATH,
		MODULE_NAME,
		PROGRAM_EXECUTABLE_PATH,
		PROGRAM_EXECUTABLE_NAME,
		PROGRAM_NAME,
		DOMAIN_FILE_NAME,
	}

	// TODO: Note language and prefer those from the same processor?
	// Will get difficult with new OBTR, since I'd need a platform
	// There's also the WoW64 issue....
	protected record IndexEntry(String name, String dfID, NameSource source) {
	}

	protected class ModuleChangeListener
			implements DomainObjectListener, DomainObjectClosedListener {
		private final Program program;

		public ModuleChangeListener(Program program) {
			this.program = program;
			program.addListener(this);
			program.addCloseListener(this);
			return;
		}

		protected void dispose() {
			program.removeListener(this);
			program.removeCloseListener(this);
		}

		@Override
		public void domainObjectClosed(DomainObject dobj) {
			// assume dobj == program
			dispose();
		}

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (disposed) {
				return;
			}
			if (ev.contains(DomainObjectEvent.RESTORED)) {
				refreshIndex(program.getDomainFile(), program);
				return;
			}
			if (ev.contains(DomainObjectEvent.PROPERTY_CHANGED)) {
				for (DomainObjectChangeRecord rec : ev) {
					if (rec.getEventType() == DomainObjectEvent.PROPERTY_CHANGED) {
						// OldValue is actually the property name :/
						// See DomainObjectAdapter#propertyChanged
						String propertyName = (String) rec.getOldValue();
						if ((Program.PROGRAM_INFO + "." + MODULE_PATHS_PROPERTY)
								.equals(propertyName)) {
							refreshIndex(program.getDomainFile(), program);
							return;
						}
					}
				}
			}
		}
	}

	protected static class MapOfSets<K, V> {
		public final Map<K, Set<V>> map = new HashMap<>();

		public void put(K key, V value) {
			map.computeIfAbsent(key, k -> new HashSet<>()).add(value);
		}

		public void remove(K key, V value) {
			Set<V> set = map.get(key);
			if (set == null) {
				return;
			}
			set.remove(value);
			if (set.isEmpty()) {
				map.remove(key);
			}
		}
	}

	protected static class ModuleIndex {
		final MapOfSets<String, IndexEntry> entriesByName = new MapOfSets<>();
		final MapOfSets<String, IndexEntry> entriesByFile = new MapOfSets<>();

		void addEntry(String name, String dfID, NameSource source) {
			IndexEntry entry = new IndexEntry(name, dfID, source);
			entriesByName.put(name, entry);
			entriesByFile.put(dfID, entry);
		}

		void removeEntry(IndexEntry entry) {
			entriesByName.remove(entry.name, entry);
			entriesByFile.remove(entry.dfID, entry);
		}

		void removeFile(String fileID) {
			Set<IndexEntry> remove = entriesByFile.map.remove(fileID);
			if (remove == null) {
				return;
			}
			for (IndexEntry entry : remove) {
				entriesByName.remove(entry.name, entry);
			}
		}

		public Collection<IndexEntry> getByName(String name) {
			return entriesByName.map.getOrDefault(name, Set.of());
		}
	}

	private final Project project;
	private final ProjectData projectData;
	private volatile boolean disposed;

	private final Map<Program, ModuleChangeListener> openedForUpdate = new HashMap<>();
	private final ModuleIndex index = new ModuleIndex();

	public ProgramModuleIndexer(PluginTool tool) {
		this.project = tool.getProject();
		this.projectData = tool.getProject().getProjectData();
		this.projectData.addDomainFolderChangeListener(this);

		indexFolder(projectData.getRootFolder());
	}

	void dispose() {
		disposed = true;
		projectData.removeDomainFolderChangeListener(this);
	}

	protected void indexFolder(DomainFolder folder) {
		for (DomainFile file : folder.getFiles()) {
			addToIndex(file);
		}
		for (DomainFolder sub : folder.getFolders()) {
			indexFolder(sub);
		}
	}

	protected void addToIndex(DomainFile file, Program program) {
		if (disposed) {
			return;
		}
		addToIndex(file, program.getMetadata());
	}

	protected void addToIndex(DomainFile file) {
		if (disposed) {
			return;
		}
		if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
			return;
		}
		addToIndex(file, file.getMetadata());
	}

	protected void addToIndex(DomainFile file, Map<String, String> metadata) {
		String dfID = file.getFileID();

		String dfName = file.getName().toLowerCase();
		String progName = metadata.get("Program Name");
		if (progName != null) {
			progName = progName.toLowerCase();
		}
		String exePath = metadata.get("Executable Location");
		if (exePath != null) {
			exePath = exePath.toLowerCase();
		}
		String exeName = exePath == null ? null : new File(exePath).getName();

		for (String modPath : getModulePaths(metadata)) {
			String modName = new File(modPath).getName();
			if (!modPath.equals(modName)) {
				index.addEntry(modPath, dfID, NameSource.MODULE_PATH);
			}
			index.addEntry(modName, dfID, NameSource.MODULE_NAME);
		}

		index.addEntry(dfName, dfID, NameSource.DOMAIN_FILE_NAME);
		if (progName != null) {
			index.addEntry(progName, dfID, NameSource.DOMAIN_FILE_NAME);
		}
		if (exeName != null) {
			if (!exePath.equals(exeName)) {
				index.addEntry(exePath, dfID, NameSource.PROGRAM_EXECUTABLE_PATH);
			}
			index.addEntry(exeName, dfID, NameSource.PROGRAM_EXECUTABLE_NAME);
		}
	}

	protected void removeFromIndex(String fileID) {
		index.removeFile(fileID);
	}

	protected void refreshIndex(DomainFile file) {
		removeFromIndex(file.getFileID());
		addToIndex(file);
	}

	protected void refreshIndex(DomainFile file, Program program) {
		removeFromIndex(file.getFileID());
		addToIndex(file, program);
	}

	@Override
	public void domainFileAdded(DomainFile file) {
		addToIndex(file);
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		removeFromIndex(fileID);
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {
		refreshIndex(file);
	}

	@Override
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		refreshIndex(file);
	}

	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		if (disposed) {
			return;
		}
		if (object instanceof Program program) {
			synchronized (openedForUpdate) {
				openedForUpdate.computeIfAbsent(program, ModuleChangeListener::new);
			}
		}
	}

	@Override
	public void domainFileObjectClosed(DomainFile file, DomainObject object) {
		if (disposed) {
			return;
		}
		synchronized (openedForUpdate) {
			ModuleChangeListener listener = openedForUpdate.remove(object);
			if (listener != null) {
				listener.dispose();
			}
		}
	}

	private DomainFile selectBest(Collection<IndexEntry> entries, Set<DomainFile> libraries,
			Map<DomainFolder, Integer> folderUses, Program currentProgram) {
		if (currentProgram != null) {
			DomainFile currentFile = currentProgram.getDomainFile();
			if (currentFile != null) {
				String currentID = currentFile.getFileID();
				for (IndexEntry entry : entries) {
					if (entry.dfID.equals(currentID)) {
						return currentFile;
					}
				}
			}
		}
		Comparator<IndexEntry> byIsLibrary = Comparator.comparing(e -> {
			DomainFile df = projectData.getFileByID(e.dfID);
			return libraries.contains(df) ? 1 : 0;
		});
		Comparator<IndexEntry> byNameSource = Comparator.comparing(e -> -e.source.ordinal());
		Map<IndexEntry, Integer> folderScores = new HashMap<>();
		Comparator<IndexEntry> byFolderUses = Comparator.comparing(e -> {
			return folderScores.computeIfAbsent(e, k -> {
				DomainFile df = projectData.getFileByID(k.dfID);
				int score = 0;
				for (DomainFolder folder = df.getParent(); folder != null; folder =
					folder.getParent()) {
					score += folderUses.getOrDefault(folder, 0);
				}
				return score;
			});
		});
		/**
		 * It's not clear if being a library of an already-mapped program should override a
		 * user-provided module name.... That said, unless there are already bogus mappings in the
		 * trace, or bogus external libraries in a mapped program, scoring libraries before module
		 * names should not cause problems.
		 */
		Comparator<IndexEntry> comparator =
			byIsLibrary.thenComparing(byNameSource).thenComparing(byFolderUses);
		return projectData.getFileByID(entries.stream().max(comparator).get().dfID);
	}

	public DomainFile getBestMatch(AddressSpace space, TraceModule module, Program currentProgram,
			Collection<IndexEntry> entries) {
		if (entries.isEmpty()) {
			return null;
		}
		Map<DomainFolder, Integer> folderUses = new HashMap<>();
		Set<DomainFile> alreadyMapped = module.getTrace()
				.getStaticMappingManager()
				.findAllOverlapping(
					new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress()),
					module.getLifespan())
				.stream()
				.map(m -> ProgramURLUtils.getDomainFileFromOpenProject(project,
					m.getStaticProgramURL()))
				.filter(Objects::nonNull)
				.collect(Collectors.toSet());
		Set<DomainFile> libraries = DebuggerStaticMappingUtils.collectLibraries(alreadyMapped);
		alreadyMapped.stream()
				.map(df -> df.getParent())
				.filter(folder -> folder.getProjectData() == projectData)
				.forEach(folder -> {
					for (; folder != null; folder = folder.getParent()) {
						folderUses.compute(folder, (f, c) -> c == null ? 1 : (c + 1));
					}
				});
		return selectBest(entries, libraries, folderUses, currentProgram);
	}

	public DomainFile getBestMatch(TraceModule module, Program currentProgram,
			Collection<IndexEntry> entries) {
		return getBestMatch(module.getBase().getAddressSpace(), module, currentProgram, entries);
	}

	public List<IndexEntry> getBestEntries(TraceModule module) {
		String modulePathName = module.getName().toLowerCase();
		List<IndexEntry> entries = new ArrayList<>(index.getByName(modulePathName));
		if (!entries.isEmpty()) {
			return entries;
		}
		String moduleFileName = new File(modulePathName).getName();
		entries.addAll(index.getByName(moduleFileName));
		return entries;
	}

	public DomainFile getBestMatch(AddressSpace space, TraceModule module, Program currentProgram) {
		return getBestMatch(space, module, currentProgram, getBestEntries(module));
	}

	public Collection<IndexEntry> filter(Collection<IndexEntry> entries,
			Collection<? extends Program> programs) {
		Collection<IndexEntry> result = new ArrayList<>();
		for (IndexEntry e : entries) {
			DomainFile df = projectData.getFileByID(e.dfID);
			if (df == null) {
				continue;
			}
			try (PeekOpenedDomainObject peek = new PeekOpenedDomainObject(df)) {
				if (peek.object != null && programs.contains(peek.object)) {
					result.add(e);
				}
			}
		}
		return result;
	}
}
