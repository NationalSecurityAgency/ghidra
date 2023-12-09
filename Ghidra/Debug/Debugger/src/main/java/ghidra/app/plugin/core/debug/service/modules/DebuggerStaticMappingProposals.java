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
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.core.debug.service.modules.ProgramModuleIndexer.IndexEntry;
import ghidra.app.services.*;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.modules.*;
import ghidra.framework.model.DomainFile;
import ghidra.graph.*;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.Msg;

public enum DebuggerStaticMappingProposals {
	;

	protected static String getLastLower(String path) {
		return new File(path).getName().toLowerCase();
	}

	/**
	 * Check if either the program's name, its executable path, or its domain file name contains the
	 * given module name
	 * 
	 * @param program the program whose names to check
	 * @param moduleLowerName the module name to check for in lower case
	 * @return true if matched, false if not
	 */
	protected static boolean namesContain(Program program, String moduleLowerName) {
		DomainFile df = program.getDomainFile();
		if (df == null || df.getProjectLocator() == null) {
			return false;
		}
		String programName = getLastLower(program.getName());
		if (programName.contains(moduleLowerName)) {
			return true;
		}
		String exePath = program.getExecutablePath();
		if (exePath != null) {
			String execName = getLastLower(exePath);
			if (execName.contains(moduleLowerName)) {
				return true;
			}
		}
		String fileName = df.getName().toLowerCase();
		if (fileName.contains(moduleLowerName)) {
			return true;
		}
		return false;
	}

	protected interface ProposalGenerator<F, T, MP extends MapProposal<?, ?, ?>> {
		MP proposeMap(F from, T to);

		MP proposeBestMap(F from, Collection<? extends T> tos);

		Map<F, MP> proposeBestMaps(Collection<? extends F> froms, Collection<? extends T> tos);
	}

	protected abstract static class AbstractProposalGenerator //
	<F, T, J, MP extends MapProposal<?, ?, ?>> {
		protected abstract MP proposeMap(F from, T to);

		protected abstract J computeFromJoinKey(F from);

		protected abstract boolean isJoined(J key, T to);

		protected Collection<T> filterJoined(J key, Collection<? extends T> tos) {
			return tos.stream()
					.filter(t -> isJoined(key, t))
					// Need to preserve order here
					.collect(Collectors.toCollection(LinkedHashSet::new));
		}

		protected MP proposeBestMap(F from, Collection<? extends T> tos) {
			double bestScore = -1;
			MP bestMap = null;
			for (T t : tos) {
				MP map = proposeMap(from, t);
				double score = map.computeScore();
				// NOTE: Ties prefer first in candidate collection
				if (score > bestScore) {
					bestScore = score;
					bestMap = map;
				}
			}
			return bestMap;
		}

		protected Map<F, MP> proposeBestMaps(Collection<? extends F> froms,
				Collection<? extends T> tos) {
			Map<F, MP> result = new LinkedHashMap<>();
			for (F f : froms) {
				J joinKey = computeFromJoinKey(f);
				Collection<T> joined = filterJoined(joinKey, tos);
				MP map = proposeBestMap(f, joined);
				if (map != null) {
					result.put(f, map);
				}
			}
			return result;
		}
	}

	protected static class ModuleMapProposalGenerator
			implements ProposalGenerator<TraceModule, Program, ModuleMapProposal> {
		private final ProgramModuleIndexer indexer;

		public ModuleMapProposalGenerator(ProgramModuleIndexer indexer) {
			this.indexer = indexer;
		}

		@Override
		public ModuleMapProposal proposeMap(TraceModule from, Program to) {
			return new DefaultModuleMapProposal(from, to);
		}

		@Override
		public ModuleMapProposal proposeBestMap(TraceModule from,
				Collection<? extends Program> tos) {
			Collection<IndexEntry> entries = indexer.filter(indexer.getBestEntries(from), tos);
			DomainFile df = indexer.getBestMatch(from, null, entries);
			if (df == null) {
				return null;
			}
			try (PeekOpenedDomainObject peek = new PeekOpenedDomainObject(df)) {
				return proposeMap(from, (Program) peek.object);
			}
		}

		@Override
		public Map<TraceModule, ModuleMapProposal> proposeBestMaps(
				Collection<? extends TraceModule> froms, Collection<? extends Program> tos) {
			Map<TraceModule, ModuleMapProposal> result = new LinkedHashMap<>();
			for (TraceModule f : froms) {
				ModuleMapProposal map = proposeBestMap(f, tos);
				if (map != null) {
					result.put(f, map);
				}
			}
			return result;
		}
	}

	protected static class SectionMapProposalGenerator
			extends AbstractProposalGenerator<TraceModule, Program, String, SectionMapProposal> {
		@Override
		protected SectionMapProposal proposeMap(TraceModule from, Program to) {
			return new DefaultSectionMapProposal(from, to);
		}

		@Override
		protected String computeFromJoinKey(TraceModule from) {
			return getLastLower(from.getName());
		}

		@Override
		protected boolean isJoined(String key, Program to) {
			return namesContain(to, key);
		}
	}

	protected static class RegionMapProposalGenerator extends
			AbstractProposalGenerator<Collection<TraceMemoryRegion>, Program, Set<String>, //
					RegionMapProposal> {

		@Override
		protected RegionMapProposal proposeMap(Collection<TraceMemoryRegion> from,
				Program to) {
			return new DefaultRegionMapProposal(from, to);
		}

		@Override
		protected Set<String> computeFromJoinKey(Collection<TraceMemoryRegion> from) {
			return from.stream()
					.flatMap(r -> getLikelyModulesFromName(r).stream())
					.map(n -> getLastLower(n))
					.collect(Collectors.toSet());
		}

		@Override
		protected boolean isJoined(Set<String> key, Program to) {
			return key.stream().anyMatch(n -> namesContain(to, n));
		}
	}

	// TODO: Should these also take advantage of the program-module index?
	protected static final SectionMapProposalGenerator SECTIONS = new SectionMapProposalGenerator();
	protected static final RegionMapProposalGenerator REGIONS = new RegionMapProposalGenerator();

	public static RegionMapProposal proposeRegionMap(
			Collection<? extends TraceMemoryRegion> regions,
			Collection<? extends Program> programs) {
		return REGIONS.proposeBestMap(Collections.unmodifiableCollection(regions), programs);
	}

	public static <V, J> Set<Set<V>> groupByComponents(Collection<? extends V> vertices,
			Function<V, J> precompute, BiPredicate<J, J> areConnected) {
		List<V> vs = List.copyOf(vertices);
		List<J> pres = vs.stream().map(precompute).collect(Collectors.toList());
		GDirectedGraph<V, GEdge<V>> graph = new JungDirectedGraph<>();
		for (V v : vs) {
			graph.addVertex(v); // Lone regions should still be considered
		}
		int size = vs.size();
		for (int i = 0; i < size; i++) {
			V v1 = vs.get(i);
			J j1 = pres.get(i);
			for (int j = i + 1; j < size; j++) {
				V v2 = vs.get(j);
				J j2 = pres.get(j);
				if (areConnected.test(j1, j2)) {
					graph.addEdge(new DefaultGEdge<>(v1, v2));
					graph.addEdge(new DefaultGEdge<>(v2, v1));
				}
			}
		}
		return GraphAlgorithms.getStronglyConnectedComponents(graph);
	}

	protected static Set<String> getLikelyModulesFromName(TraceMemoryRegion region) {
		String key;
		try {
			List<String> path = PathUtils.parse(region.getPath());
			key = PathUtils.getKey(path);
			if (PathUtils.isIndex(key)) {
				key = PathUtils.parseIndex(key);
			}
		}
		catch (IllegalArgumentException e) { // Parse error
			Msg.error(DebuggerStaticMappingProposals.class,
				"Encountered unparsable path: " + region.getName());
			key = region.getName(); // Not a great fallback, but it'll have to do
		}
		return Stream.of(key.split("\\s+"))
				.filter(n -> n.replaceAll("[0-9A-Fa-f]+", "").length() >= 5)
				.collect(Collectors.toSet());
	}

	public static Set<Set<TraceMemoryRegion>> groupRegionsByLikelyModule(
			Collection<? extends TraceMemoryRegion> regions) {
		return groupByComponents(regions, r -> getLikelyModulesFromName(r), (m1, m2) -> {
			return m1.stream().anyMatch(m2::contains);
		});
	}
}
