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
package ghidra.feature.vt.api;

import java.util.Set;
import java.util.TreeMap;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

/**
 * A neighborhood generator that, for a given function, generates all functions
 * in the same namespace.  For efficiency, it caches the namespace sets it generates.
 */
public class NamespaceNeighborhood extends NeighborGenerator {

	private FunctionNodeContainer sourceNodes;					// Reference to global set of source functions
	private FunctionNodeContainer destNodes;					// Reference to global set of destination functions
	private TreeMap<Long, Set<FunctionNode>> sourceSets;		// Map from namespace ID to matching set of source functions
	private TreeMap<Long, Set<FunctionNode>> destSets;			// Map from namespace ID to matching set of dest functions
	private TreeMap<PairLabel, NeighborhoodPair> namespacePair;	// Map from pair of namespace IDs to pair of namespace sets
	private PairLabel cacheKey;									// internal key for quick lookups into namespacePair map

	private static class PairLabel implements Comparable<PairLabel> {
		public Long srcLabel;
		public Long destLabel;

		@Override
		public int compareTo(PairLabel o) {
			int srcCmp = Long.compare(srcLabel.longValue(), o.srcLabel.longValue());
			if (srcCmp != 0) {
				return srcCmp;
			}
			return Long.compare(destLabel.longValue(), o.destLabel.longValue());
		}
	}

	public NamespaceNeighborhood(LSHVectorFactory vectorFactory, double impThreshold,
			FunctionNodeContainer sourceNodes, FunctionNodeContainer destNodes) {
		super(vectorFactory, impThreshold);
		this.sourceNodes = sourceNodes;
		this.destNodes = destNodes;
		sourceSets = new TreeMap<Long, Set<FunctionNode>>();
		destSets = new TreeMap<Long, Set<FunctionNode>>();
		namespacePair = new TreeMap<PairLabel, NeighborhoodPair>();
		cacheKey = new PairLabel();
	}

	private Namespace getNamespace(FunctionNode root, FunctionNodeContainer container) {
		Function function =
			container.getProgram().getFunctionManager().getFunctionAt(root.getAddress());
		if (function == null) {
			return null;
		}
		Namespace namespace = function.getParentNamespace();
		return namespace;
	}

	private Set<FunctionNode> buildNeighborhood(Namespace namespace, Long namespaceKey,
			FunctionNodeContainer container, TreeMap<Long, Set<FunctionNode>> sets) {
		Set<FunctionNode> resultSet = sets.get(namespaceKey);
		if (resultSet == null) {
			resultSet = FunctionNode.neigborhoodAllocate();
			SymbolTable symbolTable = container.getProgram().getSymbolTable();
			SymbolIterator iter = symbolTable.getSymbols(namespace);
			while (iter.hasNext()) {
				Symbol sym = iter.next();
				if (sym.getSymbolType() != SymbolType.FUNCTION) {
					continue;
				}
				FunctionNode node = container.get(sym.getAddress());
				if (node != null) {
					resultSet.add(node);
				}
			}
			sets.put(namespaceKey, resultSet);
		}
		return resultSet;
	}

	private NeighborhoodPair findPair(Long srcKey, Long destKey) {
		cacheKey.srcLabel = srcKey;
		cacheKey.destLabel = destKey;
		return namespacePair.get(cacheKey);
	}

	private void cachePair(Long srcKey, Long destKey, NeighborhoodPair pair) {
		PairLabel newLabel = new PairLabel();
		newLabel.srcLabel = srcKey;
		newLabel.destLabel = destKey;
		namespacePair.put(newLabel, pair);
	}

	@Override
	public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
		Namespace srcNamespace = getNamespace(srcRoot, sourceNodes);
		Namespace destNamespace = getNamespace(destRoot, destNodes);
		if (srcNamespace == null || destNamespace == null) {
			NeighborhoodPair pair = new NeighborhoodPair();
			pair.srcNeighbors = FunctionNode.neigborhoodAllocate();
			pair.destNeighbors = FunctionNode.neigborhoodAllocate();
			return pair;		// Empty pair
		}
		Long srcNamespaceKey = srcNamespace.getID();
		Long destNamespaceKey = destNamespace.getID();
		NeighborhoodPair pair = findPair(srcNamespaceKey, destNamespaceKey);
		if (pair == null) {
			pair = new NeighborhoodPair();
			pair.srcNeighbors =
				buildNeighborhood(srcNamespace, srcNamespaceKey, sourceNodes, sourceSets);
			pair.destNeighbors =
				buildNeighborhood(destNamespace, destNamespaceKey, destNodes, destSets);
			cachePair(srcNamespaceKey, destNamespaceKey, pair);
		}
		if (!pair.isFilledOut) {
			if (fillOutPairs(pair, 10000)) {
				pair.isFilledOut = true;
			}
		}
		return pair;
	}
}
