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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.map.LazyMap;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyContextGraph.Edge;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyContextGraph.Vertex;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.graph.*;
import ghidra.graph.algo.DijkstraShortestPathsAlgorithm;

/**
 * A graph of possible context changes via the application of various constructors
 * 
 * This is used primarily to find optimal paths for the application of recursive rules, i.e., those
 * of the form I =&gt; I. These cannot be resolved without some form of semantic analysis. The most
 * notable disadvantage to all of this is that you no longer get all of the possible assemblies,
 * but only those with the fewest rule applications.
 * 
 * Conceivably, this may also be used to prune some possibilities during semantic resolution of a
 * parse tree. Even better, it may be possible to derive a grammar which accounts for the context
 * changes already; however, it's unclear how many rules this will generate, and consequently, how
 * much larger its LALR(1) parser would become.
 */
public class AssemblyContextGraph implements GImplicitDirectedGraph<Vertex, Edge> {
	protected final Map<String, Set<AssemblyConstructorSemantic>> semantics =
		LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>());
	protected final AssemblyGrammar grammar;
	protected final SleighLanguage lang;
	protected final DijkstraShortestPathsAlgorithm<Vertex, Edge> dijkstra;

	protected final Set<Vertex> cachedVertices = new HashSet<>();
	protected final Set<Edge> cachedEdges = new HashSet<>();
	protected final Map<Vertex, Set<Edge>> cachedOutEdges =
		LazyMap.lazyMap(new HashMap<>(), (Vertex v) -> computeOutEdges(v));

	/**
	 * Build the context change graph for a given language and grammar
	 * 
	 * The grammar must have been constructed from the given language. The language is used just to
	 * obtain the most common default context.
	 * 
	 * At the moment, this graph only expands the recursive rules at the root constructor table,
	 * i.e., "instruction". Thus, the assembler will not be able to process any language that has
	 * <i>purely</i>-recursive rules at subconstructors.
	 * @param lang the language
	 * @param grammar the grammar derived from the given language
	 */
	public AssemblyContextGraph(SleighLanguage lang, AssemblyGrammar grammar) {
		this.grammar = grammar;
		this.lang = lang;

		gatherSemantics();

		AssemblyDefaultContext ctx = new AssemblyDefaultContext(lang);
		AssemblyPatternBlock defctx = ctx.getDefault();
		defctx = defctx.fillMask();

		Vertex v = new Vertex(defctx, grammar.getStartName());
		// Because this graph is potentially infinite, we must cap the distance.
		// Since we'd like to apply each constructor once, we can cap by the number of semantics.
		// Certainly this doesn't strictly enforce the apply once rule, but we do get an overset.
		dijkstra = new DijkstraShortestPathsAlgorithm<>(this,
			semantics.get(grammar.getStartName()).size(), GEdgeWeightMetric.unitMetric());

		// Pre-compute for the source we know we will always use
		dijkstra.getDistancesFromSource(v);
	}

	/**
	 * Compute the optimal, i.e., fewest, sequences of applications to resolve a given context to
	 * the language's default context.
	 * 
	 * @param src presumably, the language's default context
	 * @param srcTable the name of the SLEIGH constructor table, presumably "instruction"
	 * @param dst the context block being resolved
	 * @param dstTable the name of the SLEIGH constructor table being resolved
	 * @return a collection of sequences of constructor applications from {@code src} to
	 *         {@code dst}
	 * 
	 * NOTE: For assembly, the sequences will need to be applied right-to-left.
	 */
	public Collection<Deque<AssemblyConstructorSemantic>> computeOptimalApplications(
			AssemblyPatternBlock src, String srcTable, AssemblyPatternBlock dst, String dstTable) {
		Vertex s = new Vertex(src, srcTable);
		Vertex xd = new Vertex(dst, dstTable);
		// Because we're working with masks, there may be many vertices that match dst
		// Find the one(s) with the shortest distance
		Set<Vertex> bestDests = new HashSet<>();
		Double bestDist = null;
		for (Entry<Vertex, Double> ent : dijkstra.getDistancesFromSource(s).entrySet()) {
			if (ent.getKey().matches(xd)) {
				if (bestDist == null || ent.getValue() < bestDist) {
					bestDests.clear();
					bestDests.add(ent.getKey());
					bestDist = ent.getValue();
				}
				else if (bestDist.equals(ent.getValue())) {
					bestDests.add(ent.getKey());
				}
			}
		}

		// Now collect all the shortest paths to those closest destinations
		Set<Deque<AssemblyConstructorSemantic>> result = new HashSet<>();
		for (Vertex d : bestDests) {
			Collection<Deque<Edge>> optimalPaths = dijkstra.computeOptimalPaths(s, d);
			for (Deque<Edge> path : optimalPaths) {
				Deque<AssemblyConstructorSemantic> sems = new LinkedList<>();
				for (Edge e : path) {
					sems.add(e.sem);
				}
				result.add(sems);
			}
		}
		return result;
	}

	/**
	 * Gather all the semantics that can be used as state transitions
	 * 
	 * Currently, only semantics from {@code :^instruction} constructors are taken.
	 */
	protected void gatherSemantics() {
		AssemblyProduction rec =
			grammar.getPureRecursion(grammar.getNonTerminal(grammar.getStartName()));
		if (rec == null) {
			return;
		}
		for (AssemblyConstructorSemantic sem : grammar.getSemantics(rec)) {
			semantics.get(grammar.getStartName()).add(sem);
		}
	}

	/**
	 * A vertex in a context transition graph
	 * 
	 * Each vertex consists of a context block and a (sub)table name
	 */
	protected static class Vertex implements Comparable<Vertex> {
		protected final AssemblyPatternBlock context;
		protected final String subtable;

		/**
		 * Construct a new vertex with the given block and subtable name
		 * @param context the context
		 * @param subtable the name
		 */
		protected Vertex(AssemblyPatternBlock context, String subtable) {
			this.context = context;
			this.subtable = subtable;
		}

		/**
		 * Check if this and another vertex "agree"
		 * 
		 * This doesn't mean they're equal, but that they share a subtable, and the defined bits of
		 * their context blocks agree.
		 * @param that the other vertex
		 * @return true iff they share subtables and defined bits
		 */
		public boolean matches(Vertex that) {
			if (!this.subtable.equals(that.subtable)) {
				return false;
			}
			if (this.context.combine(that.context) == null) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return context.hashCode() * 31 + subtable.hashCode();
		}

		@Override
		public String toString() {
			return "ctx:" + context + " at " + subtable;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Vertex)) {
				return false;
			}
			Vertex that = (Vertex) o;
			if (!this.context.equals(that.context)) {
				return false;
			}
			if (!this.subtable.equals(that.subtable)) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(Vertex that) {
			int result;
			result = this.context.compareTo(that.context);
			if (result != 0) {
				return result;
			}
			result = this.subtable.compareTo(that.subtable);
			if (result != 0) {
				return result;
			}
			return 0;
		}
	}

	/**
	 * A transition in a context transition graph
	 * 
	 * A transition consists of the constructor whose context changes were applied. The operand
	 * index is included for reference and debugging. If we ever need to process rules with
	 * multiple subconstructors, the operand index explains the subtable name of the destination
	 * vertex.
	 */
	protected static class Edge implements GEdge<Vertex>, Comparable<Edge> {
		protected final AssemblyConstructorSemantic sem;
		protected final int op;

		protected final Vertex start;
		protected final Vertex end;

		/**
		 * Construct a new transition associated with the given constructor and operand index
		 * @param sem the constructor semantic
		 * @param op the operand index
		 */
		public Edge(AssemblyConstructorSemantic sem, int op, Vertex start, Vertex end) {
			this.sem = sem;
			this.op = op;
			this.start = start;
			this.end = end;
		}

		@Override
		public int hashCode() {
			int result = sem.hashCode();
			result *= 31;
			result += Integer.hashCode(op);
			result *= 31;
			result += start.hashCode();
			result *= 31;
			result += end.hashCode();
			return result;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Edge)) {
				return false;
			}
			Edge that = (Edge) o;
			if (!this.sem.equals(that.sem)) {
				return false;
			}
			if (this.op != that.op) {
				return false;
			}
			if (!this.start.equals(that.start)) {
				return false;
			}
			if (!this.end.equals(that.end)) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(Edge that) {
			int result;
			result = this.sem.compareTo(that.sem);
			if (result != 0) {
				return result;
			}
			result = this.op - that.op;
			if (result != 0) {
				return result;
			}
			result = this.start.compareTo(that.start);
			if (result != 0) {
				return result;
			}
			result = this.end.compareTo(that.end);
			if (result != 0) {
				return result;
			}
			return 0;
		}

		@Override
		public String toString() {
			return start + " --[" + sem + " op " + op + "]-> " + end;
		}

		@Override
		public Vertex getStart() {
			return start;
		}

		@Override
		public Vertex getEnd() {
			return end;
		}
	}

	protected Set<Edge> computeOutEdges(Vertex from) {
		cachedVertices.add(from);
		Set<Edge> result = new HashSet<>();
		for (AssemblyConstructorSemantic sem : semantics.get(from.subtable)) {
			for (AssemblyResolvedConstructor rc : sem.patterns) {
				AssemblyPatternBlock pattern = rc.ctx;
				AssemblyPatternBlock outer = from.context.combine(pattern);
				if (outer == null) {
					continue;
				}
				if (sem.getConstructor().getNumOperands() == 0) {
					continue;
				}

				AssemblyResolvedConstructor orc =
					AssemblyResolution.contextOnly(outer, "For context transition", null);
				AssemblyResolvedConstructor irc = sem.applyForward(orc);
				AssemblyPatternBlock inner = irc.getContext();

				Constructor ct = sem.getConstructor();
				for (int i = 0; i < ct.getNumOperands(); i++) {
					OperandSymbol op = ct.getOperand(i);
					TripleSymbol def = op.getDefiningSymbol();
					if (!(def instanceof SubtableSymbol)) {
						continue;
					}
					SubtableSymbol subtable = (SubtableSymbol) def;

					// TODO: Remove this check, eventually
					// NOTE: If pure recursion appears anywhere other than "instruction", this
					// check will prevent it from being handled.
					if (!from.subtable.equals(subtable.getName())) {
						continue;
					}

					Vertex dest = new Vertex(inner, subtable.getName());
					cachedVertices.add(dest);
					Edge e = new Edge(sem, i, from, dest);
					cachedEdges.add(e);
					result.add(e);
				}
			}
		}
		return result;
	}

	/**
	 * This operation is not supported.
	 * 
	 * I could implement this using the cached edges, but that may not be semantically, what a path
	 * computation algorithm actually requires. Instead, I will assume the algorithm only explores
	 * the graph in the same direction as its edges. If not, I will hear about it quickly.
	 */
	@Override
	public Collection<Edge> getInEdges(Vertex v) {
		throw new UnsupportedOperationException("Does not support backward traversal");
	}

	@Override
	public Collection<Edge> getOutEdges(Vertex v) {
		return cachedOutEdges.get(v);
	}

	/**
	 * Returns a copy of the graph explored so far
	 */
	@Override
	public GDirectedGraph<Vertex, Edge> copy() {
		GDirectedGraph<Vertex, Edge> graph = GraphFactory.createDirectedGraph();
		for (Vertex v : cachedVertices) {
			graph.addVertex(v);
		}
		for (Edge e : cachedEdges) {
			graph.addEdge(e);
		}
		return graph;
	}
}
