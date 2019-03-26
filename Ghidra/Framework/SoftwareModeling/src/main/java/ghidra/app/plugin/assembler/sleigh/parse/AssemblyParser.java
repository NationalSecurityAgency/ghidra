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
package ghidra.app.plugin.assembler.sleigh.parse;

import java.io.PrintStream;
import java.util.*;
import java.util.function.Consumer;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.sleigh.grammars.*;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.assembler.sleigh.util.TableEntry;

/**
 * A class to encapsulate LALR(1) parsing for a given grammar
 * 
 * This class constructs the Action/Goto table (and all the other trappings) of a LALR(1) parser
 * and provides a {@link #parse(String)} method to parse actual sentences.
 * 
 * This implementation is somewhat unconventional in that it permits ambiguous grammars. Instead of
 * complaining, it produces the set of all possible parse trees. Of course, this comes at the cost
 * of some efficiency.
 * 
 * See Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman, <i>Compilers: Principles,
 * Techniques, &amp; Tools</i>. Bostom, MA: Pearson, 2007.
 * 
 * See Jackson, Stephen. <a href="http://web.cs.dal.ca/~sjackson/lalr1.html">LALR(1) Parsing</a>.
 * Halifax, Nova Scotia, Canada: Dalhousie University.
 * &lt;http://web.cs.dal.ca/~sjackson/lalr1.html&gt;
 */
public class AssemblyParser {
	protected final AssemblyGrammar grammar; // The input grammar
	protected final AssemblyFirstFollow ff; // The first and follow sets for the input grammar

	// LR(0) fodder
	protected final ArrayList<AssemblyParseState> states = new ArrayList<>();
	protected final AssemblyParseTransitionTable table = new AssemblyParseTransitionTable();

	// see Stephen Jackson's rant regarding this fodder
	protected AssemblyExtendedGrammar extendedGrammar;
	protected final AssemblyFirstFollow extff;
	protected Map<MergeKey, MergeValue> mergers;

	// the LALR(1) Action/Goto table
	protected AssemblyParseActionGotoTable actions;

	/** A convenience to specify no labels in {@link #parse(String, Map)} */
	public static final Map<String, Long> EMPTY_LABELS =
		Collections.unmodifiableMap(new HashMap<String, Long>());

	protected static final DbgTimer dbg = DbgTimer.INACTIVE;
	protected static final boolean dbg_detail = false;

	/**
	 * Construct a LALR(1) parser from the given grammar
	 * @param grammar the grammar
	 */
	public AssemblyParser(AssemblyGrammar grammar) {
		this.grammar = grammar;

		// Check if the start production is of the form
		// A => B, where A != B, and that is the only production of A
		// If not, synthesize a new start symbol
		String newName = "$S";
		while (grammar.contains(newName)) {
			newName = "$" + newName;
		}
		AssemblyNonTerminal start = new AssemblyNonTerminal(newName);
		grammar.addProduction(start, new AssemblySentential<>(grammar.getStart(), AssemblyEOI.EOI));
		grammar.setStart(start);

		try (DbgCtx dc = dbg.start("Computing First/Follow for General Grammar")) {
			this.ff = new AssemblyFirstFollow(grammar);
			if (dbg_detail) {
				printGeneralFF(dbg);
			}
		}

		try (DbgCtx dc = dbg.start("Computing LR0 States and Transition Table")) {
			buildLR0Machine();
			if (dbg_detail) {
				printLR0States(dbg);
				printLR0TransitionTable(dbg);
			}
		}

		try (DbgCtx dc = dbg.start("Computing Extended Grammar")) {
			buildExtendedGrammar();
			if (dbg_detail) {
				printExtendedGrammar(dbg);
			}
		}

		try (DbgCtx dc = dbg.start("Computing First/Follow for Extended Grammar")) {
			this.extff = new AssemblyFirstFollow(extendedGrammar);
			if (dbg_detail) {
				printExtendedFF(dbg);
			}
		}

		try (DbgCtx dc = dbg.start("Computing Parse Table")) {
			buildActionGotoTable();
			if (dbg_detail) {
				printParseTable(dbg);
			}
		}
	}

	protected void buildLR0Machine() {
		AssemblyProduction sp = grammar.productionsOf(grammar.getStart()).iterator().next();
		AssemblyParseStateItem startItem = new AssemblyParseStateItem(sp, 0);
		AssemblyParseState startState = new AssemblyParseState(grammar, startItem);
		states.add(startState);

		// I'm using a counting loop purposefully
		// Want to add things and process them later
		for (int curState = 0; curState < states.size(); curState++) {
			// perform a "read" or "goto" on each item, adding it to the kernel of its destination state
			// NOTE: destination state is keyed ONLY from curState and symbol read
			AssemblyParseState state = states.get(curState);
			// Since we work with one state at a time, we need only key on symbol read
			Map<AssemblySymbol, AssemblyParseState> go =
				LazyMap.lazyMap(new LinkedHashMap<AssemblySymbol, AssemblyParseState>(),
					() -> new AssemblyParseState(grammar));
			// Advance each item, and add the result to the kernel
			// NOTE: We must advance from the closure of the current state
			for (AssemblyParseStateItem item : state.getClosure()) {
				AssemblySymbol sym = item.getNext();
				if (sym != null) {
					AssemblyParseStateItem ni = item.read();
					go.get(sym).add(ni);
				}
			}
			// Now, add the appropriate entries to the transition table
			for (Map.Entry<AssemblySymbol, AssemblyParseState> ent : go.entrySet()) {
				int newStateNum = addLR0State(ent.getValue());
				table.put(curState, ent.getKey(), newStateNum);
			}
		}
	}

	/**
	 * Add a newly-constructed LR0 state, and return it's assigned number
	 * @param state the newly-constructed state
	 * @return the assigned number
	 * 
	 * If the state already exists, this just returns its previously assigned number
	 */
	protected int addLR0State(AssemblyParseState state) {
		int num = states.indexOf(state);
		if (num != -1) {
			return num;
		}
		states.add(state);
		return states.size() - 1;
	}

	protected void buildExtendedGrammar() {
		extendedGrammar = new AssemblyExtendedGrammar();
		extendedGrammar.setStartName(grammar.getStartName());
		for (int curState = 0; curState < states.size(); curState++) {
			AssemblyParseState state = states.get(curState);
			for (AssemblyParseStateItem item : state.getClosure()) {
				if (item.getPos() == 0) {
					AssemblyExtendedProduction ext = extend(item.getProduction(), curState);
					extendedGrammar.addProduction(ext);
				}
			}
		}
	}

	/**
	 * Extend a production, using the given LR0 start state
	 * @param prod the production to extend
	 * @param start the starting LR0 state
	 * @return the extended production, if the start state is valid for it
	 */
	protected AssemblyExtendedProduction extend(AssemblyProduction prod, int start) {
		AssemblySentential<AssemblyExtendedNonTerminal> extR = new AssemblySentential<>();
		int curState = start;
		for (AssemblySymbol sym : prod) {
			int nextState = table.get(curState, sym);
			if (sym instanceof AssemblyTerminal) {
				extR.add(sym);
			}
			else if (sym instanceof AssemblyNonTerminal) {
				extR.add(new AssemblyExtendedNonTerminal(curState, (AssemblyNonTerminal) sym,
					nextState));
			}
			else {
				throw new RuntimeException(
					"Internal error: all AssemblySymbols must be either terminal or non-terminal");
			}
			curState = nextState;
		}
		AssemblyNonTerminal lhs = prod.getLHS();
		int nextState = -1;
		if (!lhs.equals(grammar.getStart())) {
			nextState = table.get(start, prod.getLHS());
		}
		AssemblyExtendedNonTerminal extL =
			new AssemblyExtendedNonTerminal(start, prod.getLHS(), nextState);
		return new AssemblyExtendedProduction(extL, extR, curState, prod);
	}

	protected void buildActionGotoTable() {
		actions = new AssemblyParseActionGotoTable();

		// Copy the translations tables NT columns as GOTOs
		// Also, copy the T columns as SHIFTs
		table.forEach(new Consumer<TableEntry<Integer>>() {
			@Override
			public void accept(TableEntry<Integer> ent) {
				if (ent.getSym() instanceof AssemblyNonTerminal) {
					AssemblyNonTerminal nt = (AssemblyNonTerminal) ent.getSym();
					actions.putGoto(ent.getState(), nt, ent.getValue());
				}
				else if (ent.getSym() instanceof AssemblyTerminal) {
					AssemblyTerminal t = (AssemblyTerminal) ent.getSym();
					actions.putShift(ent.getState(), t, ent.getValue());
				}
				else {
					throw new AssertionError("INTERNAL: symbols must be T or NT");
				}
			}
		});

		// Merge rules from same general rule, ending in same state
		mergers =
			LazyMap.lazyMap(new LinkedHashMap<MergeKey, MergeValue>(), () -> new MergeValue());
		int i = -1;
		for (AssemblyExtendedProduction prod : extendedGrammar) {
			i++;
			MergeValue entry = mergers.get(new MergeKey(prod.getFinalState(), prod.getAncestor()));
			entry.merge(i, extff.getFollow(prod.getLHS()));
		}

		// Write merged stuff to table as REDUCEs
		for (Map.Entry<MergeKey, MergeValue> ent : mergers.entrySet()) {
			for (AssemblyTerminal t : ent.getValue().follow) {
				AssemblyProduction prod = ent.getKey().prod;
				if (!prod.getLHS().equals(grammar.getStart())) {
					actions.putReduce(ent.getKey().finalState, t, prod);
				}
			}
		}

		// Make $ accept on any state with a completed start item.
		nextState: for (i = 0; i < states.size(); i++) {
			AssemblyParseState state = states.get(i);
			for (AssemblyParseStateItem item : state) {
				if (item.completed() && item.getProduction().getLHS().getName().equals("$S")) {
					actions.putAccept(i);
					continue nextState;
				}
			}
		}
	}

	/**
	 * A map key used to identify merges for Step 4 in Stephen Jackson's rant
	 */
	protected static class MergeKey implements Comparable<MergeKey> {
		int finalState;
		AssemblyProduction prod;

		protected MergeKey(int finalState, AssemblyProduction prod) {
			this.finalState = finalState;
			this.prod = prod;
		}

		@Override
		public int hashCode() {
			int result = 0;
			result += finalState;
			result *= 31;
			result += prod.hashCode();
			return result;
		}

		@Override
		public boolean equals(Object that) {
			if (!(that instanceof MergeKey)) {
				return false;
			}
			MergeKey mk = (MergeKey) that;
			if (this.finalState != mk.finalState) {
				return false;
			}
			if (!this.prod.equals(mk.prod)) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(MergeKey that) {
			int result;
			result = this.finalState - that.finalState;
			if (result != 0) {
				return result;
			}
			result = this.prod.compareTo(that.prod);
			if (result != 0) {
				return result;
			}
			return 0;
		}
	}

	/**
	 * The map value keyed by {@link MergeKey}
	 */
	protected static class MergeValue {
		Set<Integer> extProds = new TreeSet<>();
		Set<AssemblyTerminal> follow = new TreeSet<>();

		protected void merge(int extProdNum, Collection<AssemblyTerminal> more) {
			extProds.add(extProdNum);
			this.follow.addAll(more);
		}
	}

	/**
	 * Parse the given sentence
	 * @param input the sentence to parse
	 * @return all possible parse trees (and possible errors)
	 */
	public Iterable<AssemblyParseResult> parse(final String input) {
		return parse(input, EMPTY_LABELS);
	}

	/**
	 * Parse the given sentence with the given defined labels
	 * @param input the sentence to parser
	 * @param labels a map of label to number substitutions
	 * @return all possible parse results (trees and errors)
	 * 
	 * The tokenizer for numeric terminals also accepts any key in {@code labels.} In such cases,
	 * the resulting token is assigned the value of the label.
	 */
	public Collection<AssemblyParseResult> parse(final String input, Map<String, Long> labels) {
		AssemblyParseMachine init = new AssemblyParseMachine(this, input, 0, null, labels);
		Set<AssemblyParseMachine> results = init.exhaust();

		Set<AssemblyParseResult> ret = new LinkedHashSet<>();
		for (AssemblyParseMachine m : results) {
			if (m.accepted) {
				ret.add(AssemblyParseResult.accept(m.getTree()));
			}
			else if (m.error != 0) {
				Set<String> suggestions = new TreeSet<>();
				for (AssemblyTerminal t : m.expected) {
					suggestions.addAll(t.getSuggestions(m.got, labels));
				}
				ret.add(AssemblyParseResult.error(m.got, suggestions));
			}
			else {
				throw new AssertionError("INTERNAL: Unfinished machine was returned");
			}
		}
		return ret;
	}

	/**
	 * For debugging
	 */
	public void printGrammar(PrintStream out) {
		out.println("\nGeneral Grammar:");
		grammar.print(out);
	}

	/**
	 * For debugging
	 */
	public void printLR0States(PrintStream out) {
		out.println("\nLR0 States:");
		for (int i = 0; i < states.size(); i++) {
			AssemblyParseState state = states.get(i);
			out.println("I" + i);
			for (AssemblyParseStateItem item : state) {
				out.println("K: " + item);
			}
			for (AssemblyParseStateItem item : state.getClosure()) {
				if (!state.contains(item)) {
					out.println("C: " + item);
				}
			}
		}
	}

	/**
	 * For debugging
	 */
	public void printLR0TransitionTable(PrintStream out) {
		out.println("\nLR0 Transition Table:");
		out.print("State\t");
		for (AssemblyTerminal t : grammar.terminals()) {
			out.print(t + "\t");
		}
		for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
			out.print(nt + "\t");
		}
		out.println();
		for (int i = 0; i < states.size(); i++) {
			out.print(i + "\t");
			for (AssemblyTerminal t : grammar.terminals()) {
				Integer newState = table.get(i, t);
				if (newState != null) {
					out.print(newState);
				}
				out.print("\t");
			}
			for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
				Integer newState = table.get(i, nt);
				if (newState != null) {
					out.print(newState);
				}
				out.print("\t");
			}
			out.println();
		}
	}

	/**
	 * For debugging
	 */
	public void printExtendedGrammar(PrintStream out) {
		out.println("\nExtended Grammar:");
		extendedGrammar.print(out);
	}

	/**
	 * For debugging
	 */
	public void printGeneralFF(PrintStream out) {
		out.println("\nGeneral FF:");
		ff.print(out);
	}

	/**
	 * For debugging
	 */
	public void printExtendedFF(PrintStream out) {
		out.println("\nExtended FF:");
		extff.print(out);
	}

	/**
	 * For debugging
	 */
	public void printMergers(PrintStream out) {
		out.println("\nMergers:");
		for (Map.Entry<MergeKey, MergeValue> ent : mergers.entrySet()) {
			out.print(ent.getKey().finalState + "\t");
			out.print(ent.getKey().prod + "\t");
			out.print(ent.getValue().extProds + "\t");
			out.print(ent.getValue().follow + "\n");
		}
	}

	/**
	 * For debugging
	 */
	public void printParseTable(PrintStream out) {
		out.println("\nParse Table:");
		out.print("State\t");
		for (AssemblyTerminal t : grammar.terminals()) {
			out.print(t + "\t");
		}
		for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
			out.print(nt + "\t");
		}
		out.println();
		for (int i = 0; i < states.size(); i++) {
			out.print(i + "\t");
			for (AssemblyTerminal t : grammar.terminals()) {
				out.print(StringUtils.join(actions.get(i, t), "/"));
				out.print("\t");
			}
			for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
				out.print(StringUtils.join(actions.get(i, nt), "/"));
				out.print("\t");
			}
			out.println();
		}
	}

	/**
	 * For debugging
	 */
	public void printStuff(PrintStream out) {
		printGrammar(out);
		printGeneralFF(out);
		printLR0States(out);
		printLR0TransitionTable(out);
		printExtendedGrammar(out);
		printExtendedFF(out);
		printMergers(out);
		printParseTable(out);
	}

	/**
	 * Get the grammar used to construct this parser
	 * @return the grammar
	 */
	public AssemblyGrammar getGrammar() {
		return grammar;
	}
}
