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

import java.util.*;

import generic.util.DequePush;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential.TruncatedWhiteSpaceParseToken;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseActionGotoTable.*;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.assembler.sleigh.util.SleighUtil;

/**
 * A class that implements the LALR(1) parsing algorithm
 * 
 * Instances of this class store a parse state. In order to work correctly, the class must be
 * given a properly-constructed Action/Goto table.
 * 
 * This implementation is somewhat unconventional. First, instead of strictly tokenizing and then
 * parsing, each terminal is given the opportunity to match a token in the input. If none match, it
 * results in a syntax error (equivalent to the token type having an empty cell in the classical
 * algorithm). If more than one match, the parser branches. Also, because a single cell may also
 * contain multiple actions, the parser could branch again. Thus, if a sentence is ambiguous, this
 * algorithm will identify all possible parse trees, including ones where the input is tokenized
 * differently than in other trees.
 */
public class AssemblyParseMachine implements Comparable<AssemblyParseMachine> {
	private static final int ERROR_NONE = 0;
	private static final int ERROR_SYNTAX = 1;

	// The parser, containing the Action/Goto table
	protected final AssemblyParser parser;

	// The formal output of the parser
	protected final List<Integer> output = new ArrayList<>(); // for checking, debugging...?
	// The format stack of the parser
	protected final Stack<Integer> stack = new Stack<>();
	// The stack of trees actually used by the assembler
	protected final Stack<AssemblyParseTreeNode> treeStack = new Stack<>();
	// The formal input buffer of the parser
	protected final String buffer;
	// The position in the buffer where we are parsing.
	protected int pos;
	// The last token we consumed (i.e., last terminal pushed to the stack)
	protected AssemblyParseToken lastTok;

	// A set of labels that identify valid tokens for some terminals
	protected final Map<String, Long> labels; // used for label -> number substitution

	protected boolean accepted = false; // the machine is in the accepted state
	protected int error = ERROR_NONE; // non-zero if the machine is in an error state
	protected String got; // if in error, provides the remaining characters in the buffer
	protected Collection<AssemblyTerminal> expected; // if in error, provides suggestions

	protected final int id; // convenient ID for debug printing

	static int nextMachineId = 0;

	static final DbgTimer dbg = DbgTimer.INACTIVE;

	/**
	 * Construct a new parse state
	 * @param parser the parser driving this machine
	 * @param input the full input line
	 * @param pos the position in the line identifying the next characters to parse
	 * @param labels a map of valid tokens to number for numeric terminals
	 */
	public AssemblyParseMachine(AssemblyParser parser, String input, int pos,
			AssemblyParseToken lastTok, Map<String, Long> labels) {
		this.parser = parser;
		this.stack.push(0);
		this.buffer = input;
		this.pos = pos;
		this.lastTok = lastTok;
		this.id = nextMachineId++;
		this.labels = labels;
	}

	/* ********************************************************************************************
	 * Equality, comparison, etc.
	 */
	// NOTE: Buffer is ignored. Machines parsing different buffers should NEVER be in the same
	// collection.

	@Override
	public int hashCode() {
		int result = pos;
		for (int s : output) {
			result *= 31;
			result += s;
		}
		/*for (int s : stack) {
			result *= 31;
			result += s;
		}*/ // Does not distinguish among multiple matches on a single terminal
		for (AssemblyParseTreeNode s : treeStack) {
			result *= 31;
			result += s.hashCode();
		}
		result *= 31;
		result += accepted ? 1 : 0;
		result *= 31;
		result += error;
		return result;
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof AssemblyParseMachine)) {
			return false;
		}
		AssemblyParseMachine apm = (AssemblyParseMachine) that;
		if (this.pos != apm.pos) {
			return false;
		}
		if (!this.output.equals(apm.output)) {
			return false;
		}
		if (!this.stack.equals(apm.stack)) {
			return false;
		}
		if (this.accepted != apm.accepted) {
			return false;
		}
		if (this.error != apm.error) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(AssemblyParseMachine that) {
		int result;

		result = this.pos - that.pos;
		if (result != 0) {
			return result;
		}

		result = SleighUtil.compareInOrder(this.stack, that.stack);
		if (result != 0) {
			return result;
		}

		result = SleighUtil.compareInOrder(this.output, that.output);
		if (result != 0) {
			return result;
		}
		if (this.accepted & !that.accepted) {
			return 1;
		}
		if (!this.accepted & that.accepted) {
			return -1;
		}
		result = (this.error - that.error);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	/* *******************************************************************************************/

	/**
	 * Duplicate this machine state
	 * 
	 * This is used extensively when branching
	 * @return the duplicate
	 */
	public AssemblyParseMachine copy() {
		AssemblyParseMachine c = new AssemblyParseMachine(parser, buffer, pos, lastTok, labels);
		// leave labels copied by reference

		c.output.clear();
		c.output.addAll(output);

		c.stack.clear();
		c.stack.addAll(stack);

		c.treeStack.clear();
		c.treeStack.addAll(treeStack);

		c.accepted = accepted;
		c.error = error;

		dbg.println("Copied " + id + " to " + c.id);
		return c;
	}

	/**
	 * Perform a given action and continue parsing, exhausting all results after the action
	 * @param a the action
	 * @param tok the token given by the terminal (column) of the entry containing this action
	 * @param results a place to store all the parsing results (each must be accept or error state)
	 * @param visited a collection of machine states already visited
	 * 
	 * The visited "collection" prevents infinite loops or stack overflows resulting from
	 * "consuming" epsilon and going to the same state. Such loops may involve many states. It is
	 * also defined as a map here for debugging purposes, so that when a loop is detected, we can
	 * print the ID of the first visit.
	 */
	protected void doAction(Action a, AssemblyParseToken tok, Set<AssemblyParseMachine> results,
			Deque<AssemblyParseMachine> visited) {
		try (DbgCtx dc = dbg.start("Action: " + a)) {
			if (a instanceof ShiftAction) {
				AssemblyParseMachine m = copy();
				m.stack.push(((ShiftAction) a).newStateNum);
				m.treeStack.push(tok);
				m.lastTok = tok;
				m.pos += tok.getString().length();
				m.exhaust(results, visited);
			}
			else if (a instanceof ReduceAction) {
				AssemblyProduction prod = ((ReduceAction) a).prod;
				AssemblyParseBranch branch = new AssemblyParseBranch(parser.grammar, prod);
				AssemblyParseMachine m = copy();
				m.output.add(prod.getIndex());
				dbg.println("Prod: " + prod);
				for (@SuppressWarnings("unused")
				AssemblySymbol sym : prod) {
					m.stack.pop();
					branch.addChild(m.treeStack.pop());
				}
				for (Action aa : m.parser.actions.get(m.stack.peek(), prod.getLHS())) {
					GotoAction ga = (GotoAction) aa;
					dbg.println("Goto: " + ga);
					AssemblyParseMachine n = m.copy();
					n.stack.push(ga.newStateNum);
					n.treeStack.push(branch);
					n.exhaust(results, visited);
				}
			}
			else if (a instanceof AcceptAction) {
				AssemblyParseMachine m = copy();
				m.accepted = true;
				results.add(m);
			}
		}
	}

	/**
	 * Consume a given terminal (and corresponding token) and continue parsing
	 * @param t the terminal
	 * @param tok the corresponding token
	 * @param results a place to store all the parsing results
	 * @param visited a collection of machine states already visited
	 */
	protected void consume(AssemblyTerminal t, AssemblyParseToken tok,
			Set<AssemblyParseMachine> results, Deque<AssemblyParseMachine> visited) {
		try (DbgCtx dc = dbg.start("Matched " + t + " " + tok)) {
			Collection<Action> as = parser.actions.get(stack.peek(), t);
			assert !as.isEmpty();
			dbg.println("Actions: " + as);
			for (Action a : as) {
				doAction(a, tok, results, visited);
			}
		}
	}

	/**
	 * Look for previous machine states having the same stack and position
	 * 
	 * This would imply we have gone in a loop without consuming anything. We need to prune.
	 * @param machine the machine state to check
	 * @param visited the stack of previous machine states
	 * @return if there is a loop, the machine state proving it, null otherwise
	 */
	protected static AssemblyParseMachine findLoop(AssemblyParseMachine machine,
			Collection<AssemblyParseMachine> visited) {
		for (AssemblyParseMachine v : visited) {
			if (v == machine) {
				continue;
			}
			if (v.pos != machine.pos) {
				continue;
			}
			if (!v.stack.equals(machine.stack)) {
				continue;
			}
			return v;
		}
		return null;
	}

	@Override
	public String toString() {
		return stack + ":" + treeStack + ":" + buffer + " (" + pos + ")";
	}

	/**
	 * Parse (or continue parsing) all possible trees from this machine state
	 * @param results a place to store all the parsing results
	 * @param visited a collection of machine states already visited
	 */
	protected void exhaust(Set<AssemblyParseMachine> results, Deque<AssemblyParseMachine> visited) {
		try (DbgCtx dc = dbg.start("Exhausting machine " + id)) {
			dbg.println("Machine: " + this);
			AssemblyParseMachine loop = findLoop(this, visited);
			if (loop != null) {
				dbg.println("Pruned. Loop of " + loop.id);
				return;
			}
			try (DequePush<?> push = DequePush.push(visited, this)) {
				if (error != ERROR_NONE) {
					throw new AssertionError("INTERNAL: Tried to step a machine with errors");
				}
				if (accepted) {
					// Gratuitous inputs should be detected by getTree
					throw new AssertionError("INTERNAL: Tried to step an accepted machine");
				}
				Collection<AssemblyTerminal> terms = parser.actions.getExpected(stack.peek());
				if (terms.isEmpty()) {
					throw new RuntimeException("Encountered a state with no actions");
				}
				Set<AssemblyTerminal> unmatched = new TreeSet<>(terms);
				for (AssemblyTerminal t : terms) {
					for (AssemblyParseToken tok : t.match(buffer, pos, parser.grammar, labels)) {
						unmatched.remove(t);
						assert buffer.regionMatches(pos, tok.getString(), 0,
							tok.getString().length());
						consume(t, tok, results, visited);
					}
				}
				if (!unmatched.isEmpty()) {
					AssemblyParseMachine m = copy();
					final Collection<AssemblyTerminal> newExpected;
					if (m.lastTok == null ||
						!(m.lastTok instanceof TruncatedWhiteSpaceParseToken)) {
						newExpected = unmatched;
					}
					else {
						newExpected = new TreeSet<>();
						newExpected.add(AssemblySentential.WHITE_SPACE);
					}
					dbg.println("Syntax Error: ");
					dbg.println("  Expected: " + newExpected);
					dbg.println("  Got: " + buffer.substring(pos));
					m.error = ERROR_SYNTAX;
					m.got = buffer.substring(pos);
					m.expected = newExpected;
					results.add(m);
					return;
				}
			}
		}
	}

	/**
	 * Parse (or continue parsing) all possible trees from this machine state
	 * @return the set of all possible trees and errors
	 */
	public Set<AssemblyParseMachine> exhaust() {
		Set<AssemblyParseMachine> results = new LinkedHashSet<>();
		Deque<AssemblyParseMachine> visited = new LinkedList<>();
		exhaust(results, visited);
		return results;
	}

	/**
	 * If in the accepted state, get the resulting parse tree for this machine
	 * @return the parse tree
	 */
	public AssemblyParseBranch getTree() {
		if (!accepted) {
			throw new AssertionError("INTERNAL: Machine has not accepted its buffer");
		}
		if (pos != buffer.length()) {
			throw new AssertionError("INTERNAL: Machine has not emptied its buffer");
		}
		if (!treeStack.pop().getSym().equals(AssemblyEOI.EOI)) {
			throw new AssertionError("INTERNAL: Machine has not encountered end of input marker");
		}
		if (treeStack.size() != 1) {
			throw new AssertionError("INTERNAL: More than root branch remains on machine stack");
		}
		return (AssemblyParseBranch) treeStack.pop();
	}
}
