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

import static org.junit.Assert.*;

import java.io.PrintStream;
import java.util.*;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import ghidra.app.plugin.assembler.sleigh.grammars.*;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.assembler.sleigh.util.SleighUtil;
import ghidra.util.NullOutputStream;

public class ParserTest {

	private boolean tracing = false;
	private PrintStream out = tracing ? System.out : new PrintStream(new NullOutputStream());

	@Test
	public void testFirstFollow() throws Exception {
		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal E = new AssemblyNonTerminal("E");
		AssemblyNonTerminal T = new AssemblyNonTerminal("T");
		AssemblyNonTerminal F = new AssemblyNonTerminal("F");

		addProduction(E, g, E, "+", T);
		addProduction(E, g, T);

		addProduction(T, g, T, "*", F);
		addProduction(T, g, F);

		addProduction(F, g, "(", E, ")");
		addProduction(F, g, "a");

		g.print(out);
		out.println("Computing sets");
		AssemblyFirstFollow ff = new AssemblyFirstFollow(g);

		printFirstFollow(ff, g);

		assertEquals(Collections.emptySet(), ff.getNullable());

		Set<AssemblyTerminal> firstEFT = new TreeSet<>();
		firstEFT.add(g.getTerminal("\"(\""));
		firstEFT.add(g.getTerminal("\"a\""));
		assertEquals(firstEFT, new TreeSet<>(ff.getFirst(E)));
		assertEquals(firstEFT, new TreeSet<>(ff.getFirst(F)));
		assertEquals(firstEFT, new TreeSet<>(ff.getFirst(T)));

		Set<AssemblyTerminal> followE = new TreeSet<>();
		followE.add(g.getTerminal("\")\""));
		followE.add(g.getTerminal("\"+\""));
		Set<AssemblyTerminal> followFT = new TreeSet<>(followE);
		followFT.add(g.getTerminal("\"*\""));
		assertEquals(followE, new TreeSet<>(ff.getFollow(E)));
		assertEquals(followFT, new TreeSet<>(ff.getFollow(F)));
		assertEquals(followFT, new TreeSet<>(ff.getFollow(T)));
	}

	private void printFirstFollow(AssemblyFirstFollow ff, AssemblyGrammar g) {
		out.print("Nullable: ");
		for (AssemblyNonTerminal nt : ff.getNullable()) {
			out.print(nt + " ");
		}
		out.println();
		out.println("Firsts:");
		for (AssemblyNonTerminal nt : g.nonTerminals()) {
			out.print(nt + "\t");
			for (AssemblyTerminal first : ff.getFirst(nt)) {
				out.print(first + " ");
			}
			out.println();
		}
		out.println("Follows:");
		for (AssemblyNonTerminal nt : g.nonTerminals()) {
			out.print(nt + "\t");
			for (AssemblyTerminal follow : ff.getFollow(nt)) {
				out.print(follow + " ");
			}
			out.println();
		}
	}

	@Test
	public void testLRStates() throws Exception {
		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal Sp = new AssemblyNonTerminal("S'");
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		AssemblyNonTerminal X = new AssemblyNonTerminal("X");

		addProduction(Sp, g, S);

		addProduction(S, g, X, X);

		addProduction(X, g, "a", X);
		addProduction(X, g, "b");

		AssemblyParser parser = new AssemblyParser(g);
		parser.printLR0States(out);

		// I don't care the state numbers, but I do want to make sure every state is present
		Comparator<Set<AssemblyParseStateItem>> comp = (Set<AssemblyParseStateItem> a,
				Set<AssemblyParseStateItem> b) -> SleighUtil.compareInOrder(a, b);
		TreeSet<Set<AssemblyParseStateItem>> states = new TreeSet<>(comp);
		for (AssemblyParseState pstate : parser.states) {
			TreeSet<AssemblyParseStateItem> state = new TreeSet<>(pstate);
			states.add(state);
		}

		TreeSet<Set<AssemblyParseStateItem>> expected = new TreeSet<>(comp);
		Map<Integer, AssemblyProduction> prods = new TreeMap<>();
		for (AssemblyProduction prod : g) {
			prods.put(prod.getIndex(), prod);
		}
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(4), 0)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(4), 1)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(0), 1)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(1), 1)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(2), 1)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(3), 1)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(4), 2)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(1), 2)));
		expected.add(Collections.singleton(new AssemblyParseStateItem(prods.get(2), 2)));

		assertEquals(expected, states);
	}

	@Test
	public void testLALRWithEpsilon37() throws Exception {
		// This comes from page 37 of http://digital.cs.usu.edu/~allan/Compilers/Notes/LRParsing.pdf

		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal Ep = new AssemblyNonTerminal("E'");
		AssemblyNonTerminal E = new AssemblyNonTerminal("E");
		AssemblyNonTerminal T = new AssemblyNonTerminal("T");
		AssemblyNonTerminal F = new AssemblyNonTerminal("F");

		addProduction(Ep, g, E);

		addProduction(E, g, E, "+", T);
		addProduction(E, g, T);

		addProduction(T, g, T, F);
		addProduction(T, g, F);

		addProduction(F, g, F, "*");
		addProduction(F, g, "(", E, ")");
		addProduction(F, g, "a");
		addProduction(F, g, "b");
		addProduction(F, g);

		AssemblyParser parser = new AssemblyParser(g);
		parser.printLR0States(out);
		parser.printLR0TransitionTable(out);
		parser.printGeneralFF(out);
		parser.printExtendedGrammar(out);
		parser.printExtendedFF(out);
		parser.printMergers(out);
		parser.printParseTable(out);

		String sentence = "(ab+a)*b";
		Iterable<AssemblyParseResult> results = parser.parse(sentence);
		String expected = StringUtils.join(new String[] { //
			"[E'] := 0. [E'] => [E]", //
			"  [E] := 2. [E] => [T]", //
			"    [T] := 3. [T] => [T] [F]", //
			"      [T] := 4. [T] => [F]", //
			"        [F] := 5. [F] => [F] \"*\"", //
			"          [F] := 6. [F] => \"(\" [E] \")\"", //
			"            \"(\" := '('", //
			"            [E] := 1. [E] => [E] \"+\" [T]", //
			"              [E] := 2. [E] => [T]", //
			"                [T] := 3. [T] => [T] [F]", //
			"                  [T] := 4. [T] => [F]", //
			"                    [F] := 7. [F] => \"a\"", //
			"                      \"a\" := 'a'", //
			"                  [F] := 8. [F] => \"b\"", //
			"                    \"b\" := 'b'", //
			"              \"+\" := '+'", //
			"              [T] := 4. [T] => [F]", //
			"                [F] := 7. [F] => \"a\"", //
			"                  \"a\" := 'a'", //
			"            \")\" := ')'", //
			"          \"*\" := '*'", //
			"      [F] := 8. [F] => \"b\"", //
			"        \"b\" := 'b'", //
		}, "\n").trim();
		boolean gotOne = false;
		int count = 0;
		for (AssemblyParseResult result : results) {
			out.println(result);
			if (result.isError()) {
				continue;
			}
			AssemblyParseAcceptResult acc = (AssemblyParseAcceptResult) result;
			assertEquals(sentence, acc.getTree().generateString());
			count++;
			if (expected.equals(result.toString().trim())) {
				gotOne = true;
			}
		}
		assertTrue(gotOne);
		assertEquals(12, count);
	}

	@Test
	public void testLALRWithEpsilon33999() throws Exception {
		// This comes from http://cs.stackexchange.com/questions/33999/lalr1-parsers-and-the-epsilon-transition

		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		AssemblyNonTerminal A = new AssemblyNonTerminal("A");
		AssemblyNonTerminal B = new AssemblyNonTerminal("B");

		addProduction(S, g, A);

		addProduction(A, g, B, "b");

		addProduction(B, g, B, "a");
		addProduction(B, g);

		out.println("Grammar:");
		g.print(out);

		AssemblyParser parser = new AssemblyParser(g);
		parser.printLR0States(out);
		parser.printLR0TransitionTable(out);
		parser.printGeneralFF(out);
		parser.printExtendedGrammar(out);
		parser.printExtendedFF(out);
		parser.printParseTable(out);

		Iterable<AssemblyParseResult> results = parser.parse("b");
		for (AssemblyParseResult result : results) {
			out.println(result);
		}
		Collection<AssemblyParseAcceptResult> valid = validOnly(results);
		assertEquals(1, valid.size());
		AssemblyParseAcceptResult acc = valid.iterator().next();
		AssemblyParseBranch tree = acc.getTree();

		/*
		 * [S] := 0. [S] => [A]
		 *   [A] := 1. [A] => [B] "b"
		 *     [B] := 3. [B] => e
		 *     "b" := 'b'
		 */
		assertEquals(0, tree.getProduction().getIndex());

		AssemblyParseTreeNode node = tree.getSubstitution(0);
		AssemblyParseBranch A1 = (AssemblyParseBranch) node;
		assertEquals(1, A1.getProduction().getIndex());

		node = A1.getSubstitution(0);
		AssemblyParseBranch B1 = (AssemblyParseBranch) node;
		assertEquals(3, B1.getProduction().getIndex());

		node = A1.getSubstitution(1);
		AssemblyParseToken b1 = (AssemblyParseToken) node;
		assertEquals("b", b1.getString());
	}

	@Test
	public void testLALRFromTutorial() throws Exception {
		// http://web.cs.dal.ca/~sjackson/lalr1.html

		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		AssemblyNonTerminal N = new AssemblyNonTerminal("N");
		AssemblyNonTerminal E = new AssemblyNonTerminal("E");
		AssemblyNonTerminal V = new AssemblyNonTerminal("V");

		addProduction(S, g, N);

		addProduction(N, g, V, "=", E);
		addProduction(N, g, E);

		addProduction(E, g, V);

		addProduction(V, g, "x");
		addProduction(V, g, "*", E);

		out.println("Grammar:");
		g.print(out);

		AssemblyParser parser = new AssemblyParser(g);
		parser.printLR0States(out);
		parser.printLR0TransitionTable(out);
		parser.printExtendedGrammar(out);
		parser.printGeneralFF(out);
		parser.printExtendedFF(out);
		parser.printMergers(out);
		parser.printParseTable(out);

		Iterable<AssemblyParseResult> results = parser.parse("x=*x");
		for (AssemblyParseResult result : results) {
			out.println(result);
		}
		Collection<AssemblyParseAcceptResult> valid = validOnly(results);
		assertEquals(1, valid.size());
		AssemblyParseAcceptResult acc = valid.iterator().next();
		AssemblyParseBranch tree = acc.getTree();

		/*
		 * [S] := 0. [S] => [N]
		 *   [N] := 1. [N] => [V] "=" [E]
		 *     [V] := 4. [V] => "x"
		 * 	     "x" := 'x'
		 *     "=" := '='
		 *     [E] := 3. [E] => [V]
		 *       [V] := 5. [V] => "*" [E]
		 *         "*" := '*'
		 *         [E] := 3. [E] => [V]
		 *           [V] := 4. [V] => "x"
		 *             "x" := 'x'
		 */
		assertEquals(0, tree.getProduction().getIndex());

		AssemblyParseTreeNode node = tree.getSubstitution(0);
		AssemblyParseBranch N1 = (AssemblyParseBranch) node;
		assertEquals(1, N1.getProduction().getIndex());

		node = N1.getSubstitution(0);
		AssemblyParseBranch V1 = (AssemblyParseBranch) node;
		assertEquals(4, V1.getProduction().getIndex());

		node = V1.getSubstitution(0);
		AssemblyParseToken x1 = (AssemblyParseToken) node;
		assertEquals("x", x1.getString());

		node = N1.getSubstitution(1);
		AssemblyParseToken eq1 = (AssemblyParseToken) node;
		assertEquals("=", eq1.getString());

		node = N1.getSubstitution(2);
		AssemblyParseBranch E1 = (AssemblyParseBranch) node;
		assertEquals(3, E1.getProduction().getIndex());

		node = E1.getSubstitution(0);
		AssemblyParseBranch V2 = (AssemblyParseBranch) node;
		assertEquals(5, V2.getProduction().getIndex());

		node = V2.getSubstitution(0);
		AssemblyParseToken mul1 = (AssemblyParseToken) node;
		assertEquals("*", mul1.getString());

		node = V2.getSubstitution(1);
		AssemblyParseBranch E2 = (AssemblyParseBranch) node;
		assertEquals(3, E2.getProduction().getIndex());

		node = E2.getSubstitution(0);
		AssemblyParseBranch V3 = (AssemblyParseBranch) node;
		assertEquals(4, V3.getProduction().getIndex());

		node = V3.getSubstitution(0);
		AssemblyParseToken x2 = (AssemblyParseToken) node;
		assertEquals("x", x2.getString());
	}

	@Test
	public void testListsFromARM() throws Exception {
		AssemblyGrammar g = new AssemblyGrammar();

		AssemblyNonTerminal S = new AssemblyNonTerminal("S");

		{ // LD
			AssemblyNonTerminal LD = new AssemblyNonTerminal("LD");
			AssemblyNonTerminal LD1 = new AssemblyNonTerminal("LD1");
			AssemblyNonTerminal LD2 = new AssemblyNonTerminal("LD2");

			addProduction(S, g, "list", LD);

			addProduction(LD, g, "[", "0", LD1, "]");
			addProduction(LD, g, "[", LD1, "]");

			addProduction(LD1, g, "1", LD2);
			addProduction(LD1, g, LD2);

			addProduction(LD2, g, "2");
			addProduction(LD2, g);
		}
		{ // LI
			AssemblyNonTerminal LI0 = new AssemblyNonTerminal("LI0");
			AssemblyNonTerminal LI1 = new AssemblyNonTerminal("LI1");
			AssemblyNonTerminal LI = new AssemblyNonTerminal("LI");

			addProduction(S, g, "list", LI);

			addProduction(LI, g, "[", LI1, "2", "]");
			addProduction(LI, g, "[", LI1, "]");

			addProduction(LI1, g, LI0, "1");
			addProduction(LI1, g, LI0);

			addProduction(LI0, g, "0");
			addProduction(LI0, g);
		}
		{ // SD
			AssemblyNonTerminal SD = new AssemblyNonTerminal("SD");
			AssemblyNonTerminal SD1 = new AssemblyNonTerminal("SD1");
			AssemblyNonTerminal SD2 = new AssemblyNonTerminal("SD2");

			addProduction(S, g, "list", SD);

			addProduction(SD, g, "[", "0", SD1, "]");
			addProduction(SD, g, "[", SD1, "]");

			addProduction(SD1, g, "1", SD2);
			addProduction(SD1, g, SD2);

			addProduction(SD2, g, "2");
			addProduction(SD2, g);
		}
		{ // SI
			AssemblyNonTerminal SI0 = new AssemblyNonTerminal("SI0");
			AssemblyNonTerminal SI1 = new AssemblyNonTerminal("SI1");
			AssemblyNonTerminal SI = new AssemblyNonTerminal("SI");

			addProduction(S, g, "list", SI);
			addProduction(SI, g, "[", SI1, "2", "]");
			addProduction(SI, g, "[", SI1, "]");

			addProduction(SI1, g, SI0, "1");
			addProduction(SI1, g, SI0);

			addProduction(SI0, g, "0");
			addProduction(SI0, g);
		}
		// Do the test
		out.println("Grammar:");
		g.print(out);

		AssemblyParser parser = new AssemblyParser(g);
		parser.printLR0States(out);
		parser.printLR0TransitionTable(out);
		parser.printExtendedGrammar(out);
		parser.printGeneralFF(out);
		parser.printExtendedFF(out);
		parser.printMergers(out);
		parser.printParseTable(out);

		Collection<AssemblyParseAcceptResult> p;

		p = validOnly(parser.parse("list[]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[1]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[2]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[01]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[02]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[12]"));
		assertEquals(4, p.size());
		p = validOnly(parser.parse("list[012]"));
		assertEquals(4, p.size());
	}

	@Test
	public void testEndsOptionalWhitespaceEpsilon() {
		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		AssemblyNonTerminal E = new AssemblyNonTerminal("E");

		addProduction(S, g, "t", " ", E);
		addProduction(E, g);

		AssemblyParser parser = new AssemblyParser(g);
		String sentence = "t";
		Collection<AssemblyParseResult> results = new HashSet<>();
		CollectionUtils.addAll(results, parser.parse(sentence));
		assertEquals(1, results.size());
		String expected = StringUtils.join(new String[] { //
			"[S] := 0. [S] => \"t\" _ [E]", //
			"  \"t\" := 't'", //
			"  _ := ''", //
			"  [E] := 1. [E] => e", //
		}, "\n").trim();
		for (AssemblyParseResult res : results) {
			assertEquals(expected, res.toString().trim());
		}
	}

	@Test
	public void testExpectsPastWhitespace() {
		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		addProduction(S, g, "a", " ", "b");

		AssemblyParser parser = new AssemblyParser(g);

		String sentence = "a ";
		Collection<AssemblyParseResult> results = new HashSet<>();
		CollectionUtils.addAll(results, parser.parse(sentence));
		assertEquals(1, results.size());
		for (AssemblyParseResult res : results) {
			assertTrue(res instanceof AssemblyParseErrorResult);
			AssemblyParseErrorResult err = (AssemblyParseErrorResult) res;
			Collection<String> sug = err.getSuggestions();
			assertEquals(Set.of("b"), sug);
		}
	}

	@Test
	public void testExpectsPastMissingWhitespace() {
		AssemblyGrammar g = new AssemblyGrammar();
		AssemblyNonTerminal S = new AssemblyNonTerminal("S");
		addProduction(S, g, "a", " ", "b");

		AssemblyParser parser = new AssemblyParser(g);

		String sentence = "a";
		Collection<AssemblyParseResult> results = new HashSet<>();
		CollectionUtils.addAll(results, parser.parse(sentence));
		assertEquals(1, results.size());
		for (AssemblyParseResult res : results) {
			assertTrue(res instanceof AssemblyParseErrorResult);
			AssemblyParseErrorResult err = (AssemblyParseErrorResult) res;
			Collection<String> sug = err.getSuggestions();
			assertEquals(Set.of(" "), sug);
		}
	}

	protected Collection<AssemblyParseAcceptResult> validOnly(
			Iterable<AssemblyParseResult> results) {
		Collection<AssemblyParseAcceptResult> valids = new ArrayList<>();
		for (AssemblyParseResult pr : results) {
			if (pr instanceof AssemblyParseAcceptResult) {
				valids.add((AssemblyParseAcceptResult) pr);
			}
		}
		return valids;
	}

	public static void addProduction(AssemblyNonTerminal lhs, AssemblyGrammar g, Object... objs) {
		AssemblySentential<AssemblyNonTerminal> rhs = new AssemblySentential<>();
		for (Object o : objs) {
			if (o instanceof AssemblySymbol) {
				rhs.add((AssemblySymbol) o);
			}
			else if (o instanceof String) {
				if (" ".equals(o)) {
					rhs.addWS();
				}
				else {
					rhs.add(new AssemblyStringTerminal((String) o));
				}
			}
			else {
				throw new RuntimeException("Type mismatch: " + o);
			}
		}
		g.addProduction(lhs, rhs);
	}
}
