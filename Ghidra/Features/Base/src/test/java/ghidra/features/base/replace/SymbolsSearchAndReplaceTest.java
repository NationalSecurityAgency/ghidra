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
package ghidra.features.base.replace;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.LabelFieldLocation;
import ghidra.util.exception.CancelledException;

public class SymbolsSearchAndReplaceTest extends AbstractSearchAndReplaceTest {

	@Test
	public void testLabelsSearchNotCaseSensitive() throws CancelledException {
		createLabel(10, "foo");
		createLabel(20, "fooxxxx");
		createLabel(30, "xxxFoox");
		createLabel(40, "xxxxfOO");
		createLabel(50, "xxxfoxo");

		setSearchTypes(labels);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByAddress(results);

		assertQuickFix(10, "foo", "bar", results.get(0));
		assertQuickFix(20, "fooxxxx", "barxxxx", results.get(1));
		assertQuickFix(30, "xxxFoox", "xxxbarx", results.get(2));
		assertQuickFix(40, "xxxxfOO", "xxxxbar", results.get(3));
	}

	@Test
	public void testLabelsSearchWholeWord() throws CancelledException {
		createLabel(10, "foo");
		createLabel(20, "fooxxxx");
		createLabel(30, "xxxFoox");
		createLabel(40, "xxxxfOO");
		createLabel(50, "xxxfoxo");

		setSearchTypes(labels);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);

		assertEquals(1, results.size());

		assertQuickFix(10, "foo", "bar", results.get(0));
	}

	@Test
	public void testLabelsSearchCaseSensitiveSearch() throws CancelledException {
		createLabel(10, "fooxxxx");
		createLabel(20, "Fooxxxx");
		createLabel(30, "xxFOOxxx");
		createLabel(40, "foo");
		createLabel(50, "xxxfoo");

		setSearchTypes(labels);
		List<QuickFix> results = query("Foo", "bar", CASE_SENSITIVE_ON, WHOLE_WORD_OFF);

		assertEquals(1, results.size());
		assertQuickFix(20, "Fooxxxx", "barxxxx", results.get(0));
	}

	@Test
	public void testLabelsSearchRegEx() throws CancelledException {
		createLabel(10, "fooxxxx");
		createLabel(20, "Fooxxxx");
		createLabel(30, "xxFOOxxx");
		createLabel(40, "foo");
		createLabel(50, "xxxfoo");

		setSearchTypes(labels);
		List<QuickFix> results = queryRegEx("^Foo$", "bar", CASE_SENSITIVE_OFF);

		assertEquals(1, results.size());
		assertQuickFix(40, "foo", "bar", results.get(0));

	}

	@Test
	public void testLabelsSearchRegExCaptureGroups() throws CancelledException {
		createLabel(10, "fooxxxx");
		createLabel(20, "Fooxxxx");
		createLabel(30, "xxFOOxxx");
		createLabel(40, "foo");
		createLabel(50, "xxBARxxx");

		setSearchTypes(labels);
		List<QuickFix> results = queryRegEx("xx(.*)xxx", "zz$1zzz", CASE_SENSITIVE_OFF);
		sortByAddress(results);
		assertEquals(2, results.size());
		assertQuickFix(30, "xxFOOxxx", "zzFOOzzz", results.get(0));
		assertQuickFix(50, "xxBARxxx", "zzBARzzz", results.get(1));
	}

	@Test
	public void testRenamingLabel() throws CancelledException {
		Symbol s = createLabel(10, "foo");
		createLabel(20, "fooxxxx");
		createLabel(30, "xxxFoox");
		createLabel(40, "xxxxfOO");
		createLabel(50, "xxxfoxo");

		setSearchTypes(labels);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Label", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(new LabelFieldLocation(s), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
	}

	@Test
	public void testRenameLabelDuplicate() throws CancelledException {
		Symbol s = createLabel(10, "foo");
		createLabel(20, "bar");

		setSearchTypes(labels);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"Global\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Label", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(new LabelFieldLocation(s), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
	}

	@Test
	public void testSearchFunctions() throws Exception {
		createFunction(10, "foo");
		createFunction(20, "fooxxxx");
		createFunction(30, "xxxFoox");
		createFunction(40, "xxxxfOO");
		createFunction(50, "xxxfoxo");

		setSearchTypes(functions);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByAddress(results);

		assertQuickFix(10, "foo", "bar", results.get(0));
		assertQuickFix(20, "fooxxxx", "barxxxx", results.get(1));
		assertQuickFix(30, "xxxFoox", "xxxbarx", results.get(2));
		assertQuickFix(40, "xxxxfOO", "xxxxbar", results.get(3));
	}

	@Test
	public void testRenamingFunction() throws Exception {
		Function function = createFunction(10, "foo");

		setSearchTypes(functions);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Function", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(function.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());

		assertEquals("bar", function.getName());

	}

	@Test
	public void testRenameFunctionDuplicate() throws Exception {
		Function function = createFunction(10, "foo");
		createFunction(20, "bar");

		setSearchTypes(functions);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"Global\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Function", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(function.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", function.getName());
	}

	@Test
	public void testSearchNamespaces() throws Exception {
		Namespace global = program.getGlobalNamespace();
		Namespace aaa = createNamespace(global, "aaa");

		createNamespace(global, "foo");
		createNamespace(global, "fooxxxx");
		createNamespace(aaa, "xxxFoox");
		createNamespace(aaa, "xxxxfOO");
		createNamespace(global, "xxxfoxo");

		setSearchTypes(namespaces);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("fooxxxx", "barxxxx", results.get(1));
		assertQuickFix("xxxFoox", "xxxbarx", results.get(2));
		assertQuickFix("xxxxfOO", "xxxxbar", results.get(3));
	}

	@Test
	public void testRenamingNamespace() throws Exception {
		Namespace global = program.getGlobalNamespace();
		Namespace foo = createNamespace(global, "foo");

		setSearchTypes(namespaces);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Namespace", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(foo.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", foo.getName());
	}

	@Test
	public void testRenameNamespaceDuplicate() throws Exception {
		Namespace global = program.getGlobalNamespace();
		Namespace foo = createNamespace(global, "foo");
		createNamespace(global, "bar");

		setSearchTypes(namespaces);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"Global\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Namespace", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(foo.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals(
			"Rename Failed! A Namespace symbol with name bar already exists in namespace Global",
			item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", foo.getName());
	}

	@Test
	public void testSearchClasses() throws Exception {
		Namespace global = program.getGlobalNamespace();
		Namespace aaa = createNamespace(global, "aaa");

		createClass(global, "foo");
		createClass(global, "fooxxxx");
		createClass(aaa, "xxxFoox");
		createClass(aaa, "xxxxfOO");
		createClass(global, "xxxfoxo");

		setSearchTypes(classes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(4, results.size());
		sortByName(results);

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("fooxxxx", "barxxxx", results.get(1));
		assertQuickFix("xxxFoox", "xxxbarx", results.get(2));
		assertQuickFix("xxxxfOO", "xxxxbar", results.get(3));
	}

	@Test
	public void testRenamingClass() throws Exception {
		Namespace global = program.getGlobalNamespace();
		GhidraClass foo = createClass(global, "foo");

		setSearchTypes(classes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Class", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(foo.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", foo.getName());
	}

	@Test
	public void testRenameClassWithDuplicate() throws Exception {
		Namespace global = program.getGlobalNamespace();
		Namespace foo = createClass(global, "foo");
		createClass(global, "bar");

		setSearchTypes(classes);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"Global\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Class", item.getItemType());
		assertEquals("Global", item.getPath());
		assertEquals(foo.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals(
			"Rename Failed! A Class symbol with name bar already exists in namespace Global",
			item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", foo.getName());
	}

	@Test
	public void testSearchParameters() throws Exception {
		createFunction(10, "aaa", "foo", "xxxfooxxx");
		createFunction(20, "bbb", "foo");

		setSearchTypes(parameters);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(3, results.size());
		sortByAddress(results);

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("xxxfooxxx", "xxxbarxxx", results.get(1));
		assertQuickFix("foo", "bar", results.get(2));
	}

	@Test
	public void testRenamingParameter() throws Exception {
		Function function = createFunction(10, "aaa", "xxxfooxxx");
		Parameter parameter = function.getParameter(1);

		setSearchTypes(parameters);
		List<QuickFix> results = query("xxxfooxxx", "xxxbarxxx", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Parameter", item.getItemType());
		assertEquals("aaa", item.getPath());
		assertEquals(parameter.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("xxxfooxxx", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("xxxbarxxx", item.getCurrent());

		assertEquals("xxxbarxxx", parameter.getName());

	}

	@Test
	public void testRenameParameterDuplicate() throws Exception {
		Function function = createFunction(10, "aaa", "foo", "bar");
		Parameter parameter = function.getParameter(1);

		setSearchTypes(parameters);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"aaa\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Parameter", item.getItemType());
		assertEquals("aaa", item.getPath());
		assertEquals(parameter.getSymbol().getProgramLocation(), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals(
			"Rename Failed! A Parameter symbol with name bar already exists in namespace aaa",
			item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", parameter.getName());
	}

	@Test
	public void testSearchLocalVars() throws Exception {
		Function f1 = createFunction(10, "aaa");
		Function f2 = createFunction(20, "bbb");
		DataType dt = new ByteDataType();
		builder.createLocalVariable(f1, "foo", dt, 0);
		builder.createLocalVariable(f1, "xxxfooxxx", dt, 4);
		builder.createLocalVariable(f2, "foo", dt, 0);

		setSearchTypes(localVariables);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(3, results.size());

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("xxxfooxxx", "xxxbarxxx", results.get(1));
		assertQuickFix("foo", "bar", results.get(2));
	}

	@Test
	public void testRenamingLocalVariable() throws Exception {
		Function f1 = createFunction(10, "aaa");
		Function f2 = createFunction(20, "bbb");
		DataType dt = new ByteDataType();
		builder.createLocalVariable(f1, "foo", dt, 0);
		builder.createLocalVariable(f2, "bar", dt, 4);

		setSearchTypes(localVariables);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Local Var", item.getItemType());
		assertEquals("aaa", item.getPath());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
	}

	@Test
	public void testRenameVariableDuplicate() throws Exception {
		Function f1 = createFunction(10, "aaa");
		DataType dt = new ByteDataType();
		builder.createLocalVariable(f1, "foo", dt, 0);
		builder.createLocalVariable(f1, "bar", dt, 4);

		setSearchTypes(localVariables);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("There is already a symbol named \"bar\" in namespace \"aaa\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Local Var", item.getItemType());
		assertEquals("aaa", item.getPath());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals(
			"Rename Failed! A Local Var symbol with name bar already exists in namespace aaa",
			item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
	}

}
