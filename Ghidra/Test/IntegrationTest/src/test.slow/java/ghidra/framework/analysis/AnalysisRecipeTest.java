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
package ghidra.framework.analysis;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.jdom.Element;
import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class AnalysisRecipeTest extends AbstractGhidraHeadlessIntegrationTest {

	private AnalysisRecipe recipe;
	private ProgramBuilder programBuilder;
	private ProgramDB program;
	private ArrayList<Analyzer> analyzers;

	@Before
	public void setUp() throws Exception {
		programBuilder = new ProgramBuilder();
		programBuilder.createMemory("AAA", "0x100", 0x1000);
		program = programBuilder.getProgram();
		analyzers = new ArrayList<>();
		GhidraScriptUtil.initialize(new BundleHost(), null);
	}

	@After
	public void cleanup() {
		GhidraScriptUtil.dispose();
	}

	@Test
	public void testXML() {
		Analyzer1 analyzer1 = new Analyzer1();
		Analyzer2 analyzer2 = new Analyzer2();
		analyzers.add(analyzer1);
		analyzers.add(analyzer2);
		recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		AnalysisPhase lastPhase = recipe.getLastPhase();
		AnalysisPhase firstPhase = recipe.createPhase();

		recipe.setAnalyzerStartPhase(analyzer1, firstPhase);

		assertEquals(firstPhase, recipe.getAnalyzerStartPhase(analyzer1));
		assertEquals(lastPhase, recipe.getAnalyzerStartPhase(analyzer2));

		Element xml = recipe.toXML();
		AnalysisRecipe savedRecipe = new AnalysisRecipe("FOO", analyzers, program);
		savedRecipe.loadFromXML(xml);
		List<AnalysisPhase> analysisPhases = savedRecipe.getAnalysisPhases();
		assertEquals(2, analysisPhases.size());
		AnalysisPhase phase1 = analysisPhases.get(0);
		AnalysisPhase phase2 = analysisPhases.get(1);

		assertEquals("Test Recipe", savedRecipe.getName());
		assertEquals("1", phase1.getName());
		assertEquals("2", phase2.getName());

		assertEquals(firstPhase, recipe.getAnalyzerStartPhase(analyzer1));
		assertEquals(lastPhase, recipe.getAnalyzerStartPhase(analyzer2));

	}

	@Test
	public void testXMLWithScriptAnalzyers() {
		Analyzer1 analyzer1 = new Analyzer1();
		Analyzer2 analyzer2 = new Analyzer2();
		analyzers.add(analyzer1);
		analyzers.add(analyzer2);
		recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		ResourceFile sourceFile = GhidraScriptUtil.findScriptByName("HelloWorldScript.java");
		assertNotNull(sourceFile);
		recipe.addScriptAnalyzer(sourceFile, AnalyzerType.INSTRUCTION_ANALYZER, 15);
		AnalysisPhase lastPhase = recipe.getLastPhase();
		AnalysisPhase firstPhase = recipe.createPhase();

		recipe.setAnalyzerStartPhase(analyzer1, firstPhase);

		assertEquals(firstPhase, recipe.getAnalyzerStartPhase(analyzer1));
		assertEquals(lastPhase, recipe.getAnalyzerStartPhase(analyzer2));

		Element xml = recipe.toXML();
		AnalysisRecipe savedRecipe = new AnalysisRecipe("FOO", analyzers, program);
		savedRecipe.loadFromXML(xml);
		List<AnalysisPhase> analysisPhases = savedRecipe.getAnalysisPhases();
		assertEquals(2, analysisPhases.size());
		AnalysisPhase phase1 = analysisPhases.get(0);
		AnalysisPhase phase2 = analysisPhases.get(1);

		assertEquals("Test Recipe", savedRecipe.getName());
		List<Analyzer> analyzerList = savedRecipe.getAnalyzers();
		assertEquals(3, analyzerList.size());
		Analyzer scriptAnalyzer = analyzerList.get(0);
		assertEquals(GhidraScriptAnalyzerAdapter.class, scriptAnalyzer.getClass());
		assertEquals("Script: HelloWorldScript.java", scriptAnalyzer.getName());
		assertEquals(AnalyzerType.INSTRUCTION_ANALYZER, scriptAnalyzer.getAnalysisType());
		assertEquals(15, scriptAnalyzer.getPriority().priority());
	}

	public static class Analyzer1 extends AnalyzerTestStub {

		Analyzer1() {
			super("Analyzer1", AnalyzerType.BYTE_ANALYZER, true, new AnalysisPriority("1", 100));
		}
	}

	public static class Analyzer2 extends AnalyzerTestStub {

		Analyzer2() {
			super("Analyzer2", AnalyzerType.BYTE_ANALYZER, true, new AnalysisPriority("2", 200));
		}
	}

	public Namespace get(Program program, Namespace otherNamespace) {
		Program source = otherNamespace.getSymbol().getProgram();
		if (source == program) {
			return otherNamespace;
		}
		getCorrespondingNamespace(source, otherNamespace, program);
		return null;
	}

	private Namespace getCorrespondingNamespace(Program source, Namespace ns, Program p) {
		Namespace parent = ns.getParentNamespace();
		if (parent == source.getGlobalNamespace()) {
			return p.getGlobalNamespace();
		}
		Namespace other = getCorrespondingNamespace(source, parent, p);
		Symbol symbol = getUniqueSymbol(p, ns.getName(), other);
		return (Namespace) symbol.getObject();
	}
}
