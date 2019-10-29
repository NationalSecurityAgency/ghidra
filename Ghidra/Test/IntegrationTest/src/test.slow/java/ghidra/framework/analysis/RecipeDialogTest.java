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

import org.junit.Before;
import org.junit.Test;

import docking.DockingWindowManager;
import ghidra.SwingExceptionHandler;
import ghidra.program.database.ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class RecipeDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramBuilder builder;
	private AnalysisRecipe recipe;

	public RecipeDialogTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder();
		recipe = AnalysisRecipeBuilder.getRecipe(builder.getProgram());
		recipe.createPhase();
		recipe.createPhase();
		recipe.createPhase();
	}

	@Test
	public void testNothing() {
		//
	}

	public void dontTestDialog() {
		RecipeEditorDialog dialog = new RecipeEditorDialog(recipe);
		DockingWindowManager.showDialog(null, dialog);
		assertNotNull(dialog);
	}

	public static void main(String[] args) throws Exception {
		SwingExceptionHandler.registerHandler();

		RecipeDialogTest test = new RecipeDialogTest();
		test.setUp();
		test.dontTestDialog();
		System.exit(0);
	}
}
