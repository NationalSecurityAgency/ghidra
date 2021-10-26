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
package ghidra.app.util.viewer.field;

import static org.hamcrest.core.StringStartsWith.*;
import static org.junit.Assert.*;

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.widgets.fieldpanel.field.FieldElement;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class EolCommentFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private CodeBrowserPlugin cb;
	private Options fieldOptions;
	private Program program;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		fieldOptions = cb.getFormatManager().getFieldOptions();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testWordWrapping() throws Exception {
		Function function = findFirstFunction();

		setCommentInFunction(function, "comment line 1\ncomment line 2");

		changeFieldWidthToHalfCommentLength(function);

		ListingTextField tf = getFieldText(function);
		assertEquals(2, tf.getNumRows());

		setBooleanOption(EolCommentFieldFactory.ENABLE_WORD_WRAP_MSG, true);

		tf = getFieldText(function);
		assertEquals(4, tf.getNumRows());
	}

	@Test
	public void testRepeatableComment_FunctionCall() throws Exception {

		// check existing auto comment
		ListingTextField tf = getFieldText(addr("0x010022e6"));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), startsWith("undefined ghidra(undefined4 param_1,"));

		// set repeatable comment at destination
		Address destination = addr("0x01002cf5");
		String repeatableComment = "My repeatable comment";
		setRepeatableComment(destination, repeatableComment);

		// check that the auto comment now matches the updated comment
		tf = getFieldText(addr("0x010022e6"));
		assertEquals(1, tf.getNumRows());
		assertEquals(tf.getText(), repeatableComment);
	}

	@Test
	public void testRepeatableComment_DataAccess() throws Exception {

		// check existing auto comment
		ListingTextField tf = getFieldText(addr("0x01002265"));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), startsWith("= 01h"));

		// set repeatable comment at destination
		Address destination = addr("0x01002265");
		String repeatableComment = "My repeatable comment";
		setRepeatableComment(destination, repeatableComment);

		// check that the auto comment now matches the updated comment
		tf = getFieldText(addr("0x01002265"));
		assertEquals(1, tf.getNumRows());
		assertEquals(tf.getText(), repeatableComment);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ProgramDB buildProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		return builder.getProgram();
	}

	private void setCommentInFunction(Function function, String comment) {
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CodeUnit.EOL_COMMENT, comment);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private Function findFirstFunction() {
		Listing listing = program.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		Function function = iter.next();
		assertNotNull("Expected a function", function);
		return function;
	}

	private void changeFieldWidthToHalfCommentLength(Function function) throws Exception {
		ListingTextField tf = getFieldText(function);
		FieldElement fieldElement = tf.getFieldElement(0, 0);
		int stringWidth = fieldElement.getStringWidth();
		setFieldWidth(tf.getFieldFactory(), stringWidth / 2);
	}

	private ListingTextField getFieldText(Function function) {
		return getFieldText(function.getEntryPoint());
	}

	private ListingTextField getFieldText(Address address) {
		assertTrue(cb.goToField(address, EolCommentFieldFactory.FIELD_NAME, 1, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		return tf;
	}

	private void setFieldWidth(final FieldFactory fieldFactory, final int width) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldFactory.setWidth(width));
		waitForSwing();
		cb.updateNow();
	}

	private void setBooleanOption(final String name, final boolean value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setBoolean(name, value));
		waitForSwing();
		cb.updateNow();
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

	private void setRepeatableComment(Address a, String comment) {
		setComment(a, CodeUnit.REPEATABLE_COMMENT, comment);
	}

	private void setComment(Address a, int commentType, String comment) {
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		tx(program, () -> {
			cu.setComment(commentType, comment);
		});
	}
}
