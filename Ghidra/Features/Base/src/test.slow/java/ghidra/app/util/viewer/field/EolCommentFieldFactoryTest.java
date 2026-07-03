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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.*;
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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

public class EolCommentFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String STRING_ADDRESS_WITH_ANNOTATION = "0x01002c98";
	private static final String ADDRESS_CALLING_STRING_WITH_ANNOTATION = "0X01002d37";
	private static final String AUTO_COMMENT_TEXT_WITH_ANNOTATION =
		"Annotation: {@address 12345678 foo}";

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

		setBooleanOption(EolCommentFieldFactory.ENABLE_WORD_WRAP_KEY, true);

		tf = getFieldText(function);
		assertEquals(4, tf.getNumRows());
	}

	@Test
	public void testRepeatableComment_FunctionCall() throws Exception {

		// check existing auto comment
		String from = "0x010022e6";
		ListingTextField tf = getFieldText(addr(from));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), startsWith("undefined ghidra(undefined4 param_1,"));

		// set repeatable comment at source
		String to = "0x01002cf5";
		String repeatableComment = "My repeatable comment";
		setRepeatableComment(addr(to), repeatableComment);

		// check that the repeatable comment now matches the updated comment
		tf = getFieldText(addr(from));
		assertEquals(1, tf.getNumRows());
		assertEquals(tf.getText(), repeatableComment);
	}

	@Test
	public void testRepeatableComment_FunctionCall_PrependRefAddress() throws Exception {

		setBooleanOption(EolCommentFieldFactory.ENABLE_PREPEND_REF_ADDRESS_KEY, true);

		// check existing auto comment
		String from = "0x010022e6";
		ListingTextField tf = getFieldText(addr(from));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), startsWith("undefined ghidra(undefined4 param_1,"));

		// set repeatable comment at source
		String to = "0x01002cf5";
		String repeatableComment = "My repeatable comment";
		setRepeatableComment(addr(to), repeatableComment);

		// check that the repeatable comment now matches the updated comment and has the ref address
		// prepended
		tf = getFieldText(addr(from));
		assertEquals(1, tf.getNumRows());
		assertEquals("01002cf5 " + repeatableComment, tf.getText());
	}

	@Test
	public void testRepeatableComment_DataAccess() throws Exception {

		// check existing auto comment
		ListingTextField tf = getFieldText(addr("0x01002265"));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), startsWith("= 00000001h"));

		// set repeatable comment at destination
		Address destination = addr("0x01002265");
		String repeatableComment = "My repeatable comment";
		setRepeatableComment(destination, repeatableComment);

		// check that the auto comment now matches the updated comment
		tf = getFieldText(addr("0x01002265"));
		assertEquals(1, tf.getNumRows());
		assertEquals(repeatableComment, tf.getText());
	}

	@Test
	public void testAutoCommentDoesNotRenderAnnotation() {

		/*
		 	Creates a data reference to a string containing an annotation.  Tests that the 
		 	annotation is not rendered, but is shown in its raw form.
		 */

		goTo(env.getTool(), program, STRING_ADDRESS_WITH_ANNOTATION);
		ListingTextField tf = getFieldText(addr(ADDRESS_CALLING_STRING_WITH_ANNOTATION));
		assertEquals(1, tf.getNumRows());
		assertThat(tf.getText(), containsString(AUTO_COMMENT_TEXT_WITH_ANNOTATION));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ProgramDB buildProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();

		builder.createString(STRING_ADDRESS_WITH_ANNOTATION, AUTO_COMMENT_TEXT_WITH_ANNOTATION);

		builder.createMemoryReference(ADDRESS_CALLING_STRING_WITH_ANNOTATION,
			STRING_ADDRESS_WITH_ANNOTATION,
			RefType.DATA, SourceType.ANALYSIS);

		return builder.getProgram();
	}

	private void setCommentInFunction(Function function, String comment) {
		CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
		int transactionID = program.startTransaction("test");
		try {
			cu.setComment(CommentType.EOL, comment);
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
		setComment(a, CommentType.REPEATABLE, comment);
	}

	private void setComment(Address a, CommentType commentType, String comment) {
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		tx(program, () -> {
			cu.setComment(commentType, comment);
		});
	}
}
