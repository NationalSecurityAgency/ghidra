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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.*;
import static ghidra.feature.vt.db.VTTestUtils.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionNameMarkupType;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import utility.function.Callback;

/**
 * Tests that focus on how to apply function name markup when it comes to default vs non-default
 * for source and destination, along with whether or not to apply a non-default namespace.
 */
public class FunctionNameMarkupItem2Test extends AbstractVTMarkupItemTest {

	private SetUp srcSetUp;
	private SetUp destSetUp;
	private FunctionNameValidator validator;

	private Function destFunction;
	private Function srcFunction;

	private String originalSrcName;
	private String originalDestName;
	private String originalDestNsString;
	private String originalSrcNsString;

	private SetUp srcSetUp_DefaultName_DefaultNs = new SetUp(() -> {
		setDefaultSource(true);
	});

	private SetUp destSetUp_DefaultName_DefaultNs = new SetUp(() -> {
		setDefaultDestination(true);
	});

	private SetUp srcSetUp_DefaultName_NonDefaultNs = new SetUp(() -> {
		setDefaultSource(false);
	});

	private SetUp destSetUp_DefaultName_NonDefaultNs = new SetUp(() -> {
		setDefaultDestination(false);
	});

	private SetUp srcSetUp_NonDefaultName_DefaultNs = new SetUp(() -> {
		setNonDefaultSource(true);
	});

	private SetUp destSetUp_NonDefaultName_DefaultNs = new SetUp(() -> {
		setNonDefaultDestination(true);
	});

	private SetUp srcSetUp_NonDefaultName_NonDefaultNs = new SetUp(() -> {
		setNonDefaultSource(false);
	});

	private SetUp destSetUp_NonDefaultName_NonDefaultNs = new SetUp(() -> {
		setNonDefaultDestination(false);
	});
	private VTSessionDB session;
	private VTMatch match;
	private VTMarkupItem markupItem;

	@Test
	public void testDefaultSrcName_DefaultNs_DefaultDestName_DefaultDestNs() throws Exception {

		srcSetUp = srcSetUp_DefaultName_DefaultNs;
		destSetUp = destSetUp_DefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoMarkup(); // no markup for default name in the default namespace

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply_NoMarkup();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply_NoMarkup();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply_NoMarkup();
	}

	// @Test
	public void testDefaultSrcName_DefaultNs_DefaultDestName_NonDefaultDestNs() throws Exception {
		// Note: since there is no markup for a default name in a default namespace, this is covered
		// in the test above
	}

	//@Test
	public void testDefaultSrcName_DefaultNs_NonDefaultDestName_DefaultDestNs() throws Exception {
		// Note: since there is no markup for a default name in a default namespace, this is covered
		// in the test above
	}

	//@Test
	public void testDefaultSrcName_DefaultNs_NonDefaultDestName_NonDefaultDestNs()
			throws Exception {
		// Note: since there is no markup for a default name in a default namespace, this is covered
		// in the test above
	}

	@Test
	public void testDefaultSrcName_NonDefaultNs_DefaultDestName_DefaultDestNs() throws Exception {

		srcSetUp = srcSetUp_DefaultName_NonDefaultNs;
		destSetUp = destSetUp_DefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestNameUnchanged();
		assertDestHasSourceNs();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestNameUnchanged();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();
	}

	@Test
	public void testDefaultSrcName_NonDefaultNs_DefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_DefaultName_NonDefaultNs;
		destSetUp = destSetUp_DefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestNameUnchanged();
		assertDestHasSourceNs();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestNameUnchanged();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply_NoEffect();
		assertDestNameUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply_NoEffect();
		assertDestNameUnchanged();
	}

	@Test
	public void testDefaultSrcName_NonDefaultNs_NonDefaultDestName_DefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_DefaultName_NonDefaultNs;
		destSetUp = destSetUp_NonDefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply_NoEffect();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect(); // destination not default; no action taken
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestNameIsDefault();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();
	}

	@Test
	public void testDefaultSrcName_NonDefaultNs_NonDefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_DefaultName_NonDefaultNs;
		destSetUp = destSetUp_NonDefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect(); // no effect due to default name when 'replace namespace' is off
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect(); // destination not default; no action taken
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestNameIsDefault();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();
	}

	@Test
	public void testNonDefaultSource_DefaultNamespace_DefaultDestName_DefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_DefaultNs;
		destSetUp = destSetUp_DefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();
	}

	@Test
	public void testNonDefaultSource_DefaultNamespace_DefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_DefaultNs;
		destSetUp = destSetUp_DefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();
	}

	@Test
	public void testNonDefaultSource_DefaultNamespace_NonDefaultDestName_DefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_DefaultNs;
		destSetUp = destSetUp_NonDefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestLabelAdded();
		assertDestHasSrcName();
	}

	@Test
	public void testNonDefaultSource_DefaultNamespace_NonDefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_DefaultNs;
		destSetUp = destSetUp_NonDefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestHasSrcName(); // Name replaced, not added, since the destination was default
		assertDestHasDefaultNamespace();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestLabelAdded();
		assertDestHasSrcName();
	}

	@Test
	public void testNonDefaultSource_NonDefaultNamespace_DefaultDestName_DefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_NonDefaultNs;
		destSetUp = destSetUp_DefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();
	}

	@Test
	public void testNonDefaultSource_NonDefaultNamespace_DefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_NonDefaultNs;
		destSetUp = destSetUp_DefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestLabelAdded();
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestHasSrcName(); // default destination label, name applied
		assertDestNsUnchanged();
	}

	@Test
	public void testNonDefaultSource_NonDefaultNamespace_NonDefaultDestName_DefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_NonDefaultNs;
		destSetUp = destSetUp_NonDefaultName_DefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestLabelAdded();
		assertDestNsUnchanged();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestLabelAdded();
		assertDestHasSourceNs();
	}

	@Test
	public void testNonDefaultSource_NonDefaultNamespace_NonDefaultDestName_NonDefaultDestNs()
			throws Exception {

		srcSetUp = srcSetUp_NonDefaultName_NonDefaultNs;
		destSetUp = destSetUp_NonDefaultName_NonDefaultNs;

		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS);
		doTestApply();
		assertDestHasSrcName();
		assertDestNsUnchanged();

		// Add
		validator = createValidator(FunctionNameChoices.ADD);
		doTestApply();
		assertDestLabelAdded();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY);
		doTestApply();
		assertDestLabelAdded();
		assertDestHasDefaultNamespace();

		// 
		// Now test again with 'replace namespace' enabled
		//
		// Replace Default
		validator = createValidator(FunctionNameChoices.REPLACE_DEFAULT_ONLY, true);
		doTestApply_NoEffect();
		assertPrimaryDestNameAndNamespaceUnchanged();

		// Replace Always
		validator = createValidator(FunctionNameChoices.REPLACE_ALWAYS, true);
		doTestApply();
		assertDestHasSrcName();
		assertDestHasSourceNs();

		// Add
		validator = createValidator(FunctionNameChoices.ADD, true);
		doTestApply();
		assertDestLabelAdded();
		assertDestNameUnchanged();
		assertDestNsUnchanged();

		// Add as Primary
		validator = createValidator(FunctionNameChoices.ADD_AS_PRIMARY, true);
		doTestApply();
		assertDestLabelAdded();
		assertDestLabelAdded();
		assertDestHasSourceNs();
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void assertDestLabelAdded() {
		SymbolManager symbolTable = destinationProgram.getSymbolTable();
		Address addr = getDestinationMatchAddress();
		Symbol symbol = getSymbol(symbolTable, originalSrcName, addr);
		assertNotNull(symbol);

		if (symbol.isPrimary()) {
			assertEquals(SymbolType.FUNCTION, symbol.getSymbolType());
		}
		else {
			assertEquals(SymbolType.LABEL, symbol.getSymbolType());
		}
	}

	private void assertDestHasSrcName() {
		String appliedDestinationName = destFunction.getName(false);
		assertEquals(originalSrcName, appliedDestinationName);
	}

	private void assertDestNameIsDefault() {
		String appliedDestName = destFunction.getName(false);
		assertEquals("FUN_01003f9e", appliedDestName);
	}

	private void assertDestHasDefaultNamespace() {
		Namespace appliedDestNs = destFunction.getParentNamespace();
		assertEquals("Global", appliedDestNs.toString());
	}

	private void assertDestNameUnchanged() {
		String appliedDestName = destFunction.getName(false);
		assertEquals(originalDestName, appliedDestName);
	}

	private void assertDestNsUnchanged() {
		Namespace appliedDestNs = destFunction.getParentNamespace();
		String appliedDestNsString = appliedDestNs.toString();
		assertEquals(originalDestNsString, appliedDestNsString);
	}

	private void assertPrimaryDestNameAndNamespaceUnchanged() {
		assertDestNameUnchanged();
		assertDestNsUnchanged();
	}

	private void assertDestHasSourceNs() {
		Namespace appliedDestNs = destFunction.getParentNamespace();
		String appliedDestNsString = appliedDestNs.toString();
		assertEquals(originalSrcNsString, appliedDestNsString);
	}

	private Address getDestinationMatchAddress() {
		return destFunction.getEntryPoint();
	}

	private Symbol getSymbol(SymbolTable symbolTable, String name, Address addr) {

		Symbol[] symbols = symbolTable.getSymbols(addr);
		for (Symbol s : symbols) {
			String symbolName = s.getName();
			if (symbolName.equals(name)) {
				return s;
			}
		}
		return null;
	}

	private void setDefaultDestination(boolean defaultNamespace) {

		Address destAddress = addr("0x01003f9e", destinationProgram);
		FunctionManager destFunctionManager = destinationProgram.getFunctionManager();
		destFunction = destFunctionManager.getFunctionAt(destAddress);

		if (!defaultNamespace) {
			setNamespace(destFunction, "Destination::Bar");
		}
	}

	private void setNonDefaultDestination(boolean defaultNamespace) {

		Address destAddress = addr("0x01003f9e", destinationProgram);
		FunctionManager destFunctionManager = destinationProgram.getFunctionManager();
		destFunction = destFunctionManager.getFunctionAt(destAddress);

		setName(destFunction, "NonDefaultDestName");
		if (!defaultNamespace) {
			setNamespace(destFunction, "Destination::Bar");
		}
	}

	private void setDefaultSource(boolean defaultNamespace) {

		Address srcAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager srcFunctionManager = sourceProgram.getFunctionManager();
		srcFunction = srcFunctionManager.getFunctionAt(srcAddress);

		clearFunctionName(srcFunction);
		if (!defaultNamespace) {
			setNamespace(srcFunction, "Source::Foo");
		}
	}

	private void setNonDefaultSource(boolean defaultNamespace) {
		Address srcAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager srcFunctionManager = sourceProgram.getFunctionManager();
		srcFunction = srcFunctionManager.getFunctionAt(srcAddress);

		setName(srcFunction, "NonDefaultSrcName");
		if (!defaultNamespace) {
			setNamespace(srcFunction, "Source::Foo");
		}
	}

	private FunctionNameValidator createValidator(FunctionNameChoices choice)
			throws Exception {
		return createValidator(choice, false);
	}

	private FunctionNameValidator createValidator(FunctionNameChoices choice,
			boolean replaceNsOption) throws Exception {

		if (validator != null) {
			doTestUnapply();
			resetPrograms();
		}

		srcSetUp.run();
		destSetUp.run();

		originalSrcName = srcFunction.getName(false);
		originalDestName = destFunction.getName(false);
		originalSrcNsString = srcFunction.getParentNamespace().toString();
		originalDestNsString = destFunction.getParentNamespace().toString();

		FunctionNameValidator fv =
			new FunctionNameValidator(srcFunction, destFunction, choice);

		if (replaceNsOption) {
			ToolOptions options = fv.getOptions();
			options.setBoolean(USE_NAMESPACE_FUNCTIONS, true);
		}

		return fv;
	}

	private void doTestUnapply() {

		if (markupItem == null) {
			return; // the current test found no markup
		}

		//
		// Verify we can unapply
		//
		VtTask task = new UnapplyMarkupItemTask(session, null, List.of(markupItem));
		runTask(session, task);
		validator.assertUnapplied();
	}

	private void doTestApply() throws Exception {

		session = createNewSession();
		match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		markupItem = validator.searchForMarkupItem(match);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationApplyAddress = validator.getDestinationApplyAddress();
		markupItem.setDefaultDestinationAddress(destinationApplyAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		//
		// verify we can apply
		//
		VTMarkupItemApplyActionType applyAction = validator.getApplyAction();
		if (applyAction != null) {
			VtTask task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
			runTask(session, task);
			VTMarkupItemStatus expectedStatus = applyAction.getApplyStatus();
			VTMarkupItemStatus actualStatus = markupItem.getStatus();
			assertEquals("The markup item status was not correctly set", expectedStatus,
				actualStatus);
			validator.assertApplied();
		}
		else {
			fail();
		}
	}

	private void doTestApply_NoMarkup() throws Exception {

		session = createNewSession();
		match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		markupItem = validator.searchForMarkupItem(match);

		//
		// verify that there isn't a markup item
		//
		assertNull(markupItem);
	}

	protected void doTestApply_NoEffect() throws Exception {

		session = createNewSession();
		match = createMatchSetWithOneMatch(session, validator.getSourceMatchAddress(),
			validator.getDestinationMatchAddress());
		markupItem = validator.searchForMarkupItem(match);

		//
		// verify we cannot unapply before we have applied
		//
		List<VTMarkupItem> markupItems = new ArrayList<>();
		Address destinationApplyAddress = validator.getDestinationApplyAddress();
		markupItem.setDefaultDestinationAddress(destinationApplyAddress, TEST_ADDRESS_SOURCE);
		markupItems.add(markupItem);

		VtTask task = new UnapplyMarkupItemTask(session, null, markupItems);
		runTask(session, task);

		//
		// verify we can apply
		//
		VTMarkupItemApplyActionType applyAction = validator.getApplyAction();
		if (applyAction != null) {
			task = new ApplyMarkupItemTask(session, markupItems, validator.getOptions());
			runTask(session, task);
			assertEquals("The markup item was applied when it should not have been.",
				VTMarkupItemStatus.UNAPPLIED, markupItem.getStatus());
		}

	}

	private void clearFunctionName(Function f) {

		Symbol s = f.getSymbol();
		Address addr = f.getEntryPoint();
		DeleteLabelCmd cmd = new DeleteLabelCmd(addr, s.getName(), s.getParentNamespace());
		assertTrue(applyCmd(sourceProgram, cmd));
	}

	private void setName(Function f, String name) {
		Program p = f.getProgram();
		tx(p, () -> {
			f.setName(name, SourceType.DEFAULT);
		});
	}

	private void setNamespace(Function f, String namespacePath) {

		Program p = f.getProgram();
		tx(p, () -> {
			Namespace globalNamespace = p.getGlobalNamespace();
			Namespace ns =
				NamespaceUtils.createNamespaceHierarchy(namespacePath, globalNamespace, p,
					SourceType.USER_DEFINED);
			f.setParentNamespace(ns);
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** Simple object to allow the source and destination functions to be setup differently */
	private class SetUp {
		private Callback callback;

		SetUp(Callback c) {
			this.callback = c;
		}

		void run() {
			callback.call();
		}
	}

	private class FunctionNameValidator extends TestDataProviderAndValidator {

		private Function sourceFunction;
		private Function destinationFunction;
		private FunctionNameChoices functionNameChoice;

		private String destinationOriginalName;

		FunctionNameValidator(Function sourceFunction, Function destinationFunction,
				FunctionNameChoices functionNameChoice) {

			this.sourceFunction = sourceFunction;
			this.destinationFunction = destinationFunction;
			this.destinationOriginalName = destinationFunction.getName(true);
			this.functionNameChoice = functionNameChoice;
		}

		@Override
		protected Address getDestinationApplyAddress() {
			return getDestinationMatchAddress();
		}

		@Override
		public ToolOptions getOptions() {
			ToolOptions vtOptions = super.getOptions();
			vtOptions.setEnum(FUNCTION_NAME, functionNameChoice);

			return vtOptions;
		}

		@Override
		protected VTMarkupItemApplyActionType getApplyAction() {
			if (functionNameChoice == FunctionNameChoices.EXCLUDE) {
				return null;
			}
			if (functionNameChoice == FunctionNameChoices.ADD ||
				functionNameChoice == FunctionNameChoices.ADD_AS_PRIMARY) {
				return ADD;
			}
			return REPLACE;
		}

		@Override
		protected Address getDestinationMatchAddress() {
			return destinationFunction.getEntryPoint();
		}

		@Override
		protected Address getSourceMatchAddress() {
			return sourceFunction.getEntryPoint();
		}

		@Override
		protected VTMarkupItem searchForMarkupItem(VTMatch vtMatch) throws Exception {
			List<VTMarkupItem> items =
				FunctionNameMarkupType.INSTANCE.createMarkupItems(vtMatch.getAssociation());
			if (items.isEmpty()) {
				return null; // no markup items
			}
			VTMarkupItem item = items.get(0);

			// we have to set the source stringable value to prevent potential name collisions
			updateSourceName();

			return item;
		}

		private void updateSourceName() {
			String sourceName = sourceFunction.getName();
			tx(sourceProgram, () -> {
				sourceFunction.setName(sourceName, SourceType.USER_DEFINED);
			});
		}

		@Override
		protected void assertApplied() {
			// the tests check their own assertions
		}

		private boolean isDefaultFunctionName(String functionName, Function function) {
			String defaultFunctionName =
				SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
			return defaultFunctionName.equals(functionName);
		}

		@Override
		protected void assertUnapplied() {

			String destName = destinationFunction.getName(true);
			assertEquals("Function name was not unapplied", destinationOriginalName, destName);

			if (functionNameChoice == FunctionNameChoices.ADD) {

				if (!isDefaultFunctionName(destinationOriginalName, destinationFunction)) {
					Program p = destinationFunction.getProgram();
					SymbolTable st = p.getSymbolTable();
					Address addr = getDestinationMatchAddress();
					String sourceName = sourceFunction.getName();
					Symbol sourceSymbol = st.getGlobalSymbol(sourceName, addr);
					assertNull(sourceSymbol);
				}
			}
			else if (functionNameChoice == FunctionNameChoices.ADD_AS_PRIMARY) {
				// don't think there is anything to test here, since the fact that the function name
				// has been restored means that the old source symbol that was made primary is gone.
			}
		}
	}

}
