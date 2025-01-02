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
package ghidra.app.util;

import static org.junit.Assert.*;

import java.util.function.Predicate;

import javax.swing.JFrame;

import org.junit.*;

import ghidra.program.database.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class AddressInputTest extends AbstractGhidraHeadedIntegrationTest {

	private JFrame frame;
	private AddressInput field;
	private ProgramDB programOneSpace;
	private ProgramDB programMultiSpaces;
	private volatile Address changedAddress;
	private volatile String errorMessage;

	@Before
	public void setUp() throws Exception {
		programOneSpace = createDefaultProgram("oneSpace", ProgramBuilder._TOY, this);
		programMultiSpaces = createDefaultProgram("mulitSpaces", ProgramBuilder._8051, this);
		field = new AddressInput(programOneSpace, this::addressChanged);
		field.setAddressErrorConsumer(this::addressError);
		frame = new JFrame("Test");
		frame.getContentPane().add(field);
		frame.pack();
		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.setVisible(false);
		programOneSpace.release(this);
		programMultiSpaces.release(this);
	}

	@Test
	public void testDefaultState() {
		assertTrue(getText().isBlank());
		assertNull(getAddress());
	}

	@Test
	public void testHexOrDecimalMode() {
		setText("100");		// should have defaulted to hex mode
		assertEquals(addr(0x100), getAddress());

		setHexMode(false);
		assertEquals(addr(100), field.getAddress());

		setHexMode(true);
		assertEquals(addr(0x100), field.getAddress());
	}

	@Test
	public void testSwitchingBetweenOneAndMultiSpaces() {
		assertEquals(1, field.getComponentCount());
		setProgram(programMultiSpaces);
		assertEquals(2, field.getComponentCount());
		setProgram(programOneSpace);
		assertEquals(1, field.getComponentCount());
	}

	@Test
	public void testSetAddress() {
		setAddress(addr(0x100));
		assertEquals("100", getText());
		setHexMode(false);
		setAddress(addr(0x100));
		assertEquals("0x100", getText());
	}

	@Test
	public void testSettingAddressChangesResultingSpace() {
		setProgram(programMultiSpaces);
		setText("100");
		Address a = getAddress();
		assertEquals("CODE:0100", a.toString(true));
		Address newAddress = addr(programMultiSpaces, "EXTMEM", 0x20);
		setAddress(newAddress);
		setText("100");
		a = getAddress();
		assertEquals("EXTMEM:0100", a.toString(true));
	}

	@Test
	public void testGetAddressWithBadExpression() {
		setText("100+ (");
		assertNull(getAddress());
	}

	@Test
	public void testWorksWithJustAddressFactory() {
		setAddressFactory(programMultiSpaces.getAddressFactory());
		setText("100");
		assertEquals(addr(programMultiSpaces, 0x100), getAddress());
	}

	@Test
	public void testGetSelectedAddressSpace() {
		setProgram(programMultiSpaces);
		ProgramAddressFactory factory = programMultiSpaces.getAddressFactory();
		AddressSpace codeSpace = factory.getAddressSpace("CODE");
		AddressSpace extmemSpace = factory.getAddressSpace("EXTMEM");

		assertEquals(codeSpace, getAddressSpaceInField());
		setAddress(addr(programMultiSpaces, "EXTMEM", 100));
		assertEquals(extmemSpace, getAddressSpaceInField());
	}

	@Test
	public void testSpaceFilter() {
		setProgram(programMultiSpaces);
		setSpaceFilter(s -> s.getName().equals("EXTMEM"));
		assertEquals(1, field.getComponentCount());
		setText("100");
		assertEquals(addr(programMultiSpaces, "EXTMEM", 0x100), getAddress());
	}

	@Test
	public void testAddressChangeConsumer() {
		setText("200");
		assertEquals(addr(0x200), changedAddress);
		setText("300");
		assertEquals(addr(0x300), changedAddress);
		setText("lkjlkj");
		assertNull(changedAddress);
	}

	@Test
	public void testAddressErrorConsmer() {
		errorMessage = null;
		setText("200");
		assertNull(errorMessage);

		setText("xyz");
		assertEquals("Could not evaluate token \"xyz\"", errorMessage);
	}

	private Address addr(long offset) {
		return addr(programOneSpace, offset);
	}

	private Address addr(ProgramDB p, long offset) {
		return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Address addr(ProgramDB p, String spaceName, long offset) {
		AddressSpace space = p.getAddressFactory().getAddressSpace(spaceName);
		return space.getAddress(offset);
	}

	private void setProgram(Program p) {
		runSwing(() -> field.setProgram(p));
	}

	private void setAddressFactory(AddressFactory factory) {
		runSwing(() -> field.setAddressFactory(factory));
	}

	private void setSpaceFilter(Predicate<AddressSpace> filter) {
		runSwing(() -> field.setAddressSpaceFilter(filter));
	}

	private void setText(String value) {
		runSwing(() -> field.setText(value));
	}

	private String getText() {
		return runSwing(() -> field.getText());
	}

	private void setAddress(Address a) {
		runSwing(() -> field.setAddress(a));
	}

	private Address getAddress() {
		return runSwing(() -> field.getAddress());
	}

	private AddressSpace getAddressSpaceInField() {
		return runSwing(() -> field.getAddressSpace());
	}

	private void setHexMode(boolean hexMode) {
		runSwing(() -> field.setAssumeHex(hexMode));
		waitForSwing();
	}

	private void addressChanged(Address address) {
		this.changedAddress = address;
	}

	private void addressError(String errorMessage) {
		this.errorMessage = errorMessage;
	}
}
