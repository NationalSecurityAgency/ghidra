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
package docking.wiz;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Objects;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.textfield.IntegerTextField;
import docking.wizard.*;
import ghidra.util.layout.PairLayout;

public class WizardTest extends AbstractDockingTest {

	private WizardDialog wizardDialog;
	private TestWizardModel model;
	private boolean stage1Disposed;
	private boolean stage2Disposed;
	private boolean stage3Disposed;

	@Before
	public void setup() {
		model = new TestWizardModel();
		wizardDialog = new WizardDialog(model);
		showDialog(wizardDialog);
	}

	@Test
	public void testInitialState() {
		assertFalse(canGoNext());
		assertFalse(canGoBack());
		assertFalse(canFinish());
		assertTrue(canCancel());
		assertEquals("Please enter a name", getStatusMessage());

	}

	@Test
	public void testAfterNameEntered() {
		setName("Bob");

		assertFalse(canGoNext());
		assertFalse(canGoBack());
		assertFalse(canFinish());
		assertTrue(canCancel());
		assertEquals("Please enter an address", getStatusMessage());

	}

	@Test
	public void testAfterNameAndAddressEntered() {
		setName("Bob");
		setAddress("123 Main Street");
		assertTrue(canGoNext());
		assertFalse(canGoBack());
		assertFalse(canFinish());
		assertTrue(canCancel());
		assertNull(getStatusMessage());

	}

	@Test
	public void testPanel2State() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		assertFalse(canGoNext());
		assertTrue(canGoBack());
		assertFalse(canFinish());
		assertTrue(canCancel());
		assertEquals("Age must be >= 18", getStatusMessage());

	}

	@Test
	public void testPanel2StateAfterAge() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);

		assertTrue(canGoNext());
		assertTrue(canGoBack());
		assertTrue(canFinish());	// phone is optional
		assertTrue(canCancel());

	}

	@Test
	public void testPanel3State() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		goNext();

		assertFalse(canGoNext());
		assertTrue(canGoBack());
		assertTrue(canFinish());	// phone is optional
		assertTrue(canCancel());
	}

	@Test
	public void testGoBack() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		assertTrue(canGoBack());
		goBack();
		assertTrue(canGoNext());
		assertTrue(canFinish());
		finish();
		assertEquals(32, model.getData().getAge());
	}

	@Test
	public void testGoBackAndForwardDoesntResetStage2Data() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		assertTrue(canGoBack());
		goBack();
		assertTrue(canGoNext());
		goNext();
		finish();
		assertEquals(32, model.getData().getAge());
	}

	@Test
	public void testGoBackAndChangingNameResetsAgeAndEnablement() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		assertTrue(canGoBack());
		goBack();
		setName("Joe");
		assertTrue(canGoNext());
		assertFalse(canFinish());
	}

	@Test
	public void testFinishAfterStage2() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		finish();
		assertFalse(wizardDialog.isVisible());
		TestWizardData data = model.getData();
		assertEquals("Bob", data.getName());
		assertEquals("123 Main Street", data.getAddress());
		assertEquals(32, data.getAge());
		assertEquals(0, data.getPhoneNumber());
	}

	@Test
	public void testFinishAfterStage3() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		goNext();
		setPhoneNumber(1234567890);
		finish();
		assertFalse(wizardDialog.isVisible());
		TestWizardData data = model.getData();
		assertEquals("Bob", data.getName());
		assertEquals("123 Main Street", data.getAddress());
		assertEquals(32, data.getAge());
		assertEquals(1234567890, data.getPhoneNumber());
	}

	@Test
	public void testDisposeGetsCalledWhenFinished() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		goNext();
		setPhoneNumber(1234567890);
		finish();
		assertTrue(stage1Disposed);
		assertTrue(stage2Disposed);
		assertTrue(stage3Disposed);

	}

	@Test
	public void testDisposeGetsCalledWhenCancelled() {
		setName("Bob");
		setAddress("123 Main Street");
		goNext();
		setAge(32);
		goNext();
		setPhoneNumber(1234567890);
		cancel();
		assertTrue(stage1Disposed);
		assertTrue(stage2Disposed);
		assertTrue(stage3Disposed);
	}

	private void goNext() {
		runSwing(() -> model.goNext());
	}

	private void goBack() {
		runSwing(() -> model.goBack());
	}

	private void finish() {
		runSwing(() -> model.finish());
	}

	private void cancel() {
		runSwing(() -> wizardDialog.cancel());
	}

	private void setName(String name) {
		runSwing(() -> {
			TestWizardStage1 stage = (TestWizardStage1) model.getCurrentStep();
			stage.setName(name);
		});
	}

	private void setAddress(String address) {
		runSwing(() -> {
			TestWizardStage1 stage = (TestWizardStage1) model.getCurrentStep();
			stage.setAddress(address);
		});
	}

	private void setAge(int age) {
		runSwing(() -> {
			TestWizardStage2 stage = (TestWizardStage2) model.getCurrentStep();
			stage.setAge(age);
		});
	}

	private void setPhoneNumber(int phone) {
		runSwing(() -> {
			TestWizardStage3 stage = (TestWizardStage3) model.getCurrentStep();
			stage.setPhoneNumber(phone);
		});
	}

	private boolean canGoBack() {
		return runSwing(() -> model.canGoBack());
	}

	private boolean canGoNext() {
		return runSwing(() -> model.canGoNext());
	}

	private boolean canFinish() {
		return runSwing(() -> model.canFinish());
	}

	private boolean canCancel() {
		return runSwing(() -> model.canCancel());
	}

	private String getStatusMessage() {
		return runSwing(() -> model.getStatusMessage());
	}

	private void showDialog(WizardDialog dialog) {
		// note: can't call runSwing with true, but use false and then waitForSwing() or
		// else this thread blocks forever.
		runSwing(() -> dialog.show(), false);
		waitForSwing();
	}

	private static class TestWizardData {
		private String name;
		private String address;
		private long phoneNumber;
		private int age;

		public void setName(String name) {
			if (!Objects.equals(this.name, name)) {
				age = 0;	// pretend age should be reset when name changes
			}
			this.name = name;
		}

		public String getName() {
			return name;
		}

		public void setAddress(String address) {
			this.address = address;
		}

		public String getAddress() {
			return address;
		}

		public long getPhoneNumber() {
			return phoneNumber;
		}

		public void setPhoneNumber(long phoneNumber) {
			this.phoneNumber = phoneNumber;
		}

		public void setAge(int age) {
			this.age = age;
		}

		public int getAge() {
			return age;
		}
	}

	private class TestWizardStage1 extends WizardStep<TestWizardData> {
		private JTextField nameField;
		private JTextField addressField;
		private JComponent component;

		protected TestWizardStage1(WizardModel<TestWizardData> model) {
			super(model, "Name & Address", null);
			component = buildComponent();
		}

		public void setName(String name) {
			nameField.setText(name);
		}

		public void setAddress(String name) {
			addressField.setText(name);
		}

		@Override
		public void initialize(TestWizardData data) {
			// nothing

		}

		@Override
		protected void dispose(TestWizardData data) {
			stage1Disposed = true;
		}

		@Override
		public boolean isValid() {
			setStatusMessage(null);
			String name = nameField.getText();
			String address = addressField.getText();
			if (name.isBlank()) {
				setStatusMessage("Please enter a name");
				return false;
			}
			if (address.isBlank()) {
				setStatusMessage("Please enter an address");
				return false;
			}
			return true;
		}

		@Override
		public void populateData(TestWizardData data) {
			data.setName(nameField.getText());
			data.setAddress(addressField.getText());
		}

		@Override
		public boolean apply(TestWizardData data) {
			// pretend extra check when next button or finish is applied
			if (data.getAddress().length() < 10) {
				setStatusMessage("Address is too short");
				return false;
			}
			return true;
		}

		@Override
		public boolean canFinish(TestWizardData data) {
			return true;
		}

		@Override
		public JComponent getComponent() {
			return component;
		}

		private JComponent buildComponent() {
			JPanel panel = new JPanel(new PairLayout());
			nameField = new JTextField(20);
			addressField = new JTextField(30);
			panel = new JPanel(new PairLayout());
			panel.add(new JLabel("Name:"));
			panel.add(nameField);
			panel.add(new JLabel("Address:"));
			panel.add(addressField);
			DocumentListener listener = new DocumentListener() {

				@Override
				public void removeUpdate(DocumentEvent e) {
					notifyStatusChanged();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					notifyStatusChanged();
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					notifyStatusChanged();
				}
			};
			nameField.getDocument().addDocumentListener(listener);
			addressField.getDocument().addDocumentListener(listener);
			return panel;
		}
	}

	private class TestWizardStage2 extends WizardStep<TestWizardData> {
		private IntegerTextField ageField;
		private JComponent component;

		protected TestWizardStage2(WizardModel<TestWizardData> model) {
			super(model, "Age", null);
			component = buildComponent();
		}

		public void setAge(int age) {
			ageField.setValue(age);
		}

		@Override
		protected void dispose(TestWizardData data) {
			stage2Disposed = true;
		}

		@Override
		public void initialize(TestWizardData data) {
			int age = data.getAge();
			if (age == 0) {
				ageField.setText("");
			}
			else {
				ageField.setValue(age);
			}
		}

		@Override
		public boolean isValid() {
			setStatusMessage(null);
			int age = ageField.getIntValue();
			if (age < 18) {
				setStatusMessage("Age must be >= 18");
				return false;
			}
			return true;
		}

		@Override
		public void populateData(TestWizardData data) {
			data.setAge(ageField.getIntValue());
		}

		@Override
		public boolean apply(TestWizardData data) {
			return true;
		}

		@Override
		public JComponent getComponent() {
			return component;
		}

		@Override
		public boolean canFinish(TestWizardData data) {
			return data.getAge() >= 18;
		}

		private JComponent buildComponent() {
			JPanel panel = new JPanel(new PairLayout());
			ageField = new IntegerTextField(10);
			panel = new JPanel(new PairLayout());
			panel.add(new JLabel("Age:"));
			panel.add(ageField.getComponent());

			ageField.addChangeListener(e -> notifyStatusChanged());
			return panel;
		}
	}

	private class TestWizardStage3 extends WizardStep<TestWizardData> {
		private IntegerTextField phoneField;
		private JComponent component;

		protected TestWizardStage3(WizardModel<TestWizardData> model) {
			super(model, "Phone #", null);
			component = buildComponent();
		}

		@Override
		public void initialize(TestWizardData data) {
			// nothing

		}

		public void setPhoneNumber(int phone) {
			phoneField.setValue(phone);
		}

		@Override
		protected void dispose(TestWizardData data) {
			stage3Disposed = true;
		}

		@Override
		public boolean isValid() {
			setStatusMessage(null);
			long phone = phoneField.getLongValue();
			if (phone == 0) {
				// allow phone # to be optional
				return true;
			}
			// if non zero, require to be 10 digits
			String s = Long.toString(phone);
			if (s.length() != 10) {
				setStatusMessage("Phone # must be exactly 10 digits");
				return false;
			}
			return true;
		}

		@Override
		public void populateData(TestWizardData data) {
			data.setPhoneNumber(phoneField.getLongValue());
		}

		@Override
		public boolean apply(TestWizardData data) {
			return true;
		}

		@Override
		public boolean canFinish(TestWizardData data) {
			return true;
		}

		@Override
		public JComponent getComponent() {
			return component;
		}

		private JComponent buildComponent() {
			JPanel panel = new JPanel(new PairLayout());
			phoneField = new IntegerTextField(10);
			panel = new JPanel(new PairLayout());
			panel.add(new JLabel("Phone #:"));
			panel.add(phoneField.getComponent());

			phoneField.addChangeListener(e -> notifyStatusChanged());
			return panel;
		}
	}

	private class TestWizardModel extends WizardModel<TestWizardData> {

		protected TestWizardModel() {
			super("Test Wizard", new TestWizardData());
		}

		@Override
		protected boolean doFinish() {
			return true;
		}

		@Override
		protected void addWizardSteps(List<WizardStep<TestWizardData>> wizardStages) {
			wizardStages.add(new TestWizardStage1(this));
			wizardStages.add(new TestWizardStage2(this));
			wizardStages.add(new TestWizardStage3(this));

		}

	}
}
