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
package ghidra.app.plugin.core.debug.gui.listing;

import java.awt.BorderLayout;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.async.AsyncUtils;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class DebuggerGoToDialog extends DialogComponentProvider {

	private final DebuggerListingProvider provider;
	final JTextField textExpression;
	final JComboBox<String> comboSpaces;
	private final DefaultComboBoxModel<String> modelSpaces;

	protected DebuggerGoToDialog(DebuggerListingProvider provider) {
		super("Go To", true, true, true, false);
		this.provider = provider;

		textExpression = new JTextField();
		modelSpaces = new DefaultComboBoxModel<>();
		comboSpaces = new JComboBox<>(modelSpaces);

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(new EmptyBorder(16, 16, 16, 16));
		JLabel help = new JLabel(
			"<html>Enter any sleigh expression to evaluate against the current thread.<br/>" +
				"Note that constants and memory derefs must have a resolved size, e.g.:" +
				"<ul>" +
				"<li><code>0x00401234:4</code></li>" +
				"<li><code>*:4 EAX</code></li>" +
				"</ul></html>");
		help.getMaximumSize().width = 400;
		panel.add(help, BorderLayout.NORTH);
		Box box = Box.createHorizontalBox();
		box.setBorder(new EmptyBorder(16, 0, 0, 0));
		panel.add(box);

		box.add(new JLabel("*["));
		box.add(comboSpaces);
		box.add(new JLabel("]"));
		box.add(textExpression);

		addWorkPanel(panel);
		setFocusComponent(textExpression);

		addOKButton();
		addCancelButton();
	}

	protected void populateSpaces(SleighLanguage language) {
		String curSpace = (String) comboSpaces.getSelectedItem();
		modelSpaces.removeAllElements();
		AddressFactory factory = language.getAddressFactory();
		List<String> names = Stream.of(factory.getAddressSpaces())
				.filter(AddressSpace::isMemorySpace)
				.map(AddressSpace::getName)
				.collect(Collectors.toList());
		modelSpaces.addAll(names);
		if (names.contains(curSpace)) {
			comboSpaces.setSelectedItem(curSpace);
		}
		else {
			comboSpaces.setSelectedItem(factory.getDefaultAddressSpace().getName());
		}
	}

	@Override
	protected void okCallback() {
		CompletableFuture<Boolean> future;
		try {
			future = provider.goToSleigh((String) comboSpaces.getSelectedItem(),
				textExpression.getText());
		}
		catch (Throwable t) {
			future = CompletableFuture.failedFuture(t);
		}
		future.thenAccept(success -> {
			if (!success) {
				setStatusText("Address not in trace", MessageType.ERROR, true);
			}
			else {
				close();
			}
		}).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			Msg.error(this, ex.getMessage(), ex);
			setStatusText(ex.getMessage(), MessageType.ERROR, true);
			return null;
		});
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	public void show(SleighLanguage language) {
		populateSpaces(language);
		provider.getTool().showDialog(this);
	}
}
