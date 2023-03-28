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
package ghidra.app.plugin.core.debug.gui.action;

import java.awt.BorderLayout;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.*;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.action.DebuggerGoToTrait.GoToResult;
import ghidra.app.plugin.core.debug.gui.breakpoint.AbstractDebuggerSleighInputDialog;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.util.*;

public class DebuggerGoToDialog extends AbstractDebuggerSleighInputDialog {
	private static final String TEXT = """
			<html>
			<body width="400px">
			<p>
			Enter an address or Sleigh expression. Press <b>F1</b> for help and examples.
			</p>
			</body>
			</html>
			""";

	private final DebuggerGoToTrait trait;
	private final DefaultComboBoxModel<String> modelSpaces;

	final JComboBox<String> comboSpaces;

	public DebuggerGoToDialog(DebuggerGoToTrait trait) {
		super("Go To", TEXT);
		setHelpLocation(new HelpLocation(
			PluginUtils.getPluginNameFromClass(DebuggerListingPlugin.class),
			DebuggerResources.GoToAction.HELP_ANCHOR));
		this.trait = trait;

		modelSpaces = new DefaultComboBoxModel<>();
		comboSpaces = new JComboBox<>(modelSpaces);

		Box hbox = Box.createHorizontalBox();
		hbox.add(comboSpaces);
		hbox.add(new JLabel(":"));
		panel.add(hbox, BorderLayout.WEST);

		setFocusComponent(textInput);

		textInput.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					okCallback();
					e.consume();
				}
			}
		});
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
	protected void validate() {
		TracePlatform platform = trait.current.getPlatform();
		if (platform == null) {
			throw new AssertionError("No current trace platform");
		}
		Address address = platform.getAddressFactory().getAddress(getInput());
		if (address != null) {
			return;
		}
		SleighUtils.parseSleighExpression(getInput());
	}

	@Override // public for tests
	public void okCallback() {
		validateAndMarkup();
		if (!isValid) {
			return;
		}

		CompletableFuture<GoToResult> future;
		try {
			future = trait.goTo((String) comboSpaces.getSelectedItem(), getInput());
		}
		catch (Throwable t) {
			future = CompletableFuture.failedFuture(t);
		}
		future.thenAccept(result -> {
			if (!result.success()) {
				setStatusText("<html>Address <code>" + result.address() + "</code> not in trace", MessageType.ERROR,
					true);
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
	public void cancelCallback() {
		close();
	}

	public void show(SleighLanguage language, GoToInput defaultInput) {
		populateSpaces(language);
		if (language.getAddressFactory().getAddressSpace(defaultInput.space()) != null) {
			comboSpaces.setSelectedItem(defaultInput.space());
		}
		prompt(trait.tool, defaultInput.offset());
	}

	public void setOffset(String offset) {
		textInput.setText(offset);
	}
}
