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
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.*;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.action.DebuggerGoToTrait.GoToResult;
import ghidra.app.plugin.core.debug.gui.breakpoint.AbstractDebuggerSleighInputDialog;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.services.DebuggerListingService;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.action.GoToInput;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.pcode.exec.SleighUtils.LitIdMode;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.util.*;

public class DebuggerGoToDialog extends AbstractDebuggerSleighInputDialog {
	private static final String TEXT = """
			<html>
			<body width="400px">
			<p>
			Enter an address or Sleigh expression. Use + (plus) or - (minus) for movement relative
			to your current address. Press <b>F1</b> for help and examples.
			</p>
			</body>
			</html>
			""";

	private final DebuggerGoToTrait trait;
	private final DefaultComboBoxModel<String> modelSpaces;

	final JComboBox<String> comboSpaces;
	private final Map<LitIdMode, JRadioButton> modeButtons;

	private LitIdMode mode = LitIdMode.HEX;

	public DebuggerGoToDialog(DebuggerGoToTrait trait) {
		super("Go To", TEXT);
		setHelpLocation(new HelpLocation(
			PluginUtils.getPluginNameFromClass(DebuggerListingPlugin.class),
			DebuggerResources.GoToAction.HELP_ANCHOR));
		this.trait = trait;

		modelSpaces = new DefaultComboBoxModel<>();
		comboSpaces = new JComboBox<>(modelSpaces);

		Box spaceBox = Box.createHorizontalBox();
		spaceBox.add(comboSpaces);
		spaceBox.add(new JLabel(":"));
		panel.add(spaceBox, BorderLayout.WEST);

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

		Box modeBox = Box.createHorizontalBox();
		modeBox.setBorder(BorderFactory.createTitledBorder("Radix / Label Resolution"));
		Map<LitIdMode, JRadioButton> modeButtons = new LinkedHashMap<>();
		ButtonGroup modeGroup = new ButtonGroup();
		for (LitIdMode mode : LitIdMode.VALUES) {
			JRadioButton button = new JRadioButton(mode.description);
			modeButtons.put(mode, button);
			modeGroup.add(button);
			button.addActionListener(evt -> {
				if (button.isSelected()) {
					this.mode = mode;
				}
			});
			modeBox.add(button);
			button.setSelected(this.mode == mode);
		}
		this.modeButtons = Collections.unmodifiableMap(modeButtons);
		panel.add(modeBox, BorderLayout.SOUTH);
	}

	protected void populateSpaces(AddressFactory factory) {
		String curSpace = (String) comboSpaces.getSelectedItem();
		modelSpaces.removeAllElements();
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
		trait.validate(platform.getAddressFactory(), (String) comboSpaces.getSelectedItem(),
			getInput(), mode);
	}

	@Override
	protected void addErrorAttribute(int start, int stop) {
		String input = getInput();
		if (input.startsWith("+") || input.startsWith("-")) {
			super.addErrorAttribute(start - 2, stop - 2);
		}
		else {
			super.addErrorAttribute(start, stop);
		}
	}

	@Override // public for tests
	public void okCallback() {
		validateAndMarkup();
		if (!isValid) {
			return;
		}

		CompletableFuture<GoToResult> future;
		try {
			future = trait.goTo((String) comboSpaces.getSelectedItem(), getInput(), mode);
		}
		catch (Throwable t) {
			future = CompletableFuture.failedFuture(t);
		}
		future.thenAccept(result -> {
			if (!result.success()) {
				setStatusText("""
						<html>Address <code>%s</code> not in address map.
						Consider <b>Force Full View</b>.
						""".formatted(result.address()),
					MessageType.ERROR,
					true);
				repack();
			}
			else {
				saveLitIdMode();
				close();
			}
		}).exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			setStatusText(ex.getMessage(), MessageType.ERROR, true);
			repack();
			return null;
		});
	}

	@Override
	public void cancelCallback() {
		close();
	}

	protected void saveLitIdMode() {
		DebuggerListingService listing = trait.tool.getService(DebuggerListingService.class);
		if (listing != null) {
			listing.setGoToSleighMode(mode);
		}
	}

	protected void loadLitIdMode() {
		DebuggerListingService listing = trait.tool.getService(DebuggerListingService.class);
		if (listing != null) {
			setLitIdMode(listing.getGoToSleighMode());
		}
	}

	public void show(AddressFactory factory, GoToInput defaultInput) {
		populateSpaces(factory);
		if (factory.getAddressSpace(defaultInput.space()) != null) {
			comboSpaces.setSelectedItem(defaultInput.space());
		}
		loadLitIdMode();
		prompt(trait.tool, defaultInput.offset());
	}

	public void setOffset(String offset) {
		textInput.setText(offset);
	}

	public void setLitIdMode(LitIdMode mode) {
		this.mode = mode;
		for (Map.Entry<LitIdMode, JRadioButton> ent : modeButtons.entrySet()) {
			ent.getValue().setSelected(ent.getKey() == mode);
		}
	}
}
