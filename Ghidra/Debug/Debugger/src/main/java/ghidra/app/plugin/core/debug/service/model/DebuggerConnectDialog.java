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
package ghidra.app.plugin.core.debug.service.model;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.beans.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractConnectAction;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.app.services.DebuggerModelService;
import ghidra.async.AsyncUtils;
import ghidra.async.SwingExecutorService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.Property;
import ghidra.framework.options.SaveState;
import ghidra.util.*;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.layout.PairLayout;

public class DebuggerConnectDialog extends DialogComponentProvider
		implements PropertyChangeListener {
	private static final String KEY_FACTORY_CLASSNAME = "factoryClassname";
	private static final String HTML_BOLD_DESCRIPTION = "<html><b>Description:</b> ";

	protected class FactoriesChangedListener
			implements CollectionChangeListener<DebuggerModelFactory> {
		@Override
		public void elementAdded(DebuggerModelFactory element) {
			addFactory(element);
		}

		@Override
		public void elementModified(DebuggerModelFactory element) {
			// Don't care
		}

		@Override
		public void elementRemoved(DebuggerModelFactory element) {
			removeFactory(element);
		}
	}

	private DebuggerModelService modelService;

	private DebuggerModelFactory factory;
	private final Map<DebuggerModelFactory, FactoryEntry> factories = new HashMap<>();
	private FactoriesChangedListener listener = new FactoriesChangedListener();

	private JComboBox<FactoryEntry> dropdown;
	protected final DefaultComboBoxModel<FactoryEntry> dropdownModel = new DefaultComboBoxModel<>();

	private final BidiMap<Property<?>, PropertyEditor> propertyEditors =
		new DualLinkedHashBidiMap<>();
	private final Map<Property<?>, Component> components = new LinkedHashMap<>();

	protected JLabel description;
	protected JPanel pairPanel;
	private PairLayout layout;

	protected JButton connectButton;
	protected CompletableFuture<? extends DebuggerObjectModel> futureConnect;
	protected CompletableFuture<DebuggerObjectModel> result;

	protected static class FactoryEntry {
		DebuggerModelFactory factory;

		public FactoryEntry(DebuggerModelFactory factory) {
			this.factory = factory;
		}

		@Override
		public String toString() {
			return factory.getBrief();
		}
	}

	public DebuggerConnectDialog() {
		super(AbstractConnectAction.NAME, true, true, true, false);

		populateComponents();
	}

	protected void clearFactories() {
		synchronized (factories) {
			factories.clear();
			SwingUtilities.invokeLater(() -> {
				dropdownModel.removeAllElements();
			});
		}
	}

	protected void loadFactories() {
		synchronized (factories) {
			List<FactoryEntry> toAdd = new ArrayList<>();
			Set<DebuggerModelFactory> current = modelService.getModelFactories();
			for (DebuggerModelFactory element : current) {
				FactoryEntry entry = new FactoryEntry(element);
				factories.put(element, entry);
				toAdd.add(entry);
			}
			SwingUtilities.invokeLater(() -> {
				toAdd.sort(Comparator.comparing(FactoryEntry::toString));
				for (FactoryEntry entry : toAdd) {
					dropdownModel.addElement(entry);
				}
			});
		}
	}

	protected void addFactory(DebuggerModelFactory element) {
		synchronized (factories) {
			if (factories.containsKey(element)) {
				return;
			}
			FactoryEntry entry = new FactoryEntry(element);
			factories.put(element, entry);
			SwingUtilities.invokeLater(() -> {
				dropdownModel.addElement(entry);
			});
		}
	}

	protected void removeFactory(DebuggerModelFactory element) {
		synchronized (factories) {
			FactoryEntry entry = factories.remove(element);
			if (entry == null) {
				return;
			}
			SwingUtilities.invokeLater(() -> {
				dropdownModel.removeElement(entry);
			});
		}
	}

	public void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeFactoriesChangedListener(listener);
			clearFactories();
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addFactoriesChangedListener(listener);
			loadFactories();
		}
	}

	public void dispose() {
		modelService.removeFactoriesChangedListener(listener);
		clearFactories();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		Box topBox = Box.createVerticalBox();
		panel.add(topBox, BorderLayout.NORTH);

		dropdown = new JComboBox<>(dropdownModel);
		topBox.add(dropdown);

		description = new JLabel(HTML_BOLD_DESCRIPTION + "</html>");
		description.setBorder(new EmptyBorder(10, 0, 10, 0));
		topBox.add(description);

		layout = new PairLayout(5, 5);
		pairPanel = new JPanel(layout);

		JPanel centering = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JScrollPane scrolling = new JScrollPane(centering, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
			JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrolling.setPreferredSize(new Dimension(100, 130));
		panel.add(scrolling, BorderLayout.CENTER);
		centering.add(pairPanel);

		addWorkPanel(panel);

		connectButton = new JButton();
		AbstractConnectAction.styleButton(connectButton);
		addButton(connectButton);

		addCancelButton();

		dropdown.addItemListener(this::itemSelected);
		connectButton.addActionListener(this::connect);
	}

	private void itemSelected(ItemEvent evt) {
		if (evt.getStateChange() == ItemEvent.DESELECTED) {
			pairPanel.removeAll();
		}
		else if (evt.getStateChange() == ItemEvent.SELECTED) {
			FactoryEntry ent = (FactoryEntry) evt.getItem();
			factory = ent.factory;
			populateOptions();
			//repack();
		}
	}

	private void connect(ActionEvent evt) {
		connectButton.setEnabled(false);
		for (Map.Entry<Property<?>, PropertyEditor> ent : propertyEditors.entrySet()) {
			Property<?> prop = ent.getKey();
			@SuppressWarnings("unchecked")
			Property<Object> objProp = (Property<Object>) prop;
			objProp.setValue(ent.getValue().getValue());
		}
		setStatusText("Connecting...");
		synchronized (this) {
			futureConnect = factory.build();
		}
		futureConnect.thenAcceptAsync(m -> {
			modelService.addModel(m);
			setStatusText("");
			close();
			modelService.activateModel(m);
			synchronized (this) {
				/**
				 * NB. Errors will typically be reported, the dialog stays up, and the user is given
				 * an opportunity to rectify the failure. Thus, errors should not be used to
				 * complete the result exceptionally. Only catastrophic errors and cancellation
				 * should affect the result.
				 */
				result.completeAsync(() -> m);
				result = null;
			}
		}, SwingExecutorService.INSTANCE).exceptionally(e -> {
			e = AsyncUtils.unwrapThrowable(e);
			if (!(e instanceof CancellationException)) {
				Msg.showError(this, getComponent(), "Could not connect", e);
			}
			setStatusText("Could not connect: " + e.getMessage(), MessageType.ERROR);
			return null;
		}).whenComplete((v, e) -> {
			synchronized (this) {
				futureConnect = null;
			}
			connectButton.setEnabled(true);
		});
	}

	@Override
	protected void cancelCallback() {
		if (futureConnect != null) {
			futureConnect.cancel(false);
		}
		if (result != null) {
			result.cancel(false);
		}
		super.cancelCallback();
	}

	protected synchronized CompletableFuture<DebuggerObjectModel> reset(
			DebuggerModelFactory factory) {
		if (factory != null) {
			synchronized (factories) {
				dropdownModel.setSelectedItem(factories.get(factory));
			}
			dropdown.setEnabled(false);
		}
		else {
			dropdown.setEnabled(true);
		}

		if (result != null) {
			result.cancel(false);
		}
		result = new CompletableFuture<>();
		setStatusText("");
		connectButton.setEnabled(true);
		return result;
	}

	protected void syncOptionsEnabled() {
		for (Map.Entry<Property<?>, Component> ent : components.entrySet()) {
			ent.getValue().setEnabled(ent.getKey().isEnabled());
		}
	}

	protected void populateOptions() {
		description.setText(
			HTML_BOLD_DESCRIPTION + HTMLUtilities.friendlyEncodeHTML(factory.getHtmlDetails()));

		propertyEditors.clear();
		components.clear();
		Map<String, Property<?>> optsMap = factory.getOptions();
		//layout.setRows(Math.max(1, optsMap.size()));
		pairPanel.removeAll();
		for (Map.Entry<String, Property<?>> opt : optsMap.entrySet()) {
			Property<?> property = opt.getValue();
			JLabel label = new JLabel(opt.getKey());
			pairPanel.add(label);

			Class<?> type = property.getValueClass();
			PropertyEditor editor = PropertyEditorManager.findEditor(type);
			if (editor == null) {
				throw new RuntimeException("Could not find editor for " + property.getValueClass());
			}
			editor.setValue(property.getValue());
			editor.addPropertyChangeListener(this);
			Component comp = MiscellaneousUtils.getEditorComponent(editor);
			pairPanel.add(comp);

			propertyEditors.put(property, editor);
			components.put(property, comp);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		PropertyEditor editor = (PropertyEditor) evt.getSource();
		Property<?> prop = propertyEditors.getKey(editor);
		@SuppressWarnings("unchecked")
		Property<Object> objProp = (Property<Object>) prop;
		objProp.setValue(editor.getValue());
		syncOptionsEnabled();
	}

	public void writeConfigState(SaveState saveState) {
		if (factory != null) {
			saveState.putString(KEY_FACTORY_CLASSNAME, factory.getClass().getName());
		}
	}

	public void readConfigState(SaveState saveState) {
		String factoryName = saveState.getString(KEY_FACTORY_CLASSNAME, null);
		if (factoryName == null) {
			return;
		}
		synchronized (factories) {
			for (Map.Entry<DebuggerModelFactory, FactoryEntry> ent : factories.entrySet()) {
				String name = ent.getKey().getClass().getName();
				if (factoryName.equals(name)) {
					factory = ent.getKey();
					dropdown.setSelectedItem(ent.getValue());
				}
			}
		}
	}
}
