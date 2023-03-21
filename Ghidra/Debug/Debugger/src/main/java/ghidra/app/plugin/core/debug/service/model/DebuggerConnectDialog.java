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
import javax.swing.text.View;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;

import docking.ReusableDialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractConnectAction;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.app.services.DebuggerModelService;
import ghidra.async.AsyncUtils;
import ghidra.async.SwingExecutorService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.Property;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.datastruct.CollectionChangeListener;

public class DebuggerConnectDialog extends ReusableDialogComponentProvider
		implements PropertyChangeListener {
	private static final String KEY_CURRENT_FACTORY_CLASSNAME = "currentFactoryCls";
	private static final String KEY_SUCCESS_FACTORY_CLASSNAME = "successFactoryCls";
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

	protected record FactoryEntry(DebuggerModelFactory factory) {
		@Override
		public String toString() {
			return factory.getBrief();
		}
	}

	protected record PrioritizedFactory(FactoryEntry entry, int priority) {
		public PrioritizedFactory(FactoryEntry ent, Program program) {
			this(ent, ent.factory.getPriority(program));
		}
	}

	protected enum NameComparator implements Comparator<String> {
		INSTANCE;

		@Override
		public int compare(String o1, String o2) {
			boolean p1 = o1.startsWith("PROTOTYPE:");
			boolean p2 = o2.startsWith("PROTOTYPE:");
			if (p1 && !p2) {
				return 1;
			}
			if (!p1 && p2) {
				return -1;
			}
			return o1.toLowerCase().compareTo(o2.toLowerCase());
		}
	}

	private DebuggerModelService modelService;

	private DebuggerModelFactory currentFactory;
	private DebuggerModelFactory successFactory;
	private final Map<DebuggerModelFactory, FactoryEntry> factories = new HashMap<>();
	private FactoriesChangedListener listener = new FactoriesChangedListener();

	private JComboBox<FactoryEntry> dropdown;
	protected final DefaultComboBoxModel<FactoryEntry> dropdownModel = new DefaultComboBoxModel<>();

	private final BidiMap<Property<?>, PropertyEditor> propertyEditors =
		new DualLinkedHashBidiMap<>();
	private final Map<Property<?>, Component> components = new LinkedHashMap<>();

	protected JLabel description;
	protected JPanel gridPanel;

	protected JButton connectButton;
	protected CompletableFuture<? extends DebuggerObjectModel> futureConnect;
	protected CompletableFuture<DebuggerObjectModel> result;

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
				toAdd.sort(Comparator.comparing(FactoryEntry::toString, NameComparator.INSTANCE));
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

	@Override
	public void dispose() {
		modelService.removeFactoriesChangedListener(listener);
		clearFactories();
		super.dispose();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		Box topBox = Box.createVerticalBox();
		dropdown = new JComboBox<>(dropdownModel);
		topBox.add(dropdown);

		// Avoid Swing's automatic indentation
		JPanel inner = new JPanel(new BorderLayout());
		description = new JLabel(HTML_BOLD_DESCRIPTION + "</html>");
		description.setBorder(new EmptyBorder(10, 0, 10, 0));
		description.setPreferredSize(new Dimension(400, 150));
		inner.add(description);
		topBox.add(inner);

		panel.add(topBox, BorderLayout.NORTH);

		gridPanel = new JPanel(new GridBagLayout());

		JPanel centering = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JScrollPane scrolling = new JScrollPane(centering, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
			JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrolling.setPreferredSize(new Dimension(100, 200));
		panel.add(scrolling, BorderLayout.CENTER);
		centering.add(gridPanel);

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
			gridPanel.removeAll();
		}
		else if (evt.getStateChange() == ItemEvent.SELECTED) {
			FactoryEntry ent = (FactoryEntry) evt.getItem();
			currentFactory = ent.factory;
			populateOptions();
			/**
			 * Don't repack here. It can shrink the dialog, which may not be what the user wants.
			 */
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
			futureConnect = currentFactory.build();
		}
		futureConnect.thenCompose(m -> m.fetchModelRoot()).thenAcceptAsync(r -> {
			DebuggerObjectModel m = r.getModel();
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
		}, SwingExecutorService.LATER).exceptionally(e -> {
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
			successFactory = currentFactory;
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

	/**
	 * For testing and documentation purposes only!
	 */
	public synchronized void setFactoryByBrief(String brief) {
		synchronized (factories) {
			for (FactoryEntry fe : factories.values()) {
				if (Objects.equals(brief, fe.factory.getBrief())) {
					dropdownModel.setSelectedItem(fe);
					return;
				}
			}
			throw new AssertionError();
		}
	}

	protected synchronized CompletableFuture<DebuggerObjectModel> reset(
			DebuggerModelFactory factory, Program program) {
		if (factory != null) {
			synchronized (factories) {
				dropdownModel.setSelectedItem(factories.get(factory));
			}
			dropdown.setEnabled(false);
		}
		else {
			selectCompatibleFactory(program);
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
		description.setText(HTML_BOLD_DESCRIPTION + currentFactory.getHtmlDetails());

		propertyEditors.clear();
		components.clear();
		Map<String, Property<?>> optsMap = currentFactory.getOptions();
		gridPanel.removeAll();
		GridBagConstraints constraints;

		if (optsMap.isEmpty()) {
			JLabel label =
				new JLabel("<html>There are no configuration options for this connector.");
			constraints = new GridBagConstraints();
			gridPanel.add(label, constraints);
		}

		int i = 0;
		for (Map.Entry<String, Property<?>> opt : optsMap.entrySet()) {
			Property<?> property = opt.getValue();
			JLabel label = new JLabel("<html>" + HTMLUtilities.escapeHTML(opt.getKey())) {
				@Override
				public Dimension getPreferredSize() {
					View v = (View) getClientProperty("html");
					if (v == null) {
						return super.getPreferredSize();
					}
					v.setSize(200, 0);
					float height = v.getPreferredSpan(View.Y_AXIS);
					return new Dimension(200, (int) height);
				}
			};
			constraints = new GridBagConstraints();
			constraints.fill = GridBagConstraints.BOTH;
			constraints.gridx = 0;
			constraints.gridy = i;
			constraints.insets = new Insets(i == 0 ? 0 : 5, 0, 0, 5);
			gridPanel.add(label, constraints);

			Class<?> type = property.getValueClass();
			PropertyEditor editor = PropertyEditorManager.findEditor(type);
			if (editor == null) {
				throw new RuntimeException("Could not find editor for " + property.getValueClass());
			}
			editor.setValue(property.getValue());
			editor.addPropertyChangeListener(this);
			Component editorComponent = MiscellaneousUtils.getEditorComponent(editor);
			if (editorComponent instanceof JTextField textField) {
				textField.setColumns(13);
			}
			constraints = new GridBagConstraints();
			constraints.fill = GridBagConstraints.HORIZONTAL;
			constraints.anchor = GridBagConstraints.WEST;
			constraints.gridx = 1;
			constraints.gridy = i;
			constraints.insets = new Insets(i == 0 ? 0 : 5, 0, 0, 0);
			gridPanel.add(editorComponent, constraints);

			propertyEditors.put(property, editor);
			components.put(property, editorComponent);

			i++;
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
		if (currentFactory != null) {
			saveState.putString(KEY_CURRENT_FACTORY_CLASSNAME, currentFactory.getClass().getName());
		}
		if (successFactory != null) {
			saveState.putString(KEY_SUCCESS_FACTORY_CLASSNAME, successFactory.getClass().getName());
		}
	}

	protected FactoryEntry getByName(String className) {
		synchronized (factories) {
			for (FactoryEntry ent : factories.values()) {
				String name = ent.factory.getClass().getName();
				if (className.equals(name)) {
					return ent;
				}
			}
			return null;
		}
	}

	protected Collection<PrioritizedFactory> getByPriority(Program program) {
		synchronized (factories) {
			return factories.values()
					.stream()
					.map(e -> new PrioritizedFactory(e, program))
					.sorted(Comparator.comparing(pf -> -pf.priority()))
					.toList();
		}
	}

	protected PrioritizedFactory getFirstCompatibleByPriority(Program program) {
		for (PrioritizedFactory pf : getByPriority(program)) {
			if (pf.priority >= 0) {
				return pf;
			}
			return null;
		}
		return null;
	}

	protected void selectCompatibleFactory(Program program) {
		if (currentFactory != null && currentFactory.isCompatible(program)) {
			return;
		}
		if (successFactory != null && successFactory.isCompatible(program)) {
			currentFactory = successFactory;
			synchronized (factories) {
				dropdown.setSelectedItem(factories.get(successFactory));
			}
			return;
		}
		PrioritizedFactory compat = getFirstCompatibleByPriority(program);
		if (compat == null) {
			return;
		}
		currentFactory = compat.entry.factory;
		dropdown.setSelectedItem(compat.entry);
	}

	public void readConfigState(SaveState saveState) {
		String currentFactoryName = saveState.getString(KEY_CURRENT_FACTORY_CLASSNAME, null);
		FactoryEntry restoreCurrent =
			currentFactoryName == null ? null : getByName(currentFactoryName);
		currentFactory = restoreCurrent == null ? null : restoreCurrent.factory;
		dropdown.setSelectedItem(restoreCurrent);

		String successFactoryName = saveState.getString(KEY_SUCCESS_FACTORY_CLASSNAME, null);
		FactoryEntry restoreSuccess =
			successFactoryName == null ? null : getByName(successFactoryName);
		successFactory = restoreSuccess == null ? null : restoreSuccess.factory;
	}
}
