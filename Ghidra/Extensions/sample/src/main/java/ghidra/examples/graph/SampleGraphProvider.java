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
package ghidra.examples.graph;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.*;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.examples.graph.layout.SampleGraphPluginDependencyLayoutProvider;
import ghidra.framework.plugintool.*;
import ghidra.graph.job.FilterVerticesJob;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;
import ghidra.graph.viewer.layout.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * A {@link ComponentProvider} that is the UI component of the {@link SampleGraphPlugin}.  This
 * shows a graph of the plugins in the system.
 */
public class SampleGraphProvider extends ComponentProviderAdapter {

	/*package*/ static final String NAME = "Sample Graph";
	/*package*/ static final String SHOW_FILTER_ACTION_NAME = "Show Filter";
	/*package*/ static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";

	private SampleGraphPlugin plugin;
	private JPanel mainPanel;
	private JComponent component;

	private JPanel filterPanel;
	private JRadioButton fadedButton;
	private JRadioButton removedButton;
	private String filterText;
	private SwingUpdateManager filterUpdateManager = new SwingUpdateManager(() -> doFilterGraph());

	private DropDownSelectionTextField<String> textField;
	private FilterDocumentListener filterDocumentListener = new FilterDocumentListener();

	private SampleGraph graph;
	private VisualGraphView<SampleVertex, SampleEdge, SampleGraph> view;
	private LayoutProvider<SampleVertex, SampleEdge, SampleGraph> layoutProvider;

	public SampleGraphProvider(PluginTool tool, SampleGraphPlugin plugin) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;

		addToTool();
		createActions();

		buildComponent();

		setHelpLocation(SampleGraphPlugin.DEFAULT_HELP);
	}

	private void installGraph() {
		if (graph != null) {
			graph.dispose();
		}

		buildGraph();

		buildFilterPanel();

		view.setLayoutProvider(layoutProvider);
		view.setGraph(graph);
	}

	void dispose() {
		filterUpdateManager.dispose();
		removeFromTool();
	}

	@Override
	public void componentShown() {
		installGraph();
	}

	private void buildComponent() {

		view = new VisualGraphView<>();

		// these default to off; they are typically controlled via a UI element; the 
		// values set here are arbitrary and are for demo purposes
		view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
		view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

		installTooltipProvider();

		component = view.getViewComponent();

		mainPanel = new JPanel(new BorderLayout());

		mainPanel.add(component, BorderLayout.CENTER);
	}

	private void buildFilterPanel() {
		filterPanel = new JPanel();
		filterPanel.setName("sample.graph.filter.panel");
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.LINE_AXIS));
		filterPanel.add(createNameFilterWidget());
		filterPanel.add(createFilterEffectWidget());
	}

	private JComponent createNameFilterWidget() {

		List<String> data = getVertexNames();
		DataToStringConverter<String> converter = DataToStringConverter.stringDataToStringConverter;
		DropDownTextFieldDataModel<String> model =
			new DefaultDropDownSelectionDataModel<>(data, converter);
		textField = new DropDownSelectionTextField<>(model);
		textField.setName("sample.graph.filter.textfield");
		textField.getDocument().addDocumentListener(filterDocumentListener);

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.LINE_AXIS));
		JLabel label = new GDLabel("Vertex Filter: ");
		label.setToolTipText(
			"Vertices with names matching the filter will remain, along with connected vertices");
		panel.add(label);
		panel.add(Box.createHorizontalStrut(5));
		panel.add(textField);
		return panel;
	}

	private void doFilterGraph() {

		this.filterText = textField.getText();

		boolean remove = removedButton.isSelected();
		GraphViewer<SampleVertex, SampleEdge> viewer = view.getPrimaryGraphViewer();

		Predicate<SampleVertex> filter =
			v -> StringUtils.containsIgnoreCase(v.getName(), filterText);
		FilterVerticesJob<SampleVertex, SampleEdge> job =
			new FilterVerticesJob<>(viewer, graph, filter, remove);

		VisualGraphViewUpdater<SampleVertex, SampleEdge> updater = viewer.getViewUpdater();
		updater.scheduleViewChangeJob(job);
	}

	private List<String> getVertexNames() {

		Collection<SampleVertex> vertices = graph.getVertices();
		//@formatter:off
		return vertices
				.stream()
				.map(v -> v.getName())
				.collect(Collectors.toList())
		        ;
		//@formatter:on
	}

	private JComponent createFilterEffectWidget() {
		//
		// How should we display the filtered-out vertices? 
		//
		fadedButton = new GRadioButton("Faded");
		fadedButton.setToolTipText("Filtered vertices remain in the graph, but are grayed-out");
		removedButton = new GRadioButton("Removed");
		removedButton.setToolTipText("Filtered vertices are removed from the graph");

		ButtonGroup group = new ButtonGroup();
		group.add(fadedButton);
		group.add(removedButton);
		fadedButton.setSelected(true);

		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		panel.add(new GLabel("Filtered Display: "));
		panel.add(fadedButton);
		panel.add(removedButton);
		return panel;
	}

	private void installTooltipProvider() {

		VertexTooltipProvider<SampleVertex, SampleEdge> tooltipProvider =
			new VertexTooltipProvider<>() {

				@Override
				public JComponent getTooltip(SampleVertex v) {
					JToolTip tip = new JToolTip();
					tip.setTipText(getTooltipText(v, v.getName()));
					return tip;
				}

				@Override
				public JComponent getTooltip(SampleVertex v, SampleEdge e) {
					boolean isStart = e.getStart() == v;
					String prefix;
					if (isStart) {
						prefix = "From: " + v.getName();
					}
					else {
						prefix = "To: " + v.getName();
					}

					String text = getTooltipText(v, prefix);
					JToolTip tip = new JToolTip();
					tip.setTipText(text);
					return tip;
				}

				@Override
				public String getTooltipText(SampleVertex v, MouseEvent e) {
					return getTooltipText(v, v.getName());
				}

				private String getTooltipText(SampleVertex v, String title) {
					return "<html>" + title;// + "<br><hr><br>" + v.getText();
				}
			};
		view.setTooltipProvider(tooltipProvider);
	}

	private void buildGraph() {
		graph = new SampleGraph();

		Map<Class<?>, SampleVertex> pluginToVertices = new HashMap<>();

		List<Plugin> plugins = tool.getManagedPlugins();
		for (Plugin p : plugins) {
			SampleVertex vertex = new SampleVertex(p.getName());
			graph.addVertex(vertex);
			pluginToVertices.put(p.getClass(), vertex);
		}

		for (Plugin p : plugins) {
			SampleVertex from = pluginToVertices.get(p.getClass());

			StringBuilder names = new StringBuilder();
			List<Class<?>> dependencies = p.getPluginDescription().getServicesRequired();
			for (Class<?> serviceClass : dependencies) {
				SampleVertex to = locateService(pluginToVertices, serviceClass);
				if (to != null) {
					names.append(serviceClass.getSimpleName()).append('\n');
					graph.addEdge(new SampleEdge(from, to));
				}
			}

			from.getTextArea().setText(names.toString());
		}

		try {
			VisualGraphLayout<SampleVertex, SampleEdge> layout =
				layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
			graph.setLayout(layout);
		}
		catch (CancelledException e) {
			// can't happen as long as we are using the dummy monitor
		}
	}

	/*package*/ SampleGraph getGraph() {
		return graph;
	}

	/*package*/ VisualGraphViewUpdater<?, ?> getGraphViewUpdater() {
		GraphViewer<SampleVertex, SampleEdge> viewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<SampleVertex, SampleEdge> updater = viewer.getViewUpdater();
		return updater;
	}

	private SampleVertex locateService(Map<Class<?>, SampleVertex> pluginToVertices,
			Class<?> serviceClass) {

		Object service = tool.getService(serviceClass);
		if (service == null) {
			// must have a service that is not installed
			return null;
		}

		SampleVertex v = pluginToVertices.get(service.getClass());
		return v;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void showFilterPanel(boolean selected) {
		if (selected) {
			mainPanel.add(filterPanel, BorderLayout.SOUTH);
		}
		else {
			mainPanel.remove(filterPanel);
		}
		mainPanel.getParent().revalidate();
	}

	private void createActions() {

		ToggleDockingAction filterAction =
			new ToggleDockingAction(SHOW_FILTER_ACTION_NAME, plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					showFilterPanel(isSelected());
				}
			};

		filterAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, "A"));
		filterAction.setHelpLocation(SampleGraphPlugin.DEFAULT_HELP);
		addLocalAction(filterAction);

		addLayoutAction();
	}

	private void addLayoutAction() {

		MultiStateDockingAction<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> layoutAction =
			new MultiStateDockingAction<>(RELAYOUT_GRAPH_ACTION_NAME, plugin.getName()) {

				@Override
				protected void doActionPerformed(ActionContext context) {
					// this callback is when the user clicks the button
					LayoutProvider<SampleVertex, SampleEdge, SampleGraph> currentUserData =
						getCurrentUserData();
					changeLayout(currentUserData);
				}

				@Override
				public void actionStateChanged(
						ActionState<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> newActionState,
						EventTrigger trigger) {
					changeLayout(newActionState.getUserData());
				}
			};
		layoutAction.setGroup("B");
		layoutAction.setHelpLocation(SampleGraphPlugin.DEFAULT_HELP);

		addLayoutProviders(layoutAction);

		addLocalAction(layoutAction);
	}

	private void changeLayout(LayoutProvider<SampleVertex, SampleEdge, SampleGraph> provider) {

		this.layoutProvider = provider;
		if (isVisible()) { // this can be called while building--ignore that
			installGraph();
		}
	}

	private void addLayoutProviders(
			MultiStateDockingAction<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> layoutAction) {

		// Note: the first state set will be made the current selected value of the multi action
		LayoutProvider<SampleVertex, SampleEdge, SampleGraph> provider =
			new SampleGraphPluginDependencyLayoutProvider();
		layoutAction.addActionState(
			new ActionState<>(provider.getLayoutName(), provider.getActionIcon(), provider));

		//
		// Add some Jung layouts for users to try
		//
		Set<JungLayoutProvider<SampleVertex, SampleEdge, SampleGraph>> jungLayouts =
			JungLayoutProviderFactory.createLayouts();

		for (JungLayoutProvider<SampleVertex, SampleEdge, SampleGraph> l : jungLayouts) {
			layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FilterDocumentListener implements DocumentListener {

		@Override
		public void insertUpdate(DocumentEvent e) {
			filterUpdateManager.updateLater();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			filterUpdateManager.updateLater();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			filterUpdateManager.updateLater();
		}

	}

}
