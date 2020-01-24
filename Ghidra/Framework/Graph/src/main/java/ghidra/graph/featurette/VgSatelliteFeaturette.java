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
package ghidra.graph.featurette;

import java.awt.Dimension;
import java.awt.event.MouseEvent;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.*;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import ghidra.framework.options.SaveState;
import ghidra.graph.VisualGraph;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.*;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * A sub-feature that provides a satellite viewer to {@link VisualGraphComponentProvider}s
 * 
 * <p>Note: this class installs actions to manipulate the satellite view.  For these to be 
 * correctly enabled, you must produce {@link VgActionContext} objects in your
 * {@link VisualGraphComponentProvider#getActionContext(MouseEvent)} method.  Specifically, 
 * the context returned must be a type of {@link VgActionContext}, with the 
 * {@link VgActionContext#shouldShowSatelliteActions()} returning true.
 * 
 * @param <V> the vertex type 
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public class VgSatelliteFeaturette<V extends VisualVertex, 
								   E extends VisualEdge<V>, 
								   G extends VisualGraph<V, E>> 
	implements VisualGraphFeaturette<V, E, G> {
//@formatter:on

	private static final Icon ICON = ResourceManager.loadImage("images/network-wireless-16.png");

	private static final String DISPLAY_SATELLITE = "DISPLAY_SATELLITE";
	private static final String DOCK_SATELLITE = "DOCK_SATELLITE";

	private ToggleDockingAction toggleSatelliteAction;
	private ToggleDockingAction dockSatelliteAction;

	private Tool tool;
	private VisualGraphView<?, ?, ?> view;
	private String owner;
	private String providerName;
	private String windowGroup;

	// a flag for us to know when we were closed because the primary graph windows was closed
	private boolean closedByPrimaryProvider;

	private VgUndockedSatelliteProvider satelliteProvider;

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putBoolean(DOCK_SATELLITE, dockSatelliteAction.isSelected());
		saveState.putBoolean(DISPLAY_SATELLITE, toggleSatelliteAction.isSelected());
	}

	@Override
	public void readConfigState(SaveState saveState) {

		// Note: we want to restore this value before the satellite visibility, as setting the
		// docked state will affect that state, which is what we want when the user executes the
		// action, but not when restoring saved settings.
		boolean dockSatellite = saveState.getBoolean(DOCK_SATELLITE, true);
		dockSatelliteAction.setSelected(dockSatellite);
		view.setSatelliteDocked(dockSatellite);

		boolean showSatellite = saveState.getBoolean(DISPLAY_SATELLITE, true);
		toggleSatelliteAction.setSelected(showSatellite);
		view.setSatelliteVisible(showSatellite);
	}

	@Override
	public void init(VisualGraphComponentProvider<V, E, G> provider) {

		tool = provider.getTool();
		view = provider.getView();
		owner = provider.getOwner();
		providerName = provider.getName();
		windowGroup = provider.getWindowGroup();

		view.setSatelliteListener(new SatelliteListener());

		addActions(provider);
	}

	@Override
	public void providerOpened(VisualGraphComponentProvider<V, E, G> provider) {
		if (satelliteProvider != null) {
			// since the provider is not null, we know that it was previously open, closed 
			satelliteProvider.setVisible(true);
			view.setSatelliteVisible(true);
		}
	}

	@Override
	public void providerClosed(VisualGraphComponentProvider<V, E, G> provider) {
		if (satelliteProvider != null) {
			closedByPrimaryProvider = true;
			satelliteProvider.closeComponent();
			closedByPrimaryProvider = false; // reset
		}
	}

	public ComponentProvider getSatelliteProvider() {
		return satelliteProvider;
	}

	private void addActions(ComponentProvider provider) {

		toggleSatelliteAction = new ToggleDockingAction("Display Satellite View", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				view.setSatelliteVisible(isSelected());
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				ComponentProvider componentProvider = context.getComponentProvider();
				if (componentProvider != provider && componentProvider != satelliteProvider) {
					// appear in satellite and the main provider
					return false;
				}

				if (!(context instanceof VisualGraphActionContext)) {
					return false;
				}

				VisualGraphActionContext vgContext = (VisualGraphActionContext) context;
				return vgContext.shouldShowSatelliteActions();
			}
		};
		toggleSatelliteAction.setSelected(true);
		toggleSatelliteAction.setPopupMenuData(
			new MenuData(new String[] { "Display Satellite View" }));
		toggleSatelliteAction.setHelpLocation(
			new HelpLocation("FunctionCallGraphPlugin", "Satellite_View"));

		dockSatelliteAction = new ToggleDockingAction("Dock Satellite View", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				view.setSatelliteDocked(isSelected());
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				ComponentProvider componentProvider = context.getComponentProvider();
				if (componentProvider != provider && componentProvider != satelliteProvider) {
					// appear in satellite and the main provider
					return false;
				}

				if (!(context instanceof VisualGraphActionContext)) {
					return false;
				}

				VisualGraphActionContext vgContext = (VisualGraphActionContext) context;
				return vgContext.shouldShowSatelliteActions();
			}
		};
		dockSatelliteAction.setSelected(true);
		dockSatelliteAction.setPopupMenuData(new MenuData(new String[] { "Dock Satellite View" }));
		dockSatelliteAction.setHelpLocation(
			new HelpLocation("FunctionCallGraphPlugin", "Satellite_View"));

		// Note: this is not a local action, since it should appear in satellite and the main view
		tool.addAction(toggleSatelliteAction);
		tool.addAction(dockSatelliteAction);
	}

	@Override
	public void remove() {
		if (satelliteProvider != null) {
			satelliteProvider.removeFromTool();
		}
	}

	// only remove the provider if the user had docked the satellite
	private void closeSatelliteProvider(boolean remove) {
		if (satelliteProvider == null) {
			return;
		}

		if (remove) {
			satelliteProvider.removeFromTool();
			satelliteProvider = null;
		}
		else {
			satelliteProvider.closeComponent();
		}
	}

	private void showSatelliteProvider() {
		if (satelliteProvider == null) {

			JComponent component = view.getUndockedSatelliteComponent();
			satelliteProvider = new VgUndockedSatelliteProvider(tool, component,
				providerName + " Satellite", owner, windowGroup);
			satelliteProvider.setVisible(true);
		}
		else {
			satelliteProvider.toFront();
		}
	}

	private class VgUndockedSatelliteProvider extends ComponentProvider {

		private JComponent satelliteComponent;

		public VgUndockedSatelliteProvider(Tool tool, JComponent component, String name,
				String owner, String windowGroup) {
			super(tool, name, owner);

			this.satelliteComponent = component;

			satelliteComponent.setMinimumSize(new Dimension(400, 400));

			// TODO - need generic, shared help for the common abstract graph features;
			//        will be done in an upcoming ticket
			// setHelpLocation(new HelpLocation("Graph", "Satellite_View_Dock"));

			// this will group the satellite with the provider
			setWindowMenuGroup(windowGroup);
			setIcon(ICON);
			setDefaultWindowPosition(WindowPosition.WINDOW);

			addToTool();
		}

		@Override
		public JComponent getComponent() {
			return satelliteComponent;
		}

		@Override
		public ActionContext getActionContext(MouseEvent event) {
			return new VgSatelliteContext(this);
		}

		@Override
		public void componentHidden() {

			if (!dockSatelliteAction.isSelected()) {
				// this implies the user has closed the provider, but it is still undocked; 
				// sync the state of the view with this provider
				view.setSatelliteVisible(false);
			}

			if (!closedByPrimaryProvider) {
				// This is the case where the user closed this satellite provider directly.  In
				// this case, we do not want to show this provider if the main provider is later
				// re-opened.		
				satelliteProvider.removeFromTool();
				satelliteProvider = null;
			}
		}
	}

	private class SatelliteListener implements GraphSatelliteListener {

		@Override
		public void satelliteVisibilityChanged(boolean docked, boolean visible) {

			toggleSatelliteAction.setSelected(visible);
			dockSatelliteAction.setSelected(docked);

			if (docked) {
				closeSatelliteProvider(true);
				return;
			}

			if (!visible) { //  undocked and not visible
				closeSatelliteProvider(false);
			}
			else {  		// undocked and visible
				showSatelliteProvider();
			}
		}
	}
}
