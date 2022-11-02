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
package ghidra.app.plugin.core.debug.gui.platform;

import java.util.*;
import java.util.Map.Entry;

import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;

@PluginInfo(
	shortDescription = "Debugger platform selection GUI",
	description = "GUI to add, edit, and remove trace platforms",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
		DebuggerPlatformPluginEvent.class,
	},
	servicesRequired = {
		DebuggerPlatformService.class,
	})
public class DebuggerPlatformPlugin extends Plugin {

	protected interface ChoosePlatformAction {
		String NAME = DebuggerResources.NAME_CHOOSE_PLATFORM;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_CHOOSE_PLATFORM;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "choose_platform";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected interface ChooseMorePlatformsActon {
		String NAME = DebuggerResources.NAME_CHOOSE_MORE_PLATFORMS;
		String TITLE = DebuggerResources.TITLE_CHOOSE_MORE_PLATFORMS;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_CHOOSE_MORE_PLATFORMS;
		String GROUP = "zzzz";
		String HELP_ANCHOR = "choose_more_platforms";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, ChoosePlatformAction.NAME, TITLE)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getObject(), b.getObject())) {
			return false;
		}
		return true;
	}

	protected class PlatformActionSet {
		private final Trace trace;
		private DebuggerCoordinates current;
		private final Map<DebuggerPlatformOffer, ToggleDockingAction> actions =
			new LinkedHashMap<>();

		public PlatformActionSet(Trace trace) {
			this.trace = trace;
			this.current = traceManager.getCurrentFor(trace);
		}

		protected Set<DebuggerPlatformOffer> computePlatformOffers(boolean includeOverrides) {
			return new LinkedHashSet<>(
				DebuggerPlatformOpinion.queryOpinions(trace, current.getObject(), 0,
					includeOverrides));
		}

		protected ToggleDockingAction createActionChoosePlatform(DebuggerPlatformOffer offer) {
			ToggleDockingAction action = ChoosePlatformAction.builder(DebuggerPlatformPlugin.this)
					.menuPath(DebuggerPluginPackage.NAME, ChoosePlatformAction.NAME,
						offer.getDescription())
					.onAction(ctx -> activatePlatform(offer))
					.build();
			String[] path = action.getMenuBarData().getMenuPath();
			tool.setMenuGroup(Arrays.copyOf(path, path.length - 1), ChoosePlatformAction.GROUP);
			return action;
		}

		protected void activatePlatform(DebuggerPlatformOffer offer) {
			platformService.setCurrentMapperFor(trace, offer.take(tool, trace), current.getSnap());
		}

		protected void cleanOffers() {
			actions.keySet().retainAll(computePlatformOffers(true));
		}

		protected void addPreferredOffers() {
			for (DebuggerPlatformOffer offer : computePlatformOffers(false)) {
				addOfferAction(offer);
			}
		}

		protected void updatePlatformOffers() {
			cleanOffers();
			addPreferredOffers();
		}

		protected ToggleDockingAction addOfferAction(DebuggerPlatformOffer offer) {
			return actions.computeIfAbsent(offer, this::createActionChoosePlatform);
		}

		protected void addChosenOffer(DebuggerPlatformOffer offer) {
			ToggleDockingAction action = addOfferAction(offer);
			// NB. PluginEvent will cause selections to update
			if (currentTrace == trace) {
				tool.addAction(action);
			}
		}

		protected void installActions() {
			for (ToggleDockingAction action : actions.values()) {
				tool.addAction(action);
			}
		}

		protected void uninstallActions() {
			for (ToggleDockingAction action : actions.values()) {
				tool.removeAction(action);
			}
		}

		protected void coordinatesActivated(DebuggerCoordinates coordinates) {
			if (sameCoordinates(current, coordinates)) {
				current = coordinates;
				return;
			}
			current = coordinates;
			updatePlatformOffers();
		}

		protected void mapperActivated(DebuggerPlatformMapper mapper) {
			for (Entry<DebuggerPlatformOffer, ToggleDockingAction> ent : actions.entrySet()) {
				DebuggerPlatformOffer offer = ent.getKey();
				ToggleDockingAction action = ent.getValue();
				action.setSelected(mapper != null && offer.isCreatorOf(mapper));
			}
		}
	}

	@AutoServiceConsumed
	DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	DebuggerPlatformService platformService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	private Trace currentTrace;

	private final ChangeListener classChangeListener = evt -> this.classesChanged();

	protected final DebuggerSelectPlatformOfferDialog offerDialog;

	final Map<Trace, PlatformActionSet> actionsChoosePlatform = new WeakHashMap<>();
	DockingAction actionMore;

	public DebuggerPlatformPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		offerDialog = new DebuggerSelectPlatformOfferDialog(tool);

		ClassSearcher.addChangeListener(classChangeListener);

		createActions();
	}

	protected void installActions() {
		if (currentTrace == null) {
			return;
		}
		PlatformActionSet actions =
			actionsChoosePlatform.computeIfAbsent(currentTrace, PlatformActionSet::new);
		actions.updatePlatformOffers();
		actions.mapperActivated(platformService.getCurrentMapperFor(currentTrace));
		actions.installActions();
	}

	protected void uninstallActions() {
		PlatformActionSet actions = actionsChoosePlatform.get(currentTrace);
		if (actions != null) {
			actions.uninstallActions();
		}
	}

	protected void createActions() {
		installActions();
		actionMore = ChooseMorePlatformsActon.builder(this)
				.enabledWhen(ctx -> currentTrace != null)
				.onAction(this::activatedChooseMore)
				.buildAndInstall(tool);
		String[] path = actionMore.getMenuBarData().getMenuPath();
		tool.setMenuGroup(Arrays.copyOf(path, path.length - 1), ChoosePlatformAction.GROUP);
		tool.contextChanged(null);
	}

	private void activatedChooseMore(ActionContext ctx) {
		if (platformService == null) {
			// Still initializing or finalizing
			return;
		}
		// Sort of a backwards way to retrieve the current coordinates....
		PlatformActionSet actions = actionsChoosePlatform.get(currentTrace);
		if (actions == null) {
			return;
		}
		DebuggerCoordinates current = actions.current;
		Trace trace = current.getTrace();
		TraceObject object = current.getObject();
		long snap = current.getSnap();

		DebuggerPlatformOffer offer = chooseOffer(trace, object, snap);
		// Dialog allows Swing to do other things, so re-check platformService
		if (offer != null && platformService != null) {
			actions.addChosenOffer(offer);
			platformService.setCurrentMapperFor(trace, offer.take(tool, trace), snap);
			// NOTE: DebuggerPlatformPluginEvent will cause selection change
		}
	}

	private void classesChanged() {
		uninstallActions();
		for (PlatformActionSet actions : actionsChoosePlatform.values()) {
			actions.updatePlatformOffers();
		}
		installActions();
	}

	protected void coordinatesActivated(DebuggerCoordinates coordinates) {
		uninstallActions();
		this.currentTrace = coordinates.getTrace();
		installActions();
		tool.contextChanged(null);
	}

	protected void traceClosed(Trace trace) {
		if (trace == currentTrace) {
			coordinatesActivated(DebuggerCoordinates.NOWHERE);
		}
		actionsChoosePlatform.remove(trace);
	}

	protected void mapperActivated(Trace trace, DebuggerPlatformMapper mapper) {
		if (trace != currentTrace) {
			return;
		}
		PlatformActionSet actions = actionsChoosePlatform.get(trace);
		if (actions != null) {
			actions.mapperActivated(mapper);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent evt) {
			coordinatesActivated(evt.getActiveCoordinates());
		}
		if (event instanceof TraceClosedPluginEvent evt) {
			traceClosed(evt.getTrace());
		}
		if (event instanceof DebuggerPlatformPluginEvent evt) {
			mapperActivated(evt.getTrace(), evt.getMapper());
		}
	}

	/**
	 * Display a dialog for the user to manually select an offer for the given object
	 * 
	 * @param object the object for which an offer is desired
	 * @param snap the snap, usually the current snap
	 * @return the offer, or null if the dialog was cancelled
	 */
	protected DebuggerPlatformOffer chooseOffer(Trace trace, TraceObject object, long snap) {
		List<DebuggerPlatformOffer> offers =
			DebuggerPlatformOpinion.queryOpinions(trace, object, snap, true);
		offerDialog.setOffers(offers);
		tool.showDialog(offerDialog);
		if (offerDialog.isCancelled()) {
			return null;
		}
		return offerDialog.getSelectedOffer();
	}
}
