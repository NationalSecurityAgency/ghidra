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
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOpinion;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
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

	protected interface ChooseMorePlatformsAction {
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

	protected class PlatformActionSet {
		private final Trace trace;
		private final Map<DebuggerPlatformOffer, ToggleDockingAction> actions =
			new LinkedHashMap<>();

		public PlatformActionSet(Trace trace) {
			this.trace = trace;
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
					.onAction(ctx -> activatePlatformOffer(offer))
					.build();
			String[] path = action.getMenuBarData().getMenuPath();
			tool.setMenuGroup(Arrays.copyOf(path, path.length - 1), ChoosePlatformAction.GROUP);
			return action;
		}

		protected void activatePlatformOffer(DebuggerPlatformOffer offer) {
			platformService.setCurrentMapperFor(trace, current.getObject(), offer.take(tool, trace),
				current.getSnap());
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
			if (current.getTrace() == trace) {
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

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

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
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		PlatformActionSet actions =
			actionsChoosePlatform.computeIfAbsent(trace, PlatformActionSet::new);
		actions.updatePlatformOffers();
		actions.mapperActivated(platformService.getCurrentMapperFor(trace));
		actions.installActions();
	}

	protected void uninstallActions() {
		PlatformActionSet actions = actionsChoosePlatform.get(current.getTrace());
		if (actions != null) {
			actions.uninstallActions();
		}
	}

	protected void createActions() {
		installActions();
		actionMore = ChooseMorePlatformsAction.builder(this)
				.enabledWhen(ctx -> current.getTrace() != null)
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
		Trace trace = current.getTrace();
		PlatformActionSet actions = actionsChoosePlatform.get(trace);
		if (actions == null) {
			return;
		}
		TraceObject object = current.getObject();
		long snap = current.getSnap();

		DebuggerPlatformOffer offer = chooseOffer(trace, object, snap);
		// Dialog allows Swing to do other things, so re-check platformService
		if (offer != null && platformService != null) {
			actions.addChosenOffer(offer);
			platformService.setCurrentMapperFor(trace, object, offer.take(tool, trace), snap);
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
		if (Objects.equals(current, coordinates)) {
			return;
		}
		uninstallActions();
		this.current = coordinates;
		installActions();
		tool.contextChanged(null);
	}

	protected void traceClosed(Trace trace) {
		if (trace == current.getTrace()) {
			coordinatesActivated(DebuggerCoordinates.NOWHERE);
		}
		actionsChoosePlatform.remove(trace);
	}

	protected void mapperActivated(Trace trace, DebuggerPlatformMapper mapper) {
		if (trace != current.getTrace()) {
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
		if (event instanceof TraceActivatedPluginEvent ev) {
			coordinatesActivated(ev.getActiveCoordinates());
		}
		if (event instanceof TraceClosedPluginEvent ev) {
			traceClosed(ev.getTrace());
		}
		if (event instanceof DebuggerPlatformPluginEvent ev) {
			mapperActivated(ev.getTrace(), ev.getMapper());
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
