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
package ghidra.app.plugin.core.string.translate;

import java.util.*;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.StringTranslationService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Data;

/**
 * Plugin that provides string translation services on {@link Data} items that are
 * strings or arrays of chars.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "String translation",
	description = "Allows the user to use string translation services.",
	servicesProvided = { StringTranslationService.class }
)
//@formatter:on

public class TranslateStringsPlugin extends Plugin {
	private List<DockingAction> translationActions = new ArrayList<>();
	private List<StringTranslationService> translationServices = new ArrayList<>();

	public TranslateStringsPlugin(PluginTool tool) {
		super(tool);
		setupServices();
	}

	@Override
	protected void init() {
		createTranslateActions();
		createTranslateMetaActions();
	}

	private void setupServices() {
		registerServiceProvided(StringTranslationService.class,
			new ManualStringTranslationService());
	}

	private void createTranslateMetaActions() {
		tool.addAction(new ClearTranslationAction(getName()));
		tool.addAction(new ToggleShowTranslationAction(getName()));
	}

	private void createTranslateActionsIfNeeded() {
		List<StringTranslationService> newServices =
			new ArrayList<>(Arrays.asList(tool.getServices(StringTranslationService.class)));
		boolean isSame = newServices.containsAll(translationServices) &&
			translationServices.containsAll(newServices);

		if (!isSame) {
			createTranslateActions();
		}
	}

	private void createTranslateActions() {
		for (DockingAction prevAction : translationActions) {
			tool.removeAction(prevAction);
		}
		translationActions.clear();
		translationServices.clear();

		translationServices.addAll(Arrays.asList(tool.getServices(StringTranslationService.class)));
		Collections.sort(translationServices,
			(s1, s2) -> s1.getTranslationServiceName().compareTo(s2.getTranslationServiceName()));

		for (StringTranslationService service : translationServices) {
			DockingAction action = new TranslateAction(getName(), service);
			translationActions.add(action);
			tool.addAction(action);
		}
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		createTranslateActionsIfNeeded();
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		createTranslateActionsIfNeeded();
	}

}
