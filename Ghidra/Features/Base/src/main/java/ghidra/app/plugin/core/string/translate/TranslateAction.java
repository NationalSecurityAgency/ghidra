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

import java.util.List;

import docking.action.MenuData;
import ghidra.app.services.StringTranslationService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Action for invoking string translation services.  One of the actions will be created for
 * each discovered {@link StringTranslationService} by the {@link TranslateStringsPlugin}
 */
public class TranslateAction extends AbstractTranslateAction {
	private StringTranslationService service;

	public TranslateAction(String owner, StringTranslationService service) {
		super("Translate with " + service.getTranslationServiceName(), owner,
			getCodeViewerMenuData(service), getDataListMenuData(service));
		this.service = service;
		HelpLocation helpLoc = service.getHelpLocation();
		if (helpLoc != null) {
			setHelpLocation(helpLoc);
		}
	}

	private static MenuData getCodeViewerMenuData(StringTranslationService service) {
		return new MenuData(
			new String[] { "Data", "Translate", service.getTranslationServiceName() }, GROUP);
	}

	private static MenuData getDataListMenuData(StringTranslationService service) {
		return new MenuData(new String[] { "Translate", service.getTranslationServiceName() },
			GROUP);
	}

	@Override
	public void actionPerformed(Program program, List<ProgramLocation> dataLocations) {
		service.translate(program, dataLocations);
	}
}
