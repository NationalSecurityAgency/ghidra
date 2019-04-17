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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.DataLocationListContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.AssertException;

public abstract class AbstractTranslateAction extends DockingAction {
	protected static String META_GROUP = "Translate_Meta";
	protected static String GROUP = "Translate";
	private MenuData codeViewerMenuData;
	private MenuData dataListMenuData;

	public AbstractTranslateAction(String name, String owner, MenuData codeViewerMenuData,
			MenuData dataListMenuData) {
		super(name, owner);
		this.codeViewerMenuData = codeViewerMenuData;
		this.dataListMenuData = dataListMenuData;
		setPopupMenuData(codeViewerMenuData);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return context instanceof DataLocationListContext || isEnabledForContext(context);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof DataLocationListContext) {
			setPopupMenuData(dataListMenuData);
			return isEnabledForContext((DataLocationListContext) context);
		}
		else if (context instanceof CodeViewerActionContext) {
			setPopupMenuData(codeViewerMenuData);
			return isEnabledForContext((CodeViewerActionContext) context);
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof DataLocationListContext) {
			DataLocationListContext dataContext = (DataLocationListContext) context;
			actionPerformed(dataContext.getProgram(), getStringLocations(dataContext));
		}
		else if (context instanceof CodeViewerActionContext) {
			CodeViewerActionContext codeContext = (CodeViewerActionContext) context;
			actionPerformed(codeContext.getProgram(), getStringLocations(codeContext));
		}
		else {
			throw new AssertException("This can't happen!");
		}
	}

	private boolean isEnabledForContext(CodeViewerActionContext context) {
		if (context.hasSelection()) {
			return false;
		}
		List<ProgramLocation> dataLocations = getStringLocations(context);
		return !dataLocations.isEmpty();
	}

	private boolean isEnabledForContext(DataLocationListContext context) {
		return context.getCount() > 0;
	}

	protected List<ProgramLocation> getStringLocations(CodeViewerActionContext context) {
		Data data = DataUtilities.getDataAtLocation(context.getLocation());
		if (data == null || !StringDataInstance.isString(data)) {
			return Collections.emptyList();
		}
		return Arrays.asList(context.getLocation());
	}

	protected List<ProgramLocation> getStringLocations(DataLocationListContext context) {
		return context.getDataLocationList(StringDataInstance::isString);
	}

	protected abstract void actionPerformed(Program program, List<ProgramLocation> dataLocations);

}
