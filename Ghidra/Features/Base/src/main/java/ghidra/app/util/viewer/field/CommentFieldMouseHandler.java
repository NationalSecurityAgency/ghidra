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
package ghidra.app.util.viewer.field;

import java.awt.event.MouseEvent;

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.services.QueryData;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;

/**
 * A handler to process {@link CommentFieldLocation} clicks.
 */
public class CommentFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES =
		new Class[] { CommentFieldLocation.class, EolCommentFieldLocation.class,
			PlateFieldLocation.class, AutomaticCommentFieldLocation.class,
			MemoryBlockStartFieldLocation.class };

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}
		String[] comments = getComment(location);
		int commentRow = getCommentRow(location);
		int column = getCommentColumn(location);

		if (comments.length == 0) {
			return false; // some comment location may have no comments, like plate comments
		}

		if (commentRow < 0) {
			return false; // Plate field locations can return negative values when clicking above 
							// the border
		}

		String clickedWord =
			StringUtilities.findWord(StringUtilities.convertTabsToSpaces(comments[commentRow]),
				column, GoToService.VALID_GOTO_CHARS);

		return checkWord(clickedWord, serviceProvider, sourceNavigatable);
	}

	protected int getCommentRow(ProgramLocation programLocation) {
		if (programLocation instanceof PlateFieldLocation) {
			return ((PlateFieldLocation) programLocation).getCommentRow();
		}
		return ((CommentFieldLocation) programLocation).getRow();
	}

	protected int getCommentColumn(ProgramLocation programLocation) {
		return ((CommentFieldLocation) programLocation).getCharOffset();
	}

	protected String[] getComment(ProgramLocation programLocation) {
		return ((CommentFieldLocation) programLocation).getComment();
	}

	protected boolean checkWord(String wordString, ServiceProvider serviceProvider,
			Navigatable sourceNavigatable) {

		if (wordString == null) {
			return false;
		}
		ProgramLocation location = sourceNavigatable.getLocation();
		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}
		QueryData queryData = new QueryData(wordString, false);
		return goToService.goToQuery(sourceNavigatable, location.getAddress(), queryData, null,
			null);

	}
}
