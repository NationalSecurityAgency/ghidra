/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.model;

import ghidra.framework.data.ContentHandler;

/** 
 * A class that describes a content types and the tool used to open it. 
 */
public class ToolAssociationInfo {

	private ToolTemplate currentTemplate;
	private final ContentHandler contentHandler;
	private String associatedToolName;
	private final ToolTemplate defaultTemplate;

	public ToolAssociationInfo(ContentHandler contentHandler, String associatedToolName,
			ToolTemplate currentToolTemplate, ToolTemplate defaultTemplate) {
		this.contentHandler = contentHandler;
		this.currentTemplate = currentToolTemplate;
		this.associatedToolName = associatedToolName;
		this.defaultTemplate = defaultTemplate;
	}

	public ContentHandler getContentHandler() {
		return contentHandler;
	}

	/**
	 * Returns the currently assigned tool used to open the content type of this association.
	 */
	public ToolTemplate getCurrentTemplate() {
		return currentTemplate;
	}

	public ToolTemplate getDefaultTemplate() {
		return defaultTemplate;
	}

	public String getAssociatedToolName() {
		return associatedToolName;
	}

	public boolean isDefault() {
		if (associatedToolName == null) {
			return true;
		}
		return associatedToolName.equals(contentHandler.getDefaultToolName());
	}

	/**
	 * Sets the tool name that should be used to open files for the content type represented 
	 * by this tool association.
	 */
	public void setCurrentTool(ToolTemplate toolTemplate) {
		this.currentTemplate = toolTemplate;
		this.associatedToolName = toolTemplate.getName();
	}

	public void restoreDefaultAssociation() {
		this.currentTemplate = defaultTemplate;
		this.associatedToolName = contentHandler.getDefaultToolName();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[\n\tContent Type: " +
			contentHandler.getContentType() + ",\n\tDefault Tool: " +
			contentHandler.getDefaultToolName() + ",\n\tCurrent Tool: " + currentTemplate + "\n]";
	}
}
