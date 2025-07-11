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
package ghidra.trace.database;

import javax.swing.Icon;

import ghidra.framework.data.LinkHandler;

public class DBTraceLinkContentHandler extends LinkHandler<DBTrace> {

	public static DBTraceLinkContentHandler INSTANCE = new DBTraceLinkContentHandler();

	public static final String TRACE_LINK_CONTENT_TYPE = "TraceLink";

	@Override
	public String getContentType() {
		return TRACE_LINK_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return TRACE_LINK_CONTENT_TYPE;
	}

	@Override
	public Class<DBTrace> getDomainObjectClass() {
		// return linked content class
		return DBTraceContentHandler.TRACE_DOMAIN_OBJECT_CLASS;
	}

	@Override
	public Icon getIcon() {
		return DBTraceContentHandler.TRACE_ICON;
	}

	@Override
	public String getDefaultToolName() {
		return DBTraceContentHandler.TRACE_CONTENT_DEFAULT_TOOL;
	}

}
