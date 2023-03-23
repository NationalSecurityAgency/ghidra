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

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObjectManagerTest;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerPlatformPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerPlatformPlugin platformPlugin;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		platformPlugin = addPlugin(tool, DebuggerPlatformPlugin.class);
	}

	@Test
	public void testCaptureDebuggerSelectPlatformOfferDialog() throws Throwable {
		SchemaContext ctx = XmlSchemaContext.deserialize(DBTraceObjectManagerTest.XML_CTX);
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("echo", "DATA:BE:64:default")) {
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getObjectManager()
						.createRootObject(ctx.getSchema(new SchemaName("Session")));
			}
			traceManager.openTrace(tb.trace);
			traceManager.activateTrace(tb.trace);
			waitForSwing();

			performAction(platformPlugin.actionMore, false);
			DebuggerSelectPlatformOfferDialog dialog =
				waitForDialogComponent(DebuggerSelectPlatformOfferDialog.class);
			dialog.setFilterRecommended(false);
			waitForSwing();

			captureDialog(dialog);
		}
	}
}
