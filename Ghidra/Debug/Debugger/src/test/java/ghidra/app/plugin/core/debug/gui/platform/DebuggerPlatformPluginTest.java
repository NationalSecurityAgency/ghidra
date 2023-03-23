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

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import docking.action.ToggleDockingActionIf;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.program.model.lang.LanguageID;
import ghidra.trace.database.ToyDBTraceBuilder;

public class DebuggerPlatformPluginTest extends AbstractGhidraHeadedDebuggerGUITest {
	DebuggerPlatformPlugin platformPlugin;
	DebuggerPlatformService platformService;

	protected List<ToggleDockingActionIf> getPlatformActions() {
		return tool.getAllActions()
				.stream()
				.filter(a -> a.getOwner().equals(platformPlugin.getName()))
				.filter(a -> a instanceof ToggleDockingActionIf)
				.filter(a -> a != platformPlugin.actionMore)
				.map(a -> (ToggleDockingActionIf) a)
				.collect(Collectors.toList());
	}

	@Before
	public void setUpPlatformTest() throws Throwable {
		platformPlugin = addPlugin(tool, DebuggerPlatformPlugin.class);
		platformService = tool.getService(DebuggerPlatformService.class);
	}

	protected void chooseLanguageIDViaMore(LanguageID langID) {
		performAction(platformPlugin.actionMore, false);
		DebuggerSelectPlatformOfferDialog dialog =
			waitForDialogComponent(DebuggerSelectPlatformOfferDialog.class);
		dialog.setFilterRecommended(false);
		waitForSwing();

		List<DebuggerPlatformOffer> offers = runSwing(() -> dialog.getDisplayedOffers());
		DebuggerPlatformOffer toyOffer = offers.stream()
				.filter(o -> Objects.equals(langID, o.getLanguageID()))
				.findFirst()
				.orElseThrow();
		runSwing(() -> dialog.setSelectedOffer(toyOffer));
		runSwing(() -> dialog.okCallback());
		waitForSwing();
	}

	@Test
	public void testActionMore() throws Throwable {
		createAndOpenTrace("DATA:BE:64:default");
		traceManager.activateTrace(tb.trace);
		
		chooseLanguageIDViaMore(new LanguageID("Toy:BE:64:default"));
		DebuggerPlatformMapper mapper = platformService.getCurrentMapperFor(tb.trace);
		assertEquals(new LanguageID("Toy:BE:64:default"), mapper.getLangauge(null).getLanguageID());
	}

	@Test
	public void testRemembersChosenOffer() throws Throwable {
		createAndOpenTrace("DATA:BE:64:default");
		try (ToyDBTraceBuilder tb2 =
			new ToyDBTraceBuilder("second-" + name.getMethodName(), "DATA:BE:64:default")) {
			traceManager.openTrace(tb2.trace);
			traceManager.activateTrace(tb2.trace);

			chooseLanguageIDViaMore(new LanguageID("Toy:BE:64:default"));
			assertEquals(2, getPlatformActions().size());

			traceManager.activateTrace(tb.trace);
			waitForSwing();
			assertEquals(1, getPlatformActions().size());

			traceManager.activateTrace(tb2.trace);
			waitForSwing();
			assertEquals(2, getPlatformActions().size());
		}
	}
}
