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
package help.screenshot;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.program.model.address.AddressSet;

public class ByteViewerPluginScreenShots extends GhidraScreenShotGenerator {

	public ByteViewerPluginScreenShots() {
		super();
	}

	@Test
	public void testByteViewer() {
		closeProvider(DataTypesProvider.class);
		closeProvider(CodeViewerProvider.class);
		setToolSize(500, 400);

		ComponentProvider provider = getProvider("Bytes");
		showProvider(provider.getClass());

		goToListing(0x400000);
		captureIsolatedProvider(provider.getClass(), 500, 400);
	}

	@Test
	public void testByteViewerOptionsDialog() {
		performAction("Byte Viewer Options", "ByteViewerPlugin", false);
		captureDialog();
	}

	@Test
	public void testByteViewerExample() {
		AddressSet set = new AddressSet(addr(0x40b000));
		ClearCmd cmd = new ClearCmd(set);
		tool.execute(cmd, program);

		closeProvider(DataTypesProvider.class);
		closeProvider(CodeViewerProvider.class);
		setToolSize(500, 400);

		ComponentProvider provider = getProvider("Bytes");
		showProvider(provider.getClass());


		goToListing(0x41cc08);
		goToListing(0x40b003);
		captureIsolatedProvider(provider.getClass(), 500, 400);
	}

	@Test
	public void testByteViewerResults() {
		AddressSet set = new AddressSet(addr(0x40b000));
		ClearCmd cmd = new ClearCmd(set);
		tool.execute(cmd, program);

		closeProvider(DataTypesProvider.class);
		closeProvider(CodeViewerProvider.class);
		setToolSize(500, 400);

		ByteViewerComponentProvider provider = getProvider(ByteViewerComponentProvider.class);
		showProvider(provider.getClass());

		goToListing(0x41cc08);
		goToListing(0x40b003);

		runSwing(() -> provider.setOffset(13));

		goToListing(0x41cc08);
		goToListing(0x40b000);
		goToListing(0x40b003);

		captureIsolatedProvider(provider.getClass(), 500, 400);
	}

}
