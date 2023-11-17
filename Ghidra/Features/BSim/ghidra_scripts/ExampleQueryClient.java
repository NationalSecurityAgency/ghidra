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
// Example of connecting to a BSim server and requesting executable and function records
//@category BSim

import java.io.StringWriter;
import java.net.URL;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.Msg;

public class ExampleQueryClient extends GhidraScript {

	@Override
	protected void run() throws Exception {
		URL url = BSimClientFactory.deriveBSimURL("ghidra://localhost/repo");
		try (FunctionDatabase client = BSimClientFactory.buildClient(url, false)) {
			if (!client.initialize()) {
				Msg.error(this, "Unable to connect to server");
				return;
			}

			QueryInfo query = new QueryInfo();
			ResponseInfo resp = query.execute(client);
			StringWriter write = new StringWriter();
			resp.saveXml(write);
			write.flush();

			QueryName exequery = new QueryName();
			exequery.spec.exename = "libdocdoxygenplugin.so";
			ResponseName respname = exequery.execute(client);
			if (respname == null) {
				Msg.error(this, client.getLastError());
				return;
			}
			ExecutableRecord erec = respname.manage.getExecutableRecordSet().first();
			FunctionDescription funcrec =
				respname.manage.findFunctionByName("DocDoxygenPlugin::createCatalog", erec);

			QueryChildren childquery = new QueryChildren();
			childquery.md5sum = funcrec.getExecutableRecord().getMd5();
			childquery.functionKeys.add(new FunctionEntry(funcrec));

			ResponseChildren respchild = childquery.execute(client);
			if (respchild == null) {
				Msg.error(this, client.getLastError());
				return;
			}
			for (int i = 0; i < respchild.correspond.size(); ++i) {
				FunctionDescription func = respchild.correspond.get(i);
				List<CallgraphEntry> callgraphRecord = func.getCallgraphRecord();
				if (callgraphRecord != null) {
					for (int j = 0; j < callgraphRecord.size(); ++j) {
						write.write(
							callgraphRecord.get(j).getFunctionDescription().getFunctionName());
						write.write('\n');
					}
				}
			}
			write.flush();
			Msg.info(this, write.toString());
		}
	}

}
