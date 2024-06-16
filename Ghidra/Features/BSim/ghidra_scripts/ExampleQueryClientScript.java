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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class ExampleQueryClientScript extends GhidraScript {

	private static final String URL = "URL";
	private static final String EXECUTABLE_NAME = "Executable Name";
	private static final String FUNCTION_NAME = "Function Name";

	@Override
	protected void run() throws Exception {
		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(URL);
		values.defineString(EXECUTABLE_NAME);
		values.defineString(FUNCTION_NAME);

		values.setValidator((valueMap, status) -> {
			String url = valueMap.getString(URL);
			if (StringUtils.isBlank(url)) {
				status.setStatusText(URL + " cannot be empty!", MessageType.ERROR);
				return false;
			}
			String exe = valueMap.getString(EXECUTABLE_NAME);
			if (StringUtils.isBlank(exe)) {
				status.setStatusText(EXECUTABLE_NAME + " cannot be empty!", MessageType.ERROR);
				return false;
			}
			String func = valueMap.getString(FUNCTION_NAME);
			if (StringUtils.isBlank(func)) {
				status.setStatusText(FUNCTION_NAME + " cannot be empty!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		askValues("BSim Query Info", "BSim Query Info", values);

		URL url = BSimClientFactory.deriveBSimURL(values.getString(URL));
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
			exequery.spec.exename = values.getString(EXECUTABLE_NAME);
			ResponseName respname = exequery.execute(client);
			if (respname == null) {
				Msg.error(this, client.getLastError());
				return;
			}

			ExecutableRecord erec = respname.manage.getExecutableRecordSet().first();
			FunctionDescription funcrec =
				respname.manage.findFunctionByName(values.getString(FUNCTION_NAME), erec);

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
			printf("%s", write.toString());
		}
	}

}
