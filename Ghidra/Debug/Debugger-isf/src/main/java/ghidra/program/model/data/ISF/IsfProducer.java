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
package ghidra.program.model.data.ISF;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

import ghidra.program.model.listing.Program;

public class IsfProducer implements IsfObject {

	public String datetime;
	public String name;
	public String version;

	public IsfProducer(Program program) {
		Map<String, String> metaData = program.getMetadata();
		Date creationDate = program.getCreationDate();
		SimpleDateFormat dataFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSSSS");

		datetime = dataFormat.format(creationDate);
		name = "Ghidra";
		version = metaData.get(Program.CREATED_WITH_GHIDRA_VERSION);
	}

}
