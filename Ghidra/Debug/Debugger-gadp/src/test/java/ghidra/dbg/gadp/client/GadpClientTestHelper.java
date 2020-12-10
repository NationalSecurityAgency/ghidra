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
package ghidra.dbg.gadp.client;

import java.util.concurrent.CompletableFuture;

import com.google.protobuf.Message;

/**
 * A means for tests to access package members of {@link GadpClient}
 */
public enum GadpClientTestHelper {
	;
	public static <MI extends Message> CompletableFuture<?> sendChecked(GadpClient client,
			Message.Builder req, MI exampleRep) {
		return client.sendChecked(req, exampleRep);
	}
}
