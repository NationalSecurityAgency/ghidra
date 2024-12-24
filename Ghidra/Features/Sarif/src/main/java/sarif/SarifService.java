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
package sarif;

import java.io.File;
import java.io.IOException;

import com.contrastsecurity.sarif.SarifSchema210;
import com.google.gson.JsonSyntaxException;

import ghidra.framework.plugintool.ServiceInfo;
import ghidra.util.Swing;

/**
 * The SarifService provides a general service for plugins to load and display sarif files
 * <p>
 * {@link Swing#runLater(Runnable)} call, which will prevent any deadlock issues.
 */
@ServiceInfo(defaultProvider = SarifPlugin.class, description = "load SARIF")
public interface SarifService {

	/**
	 * Attempts to read a SARIF file
	 *
	 * @param sarif file
	 * @throws IOException 
	 * @throws JsonSyntaxException 
	 * @see #readSarif(sarifFile)
	 */
	public SarifSchema210 readSarif(File sarifFile) throws JsonSyntaxException, IOException;

	/**
	 * Attempts to read a SARIF blob
	 *
	 * @param sarif string
	 * @throws IOException 
	 * @throws JsonSyntaxException 
	 * @see #readSarif(sarif)
	 */
	public SarifSchema210 readSarif(String sarif) throws JsonSyntaxException, IOException;

	/**
	 * Attempts to load a SARIF file
	 *
	 * @param logName tracks errors
	 * @param sarif base object
	 * @see #showSarif(logName, sarif)
	 */
	public void showSarif(String logName, SarifSchema210 sarif);

	/**
	 * Retrieve the current controller
	 */
	public SarifController getController();

}
