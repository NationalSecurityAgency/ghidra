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
package ghidra.app.plugin.core.decompiler.taint;

import java.util.Map;
import java.util.Set;

import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Swing;

/**
 * The TaintService provides a general service for retrieving or setting taint from an external engine
 * <p>
 * {@link Swing#runLater(Runnable)} call, which will prevent any deadlock issues.
 */
@ServiceInfo(defaultProvider = TaintPlugin.class, description = "supply taint")
public interface TaintService {

	/**
	 * Get tainted address set
	 * @return addresses
	 */
	public AddressSet getAddressSet();

	/**
	 * Set taint using address set
	 * 
	 * @param set tainted addresses
	 * @param clear before setting
	 */
	public void setAddressSet(AddressSet set, boolean clear);

	/**
	 * Get tainted varnode map
	 * @return address-to-result map
	 */
	public Map<Address, Set<TaintQueryResult>> getVarnodeMap();

	/**
	 * Set taint using varnode map
	 * 
	 * @param vmap tainted addresses
	 * @param clear before setting
	 */
	public void setVarnodeMap(Map<Address, Set<TaintQueryResult>> vmap, boolean clear);

	/**
	 * Clear existing taint
	 */
	public void clearTaint();

}
