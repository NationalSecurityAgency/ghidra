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
package ghidra.app.plugin.core.debug.gui.modules;

import java.math.BigInteger;
import java.net.URL;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceStaticMapping;

public class StaticMappingRow {
	private static final BigInteger BIT64 = BigInteger.ONE.shiftLeft(64);
	private final TraceStaticMapping mapping;

	public StaticMappingRow(TraceStaticMapping mapping) {
		this.mapping = mapping;
	}

	public TraceStaticMapping getMapping() {
		return mapping;
	}

	public Trace getTrace() {
		return mapping.getTrace();
	}

	public Address getTraceAddress() {
		return mapping.getMinTraceAddress();
	}

	public URL getStaticProgramURL() {
		return mapping.getStaticProgramURL();
	}

	public String getStaticAddress() {
		return mapping.getStaticAddress();
	}

	public long getLength() {
		return mapping.getLength();
	}

	public BigInteger getBigLength() {
		long length = mapping.getLength();
		if (length == 0) {
			return BIT64;
		}
		else if (length < 0) {
			return BigInteger.valueOf(length).add(BIT64);
		}
		else {
			return BigInteger.valueOf(length);
		}
	}

	public long getShift() {
		return mapping.getShift();
	}

	public Range<Long> getLifespan() {
		return mapping.getLifespan();
	}
}
