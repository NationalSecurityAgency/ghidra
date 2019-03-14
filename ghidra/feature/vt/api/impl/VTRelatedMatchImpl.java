/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.util.VTRelatedMatch;
import ghidra.feature.vt.gui.provider.relatedMatches.VTRelatedMatchType;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class VTRelatedMatchImpl implements VTRelatedMatch {

    private final VTRelatedMatchType correlation;
    private final Address destinationAddress;
    private final Function destinationFunction;
    private final Address sourceAddress;
    private final Function sourceFunction;

    public VTRelatedMatchImpl(VTRelatedMatchType correlation,
            Address sourceAddress, Function sourceFunction,
            Address destinationAddress, Function destinationFunction) {
        super();
        if (correlation == null) {
            throw new IllegalArgumentException("correlation");
        }
        if (sourceAddress == null) {
            throw new IllegalArgumentException("sourceAddress");
        }
        if (sourceFunction == null) {
            throw new IllegalArgumentException("sourceFunction");
        }
        if (destinationAddress == null) {
            throw new IllegalArgumentException("destinationAddress");
        }
        if (destinationFunction == null) {
            throw new IllegalArgumentException("destinationFunction");
        }
        this.correlation = correlation;
        this.destinationAddress = destinationAddress;
        this.destinationFunction = destinationFunction;
        this.sourceAddress = sourceAddress;
        this.sourceFunction = sourceFunction;
    }

    public VTRelatedMatchType getCorrelation() {
        return correlation;
    }

    public Address getDestinationAddress() {
        return destinationAddress;
    }

    public Function getDestinationFunction() {
        return destinationFunction;
    }

    public Address getSourceAddress() {
        return sourceAddress;
    }

    public Function getSourceFunction() {
        return sourceFunction;
    }
}
