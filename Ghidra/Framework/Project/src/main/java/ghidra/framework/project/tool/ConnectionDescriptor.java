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
package ghidra.framework.project.tool;

import java.io.Serializable;

/**
 * Class to describe the connection between two tools for a specific event.
 * This class is used by the ToolSetImpl when it serializes itself.
 */
class ConnectionDescriptor implements Serializable {

    private String producerName;
    private String consumerName;
    private String event;

    /**
     * Constructor
     * @param producerName name of the tool the produces the event
     * @param consumerName name of the tool that consumes the event
     * @param event name of the event that represents the connection
     * between the tools
     */
    ConnectionDescriptor(String producerName, String consumerName, 
                         String event) {
        this.producerName = producerName;
        this.consumerName = consumerName;
        this.event = event;
    }

    /**
     * Get the producer name.
     */
    String getProducerName() {
        return producerName;
    }

    /**
     * Get the consumer name.
     */
    String getConsumerName() {
        return consumerName;
    }

    /**
     * Get the event that connects the tools.
     */
    String getEvent() {
        return event;
    }


    /**
     * Returns a hash code value for the object. This method is
     * supported for the benefit of hashtables such as those provided by
     * <code>java.util.Hashtable</code>.
     */
    @Override
    public int hashCode() {
        return producerName.hashCode() + consumerName.hashCode() +
            event.hashCode();
    }
    /**
     * Indicates whether some other object is "equal to" this one.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        ConnectionDescriptor c = (ConnectionDescriptor)obj;
        if (hashCode() != c.hashCode()) {
            return false;
        }

        return producerName.equals(c.producerName) && 
               consumerName.equals(c.consumerName) &&
               event.equals(c.event);
    }
    /**
     * Returns a string representation of the object. In general, the
     * <code>toString</code> method returns a string that
     * "textually represents" this object. The result should
     * be a concise but informative representation that is easy for a
     * person to read.
     */
    @Override
    public String toString() {
        return "Producer=" + producerName +
            ", Consumer=" + consumerName + ", Event=" + event;
    }

}
