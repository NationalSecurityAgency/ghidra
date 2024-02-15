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
package ghidra.framework.model;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

import utility.function.Callback;

/**
 * Builder for creating a compact and efficient {@link DomainObjectListener} for 
 * {@link DomainObjectChangedEvent}s
 * <P>
 * There are three basic ways to process {@link DomainObjectChangeRecord}s within a 
 * {@link DomainObjectChangedEvent}. 
 * <P>The first way is to look for the event to contain one or more
 * records of a certain type, and if it is there, do some major refresh operation, and ignore
 * the remaining event records. This is can be handled with an {@link #any(EventType...)},  
 * followed by a {@link AnyBuilder#terminate(Callback)} or {@link AnyBuilder#terminate(Consumer)} 
 * if you want the event.
 * <P>
 * <PRE>
 * new DomainObjectListenerBuilder()
 *	.any(DomainObjectEvent.RESTORED).call(() -> refreshAll())
 *	.build();
 * </PRE>
 * 
 *or if you need the event, you can use a consumer
 *
 * <PRE> 
 * new DomainObjectListenerBuilder()
 *	.any(DomainObjectEvent.RESTORED).call(e -> refreshAll(e))
 *	.build();
 * </PRE>
 * <P>
 * The second way is to just test for presence of one or more records of a certain type, and if
 * any of those types exist is the event, call a method. In this case you don't need to know the 
 * details of the record, only that one of the  given events was fired. This can be handled using 
 * the  {@link #any(EventType...)}, followed by a  call to {@link AnyBuilder#call(Callback)} or
 * {@link AnyBuilder#call(Consumer)}
 * <P>
 * <PRE>
 * new DomainObjectListenerBuilder()
 *	.onAny(ProgramEvent.FUNCTION_CHANGED).call(() -> refreshFunctions())
 *	.build();
 * </PRE>
 *or if you need the event, you can use a consumer
 * <PRE>
 *
 * new DomainObjectListenerBuilder()
 *	.onAny(ProgramEvent.FUNCTION_CHANGED).call(e -> refreshFunctions(e))
 *	.build();
 * </PRE>
 * <P>
 * And finally, the third way is where you have to perform some processing on each record of a 
 * certain type. This can be done using the the {@link #each(EventType...)}, followed by the
 * {@link EachBuilder#call(Consumer)} if you just want the record, or 
 * {@link EachBuilder#call(BiConsumer)} if you want the record and the event.
 * <P>
 * By default, the consumer for the "each" case is typed on DomainObjectChangeRecord. But that
 * can be changed by calling {@link #with(Class)}. Once this is called the builder
 * will require that all consumers being passed in will now be typed on that record
 * class. 
 * <P>
 * <PRE>
 * new DomainObjectListenerBuilder()
 *	.each(DomainObjectEvent.PROPERTY_CHANGED).call(r -> processPropertyChanged(r))
 *	.withRecord(ProgramChangeRecord.class)
 *	.each(ProgramEvent.SYMBOL_RENANED).call(r -> symbolRenamed(r)
 *	.build();
 *
 * private void processPropertyChanged(DomainObjectChangeRecord record) {
 * 		...
 * }
 * private void symbolRenamed(ProgramChangeRecord record) {
 * 		...
 * }
 * </PRE>
 * 
 * or if you also need the event (to get the domainObject that is the event source)
 * 
 * <PRE
 *   new DomainObjectListenerBuilder()
 *	.each(DomainObjectEvent.PROPERTY_CHANGED).call((e, r) -> processPropertyChanged(e, r))
 *	.withRecord(ProgramChangeRecord.class)
 *	.each(ProgramEvent.SYMBOL_RENANED).call((e, r) -> symbolRenamed(e, r)
 *	.build();
 *
 * private void propertyChanged(DomainObjectChangedEvent e, DomainObjectChangeRecord record) {
 * 	    Program p = (Program)e.getSource().
 * 		...
 * }
 * private void symbolRenamed(DomainObjectChangedEvent e, ProgramChangeRecord record) {
 * 	    Program p = (Program)e.getSource().
 * 	    ...
 * }
 * </PRE>
 */

public class DomainObjectListenerBuilder extends
		AbstractDomainObjectListenerBuilder<DomainObjectChangeRecord, DomainObjectListenerBuilder> {

	/**
	 * Constructs a new builder
	 * @param creator the object that created this builder (usually, just pass in "this"). This
	 * will help with debugging event processing
	 */
	public DomainObjectListenerBuilder(Object creator) {
		super(creator.getClass().getSimpleName(), DomainObjectChangeRecord.class);
	}

	@Override
	protected DomainObjectListenerBuilder self() {
		return this;
	}

}
