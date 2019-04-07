<?xml version='1.0' encoding='ISO-8859-1' ?>
<!-- 

	This is an XML file intended to be parsed by the Ghidra help system.  It is loosely based 
	upon the JavaHelp table of contents document format.  The Ghidra help system uses a 
	TOC_Source.xml file to allow a module with help to define how its contents appear in the 
	Ghidra help viewer's table of contents.  The main document (in the Base module) 
	defines a basic structure for the 
	Ghidra table of contents system.  Other TOC_Source.xml files may use this structure to insert
	their files directly into this structure (and optionally define a substructure).
	
	
	In this document, a tag can be either a <tocdef> or a <tocref>.  The former is a definition
	of an XML item that may have a link and may contain other <tocdef> and <tocref> children.  
	<tocdef> items may be referred to in other documents by using a <tocref> tag with the 
	appropriate id attribute value.  Using these two tags allows any module to define a place 
	in the table of contents system (<tocdef>), which also provides a place for 
	other TOC_Source.xml files to insert content (<tocref>).  
	
	During the help build time, all TOC_Source.xml files will be parsed and	validated to ensure
	that all <tocref> tags point to valid <tocdef> tags.  From these files will be generated
	<module name>_TOC.xml files, which are table of contents files written in the format 
	desired by the JavaHelp system.   Additionally, the genated files will be merged together
	as they are loaded by the JavaHelp system.  In the end, when displaying help in the Ghidra
	help GUI, there will be on table of contents that has been created from the definitions in 
	all of the modules' TOC_Source.xml files.

	
	Tags and Attributes
	
	<tocdef>
	-id          - the name of the definition (this must be unique across all TOC_Source.xml files)	
	-text        - the display text of the node, as seen in the help GUI
	-target**    - the file to display when the node is clicked in the GUI
	-sortgroup   - this is a string that defines where a given node should appear under a given
	               parent.  The string values will be sorted by the JavaHelp system using
	               a javax.text.RulesBasedCollator.  If this attribute is not specified, then
	               the text of attribute will be used.

	<tocref>
	-id			 - The id of the <tocdef> that this reference points to 
	
	**The URL for the target is relative and should start with 'help/topics'.  This text is 
	used by the Ghidra help system to provide a universal starting point for all links so that
	they can be resolved at runtime, across modules.
	
	
-->


<tocroot>
	<!-- Uncomment and adjust fields to add help topic to help system's Table of Contents
	<tocref id="Ghidra Functionality">
		<tocdef id="HelpAnchor" text="My Feature" target="help/topics/my_topic/help.html" />
	</tocref>
	-->
</tocroot>
