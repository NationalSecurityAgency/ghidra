<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="/usr/share/sgml/docbook/stylesheet/xsl/docbook-xsl/html/chunk.xsl"/>

  <xsl:include href="cspec_common.xsl" />

  <!-- Split up into files based on id attribute -->
  <xsl:param name="use.id.as.filename" select="1"/>

  <!-- Use our custom cascading style sheet -->
  <xsl:param name="html.stylesheet" select="'Frontpage.css'"/>

  <!-- Do proper indenting of html -->
  <xsl:param name="chunker.output.indent" select="'yes'"/>

</xsl:stylesheet>
