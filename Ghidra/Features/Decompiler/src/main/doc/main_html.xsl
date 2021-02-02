<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>

<xsl:param name="generate.toc">
  article/appendix  nop
  article   title
  book      toc,title,figure,table,example,equation
  chapter   nop
  part      toc,title
  preface   toc,title
  qandadiv  toc
  qandaset  toc
  reference toc,title
  sect1     nop
  sect2     nop
  sect3     nop
  sect4     nop
  sect5     nop
  section   nop
  set       toc,title
</xsl:param>

<xsl:param name="html.stylesheet" select="'html/Frontpage.css'"/>    <!-- Use our custom cascading style sheet -->

<xsl:output method="html"
            encoding="UTF8"
            indent="yes"/>

</xsl:stylesheet>
