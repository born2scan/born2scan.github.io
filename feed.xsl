<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="3.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:atom="http://www.w3.org/2005/Atom">
 <xsl:output method="html" version="1.0" encoding="UTF-8" indent="yes"/>
 <xsl:template match="/">
 <html xmlns="http://www.w3.org/1999/xhtml" lang="en">
  <head>
    <title>
      <xsl:value-of select="/rss/channel/title"/> | RSS Feed
    </title>
    <link rel="stylesheet" href="/css/main.css"/>
  </head>
  <body>
    <div class="wrapper" style="padding-top: 32px">
      <h1 class="page-title" style="margin: revert">
        <img src="/assets/img/logo.png" alt="born2scan logo" width="125" class="team-logo" style="margin-top: revert"/>
        <div class="page-title__text">
          Most recent posts
        </div>
        <div class="page-title__subtitle" style="margin-top: 1em">
          This is a styled RSS feed. Visit
          <a href="https://aboutfeeds.com">About Feeds</a>
          to learn more and get started. It’s free.
        </div>
      </h1>
      <div class="grid-center" style="margin-top: 1em">
        <div>
          <ul>
            <xsl:for-each select="/rss/channel/item">
              <li style="margin-bottom: 1em;">
                <div>
                  <a><xsl:attribute name="href"><xsl:value-of select="link/@href"/></xsl:attribute><xsl:value-of select="title"/></a>
                </div>
                <div>
                  <b>Published at: </b> <xsl:value-of select="substring(pubDate, 0, 17)"/>
                </div>
                <div>
                  <b>Category: </b> <xsl:value-of select="category"/>
                </div>
                <div>
                  <b>Description: </b> <xsl:value-of select="description"/>
                </div>
              </li>
            </xsl:for-each>
          </ul>
        </div>
      </div>
    </div>
  </body>
  </html>
 </xsl:template>
</xsl:stylesheet>

<!-- https://darekkay.com/blog/rss-styling/ -->