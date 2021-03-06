// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace Microsoft.Tools.WindowsInstallerXml.Extensions
{
    using Microsoft.Tools.WindowsInstallerXml;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Reflection;
    using System.Xml;
    using System.Xml.Schema;

    /// <summary>
    /// The compiler for the Windows Installer XML Toolset Http Extension.
    /// </summary>
    public sealed class HttpCompiler : CompilerExtension
    {
        private XmlSchema schema;

        /// <summary>
        /// Instantiate a new HttpCompiler.
        /// </summary>
        public HttpCompiler()
        {
            this.schema = LoadXmlSchemaHelper(Assembly.GetExecutingAssembly(), "Microsoft.Tools.WindowsInstallerXml.Extensions.Xsd.http.xsd");
        }

        /// <summary>
        /// Gets the schema for this extension.
        /// </summary>
        /// <value>Schema for this extension.</value>
        public override XmlSchema Schema
        {
            get { return this.schema; }
        }

        /// <summary>
        /// Processes an element for the Compiler.
        /// </summary>
        /// <param name="sourceLineNumbers">Source line number for the parent element.</param>
        /// <param name="parentElement">Parent element of element to process.</param>
        /// <param name="element">Element to process.</param>
        /// <param name="contextValues">Extra information about the context in which this element is being parsed.</param>
        public override void ParseElement(SourceLineNumberCollection sourceLineNumbers, XmlElement parentElement, XmlElement element, params string[] contextValues)
        {
            switch (parentElement.LocalName)
            {
                case "ServiceInstall":
                    string serviceInstallName = contextValues[1];
                    string serviceUser = String.IsNullOrEmpty(serviceInstallName) ? null : String.Concat("NT SERVICE\\", serviceInstallName);
                    string serviceComponentId = contextValues[2];

                    switch (element.LocalName)
                    {
                        case "UrlReservation":
                            this.ParseUrlReservationElement(element, serviceComponentId, serviceUser);
                            break;
                        default:
                            this.Core.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                case "Component":
                    string componentId = contextValues[0];

                    switch (element.LocalName)
                    {
                        case "SniSslCertificate":
                            this.ParseSniSslCertificateElement(element, componentId);
                            break;
                        case "UrlReservation":
                            this.ParseUrlReservationElement(element, componentId, null);
                            break;
                        default:
                            this.Core.UnexpectedElement(parentElement, element);
                            break;
                    }
                    break;
                default:
                    this.Core.UnexpectedElement(parentElement, element);
                    break;
            }
        }

        /// <summary>
        /// Parses a SniSsl element.
        /// </summary>
        /// <param name="node">The element to parse.</param>
        /// <param name="componentId">Identifier of the component that owns this SNI SSL Certificate.</param>
        private void ParseSniSslCertificateElement(XmlNode node, string componentId)
        {
            SourceLineNumberCollection sourceLineNumbers = Preprocessor.GetSourceLineNumbers(node);
            string id = null;
            string host = null;
            string port = null;
            string appId = null;
            string store = null;
            string thumbprint = null;
            int handleExisting = HttpConstants.heReplace;
            string handleExistingValue = null;

            foreach (XmlAttribute attrib in node.Attributes)
            {
                if (String.IsNullOrEmpty(attrib.NamespaceURI) || this.schema.TargetNamespace == attrib.NamespaceURI)
                {
                    switch (attrib.LocalName)
                    {
                        case "Id":
                            id = this.Core.GetAttributeIdentifierValue(sourceLineNumbers, attrib);
                            break;
                        case "AppId":
                            appId = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "HandleExisting":
                            handleExistingValue = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (handleExistingValue)
                            {
                                case "replace":
                                    handleExisting = HttpConstants.heReplace;
                                    break;
                                case "ignore":
                                    handleExisting = HttpConstants.heIgnore;
                                    break;
                                case "fail":
                                    handleExisting = HttpConstants.heFail;
                                    break;
                                default:
                                    this.Core.OnMessage(WixErrors.IllegalAttributeValue(sourceLineNumbers, node.LocalName, "HandleExisting", handleExistingValue, "replace", "ignore", "fail"));
                                    break;
                            }
                            break;
                        case "Host":
                            host = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Port":
                            port = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Store":
                            store = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Thumbprint":
                            thumbprint = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        default:
                            this.Core.UnexpectedAttribute(sourceLineNumbers, attrib);
                            break;
                    }
                }
                else
                {
                    this.Core.ParseExtensionAttribute(sourceLineNumbers, (XmlElement)node, attrib);
                }
            }

            // Need the element ID for child element processing, so generate now if not authored.
            if (null == id)
            {
                id = this.Core.GenerateIdentifier("ssl", componentId, host, port);
            }

            // Required attributes.
            if (null == host)
            {
                this.Core.OnMessage(WixErrors.ExpectedAttribute(sourceLineNumbers, node.LocalName, "Host"));
            }

            if (null == port)
            {
                this.Core.OnMessage(WixErrors.ExpectedAttribute(sourceLineNumbers, node.LocalName, "Port"));
            }

            if (null == thumbprint)
            {
                this.Core.OnMessage(WixErrors.ExpectedAttribute(sourceLineNumbers, node.LocalName, "Thumbprint"));
            }

            // Parse unknown children.
            foreach (XmlNode child in node.ChildNodes)
            {
                if (XmlNodeType.Element == child.NodeType)
                {
                    if (this.Schema.TargetNamespace == child.NamespaceURI)
                    {
                        this.Core.UnexpectedElement(node, child);
                    }
                    else
                    {
                        this.Core.ParseExtensionElement(sourceLineNumbers, (XmlElement)node, (XmlElement)child);
                    }
                }
            }

            if (!this.Core.EncounteredError)
            {
                Row row = this.Core.CreateRow(sourceLineNumbers, "WixHttpSniSslCert");
                row[0] = id;
                row[1] = host;
                row[2] = port;
                row[3] = thumbprint;
                row[4] = appId;
                row[5] = store;
                row[6] = handleExisting;
                row[7] = componentId;

                if (this.Core.CurrentPlatform == Platform.ARM)
                {
                    // Ensure ARM version of the CA is referenced.
                    this.Core.CreateWixSimpleReferenceRow(sourceLineNumbers, "CustomAction", "WixSchedHttpSniSslCertsInstall_ARM");
                    this.Core.CreateWixSimpleReferenceRow(sourceLineNumbers, "CustomAction", "WixSchedHttpSniSslCertsUninstall_ARM");
                }
                else
                {
                    // All other supported platforms use x86.
                    this.Core.CreateWixSimpleReferenceRow(sourceLineNumbers, "CustomAction", "WixSchedHttpSniSslCertsInstall");
                    this.Core.CreateWixSimpleReferenceRow(sourceLineNumbers, "CustomAction", "WixSchedHttpSniSslCertsUninstall");
                }
            }
        }

        /// <summary>
        /// Parses a UrlReservation element.
        /// </summary>
        /// <param name="node">The element to parse.</param>
        /// <param name="componentId">Identifier of the component that owns this URL reservation.</param>
        /// <param name="securityPrincipal">The security principal of the parent element (null if nested under Component).</param>
        private void ParseUrlReservationElement(XmlNode node, string componentId, string securityPrincipal)
        {
            SourceLineNumberCollection sourceLineNumbers = Preprocessor.GetSourceLineNumbers(node);
            string id = null;
            int handleExisting = HttpConstants.heReplace;
            string handleExistingValue = null;
            string sddl = null;
            string url = null;
            bool foundACE = false;

            foreach (XmlAttribute attrib in node.Attributes)
            {
                if (String.IsNullOrEmpty(attrib.NamespaceURI) || this.schema.TargetNamespace == attrib.NamespaceURI)
                {
                    switch (attrib.LocalName)
                    {
                        case "Id":
                            id = this.Core.GetAttributeIdentifierValue(sourceLineNumbers, attrib);
                            break;
                        case "HandleExisting":
                            handleExistingValue = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (handleExistingValue)
                            {
                                case "replace":
                                    handleExisting = HttpConstants.heReplace;
                                    break;
                                case "ignore":
                                    handleExisting = HttpConstants.heIgnore;
                                    break;
                                case "fail":
                                    handleExisting = HttpConstants.heFail;
                                    break;
                                default:
                                    this.Core.OnMessage(WixErrors.IllegalAttributeValue(sourceLineNumbers, node.LocalName, "HandleExisting", handleExistingValue, "replace", "ignore", "fail"));
                                    break;
                            }
                            break;
                        case "Sddl":
                            sddl = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Url":
                            url = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        default:
                            this.Core.UnexpectedAttribute(sourceLineNumbers, attrib);
                            break;
                    }
                }
                else
                {
                    this.Core.ParseExtensionAttribute(sourceLineNumbers, (XmlElement)node, attrib);
                }
            }

            // Need the element ID for child element processing, so generate now if not authored.
            if (null == id)
            {
                id = this.Core.GenerateIdentifier("url", componentId, securityPrincipal, url);
            }

            // Parse UrlAce children.
            foreach (XmlNode child in node.ChildNodes)
            {
                if (XmlNodeType.Element == child.NodeType)
                {
                    if (this.Schema.TargetNamespace == child.NamespaceURI)
                    {
                        switch (child.LocalName)
                        {
                            case "UrlAce":
                                if (null != sddl)
                                {
                                    this.Core.OnMessage(WixErrors.IllegalParentAttributeWhenNested(sourceLineNumbers, "UrlReservation", "Sddl", "UrlAce"));
                                }
                                else
                                {
                                    foundACE = true;
                                    this.ParseUrlAceElement(child, id, securityPrincipal);
                                }
                                break;
                            default:
                                this.Core.UnexpectedElement(node, child);
                                break;
                        }
                    }
                    else
                    {
                        this.Core.ParseExtensionElement(sourceLineNumbers, (XmlElement)node, (XmlElement)child);
                    }
                }
            }

            // Url is required.
            if (null == url)
            {
                this.Core.OnMessage(WixErrors.ExpectedAttribute(sourceLineNumbers, node.LocalName, "Url"));
            }
            else if (!url.EndsWith("/"))
            {
                // Normalize URL.
                url = String.Concat(url, "/");
            }

            // Security is required.
            if (null == sddl && !foundACE)
            {
                this.Core.OnMessage(HttpErrors.NoSecuritySpecified(sourceLineNumbers));
            }

            if (!this.Core.EncounteredError)
            {
                Row row = this.Core.CreateRow(sourceLineNumbers, "WixHttpUrlReservation");
                row[0] = id;
                row[1] = handleExisting;
                row[2] = sddl;
                row[3] = url;
                row[4] = componentId;

                this.Core.CreateCustomActionReference(sourceLineNumbers, "WixSchedHttpUrlReservationsInstall", Platforms.ARM | Platforms.ARM64);
                this.Core.CreateCustomActionReference(sourceLineNumbers, "WixSchedHttpUrlReservationsUninstall", Platforms.ARM | Platforms.ARM64);
            }
        }

        /// <summary>
        /// Parses a UrlAce element.
        /// </summary>
        /// <param name="node">The element to parse.</param>
        /// <param name="urlReservationId">The URL reservation ID.</param>
        /// <param name="defaultSecurityPrincipal">The default security principal.</param>
        private void ParseUrlAceElement(XmlNode node, string urlReservationId, string defaultSecurityPrincipal)
        {
            SourceLineNumberCollection sourceLineNumbers = Preprocessor.GetSourceLineNumbers(node);
            string id = null;
            string securityPrincipal = defaultSecurityPrincipal;
            int rights = HttpConstants.GENERIC_ALL;
            string rightsValue = null;

            foreach (XmlAttribute attrib in node.Attributes)
            {
                if (String.IsNullOrEmpty(attrib.NamespaceURI) || this.schema.TargetNamespace == attrib.NamespaceURI)
                {
                    switch (attrib.LocalName)
                    {
                        case "Id":
                            id = this.Core.GetAttributeIdentifierValue(sourceLineNumbers, attrib);
                            break;
                        case "SecurityPrincipal":
                            securityPrincipal = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            break;
                        case "Rights":
                            rightsValue = this.Core.GetAttributeValue(sourceLineNumbers, attrib);
                            switch (rightsValue)
                            {
                                case "all":
                                    rights = HttpConstants.GENERIC_ALL;
                                    break;
                                case "delegate":
                                    rights = HttpConstants.GENERIC_WRITE;
                                    break;
                                case "register":
                                    rights = HttpConstants.GENERIC_EXECUTE;
                                    break;
                                default:
                                    this.Core.OnMessage(WixErrors.IllegalAttributeValue(sourceLineNumbers, node.LocalName, "Rights", rightsValue, "all", "delegate", "register"));
                                    break;
                            }
                            break;
                        default:
                            this.Core.UnexpectedAttribute(sourceLineNumbers, attrib);
                            break;
                    }
                }
                else
                {
                    this.Core.ParseExtensionAttribute(sourceLineNumbers, (XmlElement)node, attrib);
                }
            }

            // Generate Id now if not authored.
            if (null == id)
            {
                id = this.Core.GenerateIdentifier("ace", urlReservationId, securityPrincipal, rightsValue);
            }

            foreach (XmlNode child in node.ChildNodes)
            {
                if (XmlNodeType.Element == child.NodeType)
                {
                    if (this.Schema.TargetNamespace == child.NamespaceURI)
                    {
                        this.Core.UnexpectedElement(node, child);
                    }
                    else
                    {
                        this.Core.ParseExtensionElement(sourceLineNumbers, (XmlElement)node, (XmlElement)child);
                    }
                }
            }

            // SecurityPrincipal is required.
            if (null == securityPrincipal)
            {
                this.Core.OnMessage(WixErrors.ExpectedAttribute(sourceLineNumbers, node.LocalName, "SecurityPrincipal"));
            }

            if (!this.Core.EncounteredError)
            {
                Row row = this.Core.CreateRow(sourceLineNumbers, "WixHttpUrlAce");
                row[0] = id;
                row[1] = urlReservationId;
                row[2] = securityPrincipal;
                row[3] = rights;
            }
        }
    }
}
