Packages in this repo:
- [SysadminsLV.PKI](#sysadminslvpki-package)
- [SysadminsLV.PKI.OcspClient](#sysadminslvpkiocspclient-package)
- [SysadminsLV.PKI.Win](#sysadminslvpkiwin-package)
---

# SysadminsLV.PKI package

## Description
This package is a cross-platform framework library that provides extended cryptography and X.509 support classes to standard .NET frameworks.

## Requirements
- .NET Standard 2.0/.NET 4.7.2
- Cross-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)

## API Documentation
- [Legacy documentation](https://www.pkisolutions.com/apidocs/pkix.net)
- [SysadminsLV.PKI package docs](https://www.pkisolutions.com/apidocs/SysadminsLV.PKI)

## CI/CD and NuGet Status
[![Build Status](https://dev.azure.com/pkisolutions/PKI%20Libraries/_apis/build/status/PKIX.NET-Build?branchName=master)](https://dev.azure.com/pkisolutions/PKI%20Libraries/_build/latest?definitionId=17&branchName=master)

# SysadminsLV.PKI.OcspClient package

## Description
This package is a cross-platform framework library that implements managed OCSP client which is compatible with [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) OCSP profile.

## Requirements
- .NET Standard 2.0/.NET 4.7.2
- Cross-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)
- [SysadminsLV.PKI](https://www.nuget.org/packages/SysadminsLV.PKI)

## API Documentation
- [SysadminsLV.PKI.OcspClient package docs](https://www.pkisolutions.com/apidocs/SysadminsLV.PKI.OcspClient)

# SysadminsLV.PKI.Win package

## Description
This package is a Windows-specific framework library that that provides extended cryptography and implements managed Active Directory Certificate Services (ADCS) classes.

## Requirements
- .NET 4.7.2
- Windows-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)
- [SysadminsLV.PKI](https://www.nuget.org/packages/SysadminsLV.PKI)
- [SysadminsLV.PKI.OcspClient](https://www.nuget.org/packages/SysadminsLV.PKI.OcspClient)

## API Documentation
- [SysadminsLV.PKI.Win package docs](https://www.pkisolutions.com/apidocs/SysadminsLV.PKI.Win)

