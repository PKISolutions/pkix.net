using System;

namespace PKI.CertificateServices.ExitModule {
	[Flags]
	enum SubscriptionEventEnum {
		Invalid				= 0,
		CertificateIssued	= 1,
		CertificatePending	= 2,
		CertificateDenied	= 4,
		CertificateRevoked	= 0x8,
		CertificateRetrieve	= 0x10,
		CRLIssued			= 0x20,
		ServiceStop			= 0x40,
		ServiceStart		= 0x80,
		CertificateImported	= 0x200
	}
}
