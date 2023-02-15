using System;

namespace PKI.CertificateServices.ExitModule {
	class SMTPTemplate {
		public SMTPTemplate (SubscriptionEventEnum subscriptionType) {
			m_initialize(subscriptionType);
		}
		public String TitleArguments { get; set; }
		public String TitleFormat { get; set; }
		public String BodyArguments { get; set; }
		public String BodyFormat { get; set; }
		public String From { get; set; }
		public String To { get; set; }
		public Boolean IsModified { get; private set; }

		void m_initialize(SubscriptionEventEnum subscriptionType) {
			
		}
	}
}
